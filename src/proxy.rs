//! The gateway itself: speaks MCP to one client (stdio), fronts one or more
//! downstream servers, and routes every `tools/call` through the engine.

use std::collections::HashMap;
use std::io::{BufRead, Write};

use serde_json::{json, Value};

use crate::downstream::{self, Downstream};
use crate::engine::{Engine, Verdict};
use crate::jsonrpc::{self, Incoming, RpcError};
use crate::policy::Policy;

const SUPPORTED: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

pub struct Gateway {
    pub engine: Engine,
    servers: Vec<(String, Box<dyn Downstream>)>,
    /// Exposed tool name -> (server index, downstream tool name).
    routes: HashMap<String, (usize, String)>,
    tools: Vec<Value>,
    audit: Option<Box<dyn Write + Send>>,
    pub stats: Stats,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub calls: u64,
    pub blocked: u64,
    pub labelled_results: u64,
}

impl Gateway {
    /// Start every downstream server in the policy and collect their tools.
    pub fn start(policy: Policy) -> Result<Self, String> {
        let mut servers = Vec::new();
        for s in &policy.server {
            let mut d = downstream::connect(s)?;
            let tools = downstream::initialize(d.as_mut())
                .map_err(|e| format!("server {:?}: {e}", s.name))?;
            servers.push((s.name.clone(), d, tools));
        }
        Self::from_parts(policy, servers)
    }

    /// Build from already-initialised downstreams (used by tests).
    pub fn from_parts(
        policy: Policy,
        servers: Vec<(String, Box<dyn Downstream>, Vec<Value>)>,
    ) -> Result<Self, String> {
        if servers.is_empty() {
            return Err("no [[server]] configured".into());
        }
        let prefix = servers.len() > 1;
        let mut routes = HashMap::new();
        let mut tools = Vec::new();
        let mut conns = Vec::new();
        for (i, (name, d, list)) in servers.into_iter().enumerate() {
            for mut t in list {
                let Some(orig) = t.get("name").and_then(Value::as_str).map(str::to_string) else {
                    continue;
                };
                let exposed = if prefix {
                    format!("{name}__{orig}")
                } else {
                    orig.clone()
                };
                if routes.contains_key(&exposed) {
                    return Err(format!("duplicate tool name {exposed:?}"));
                }
                t["name"] = Value::String(exposed.clone());
                routes.insert(exposed, (i, orig));
                tools.push(t);
            }
            conns.push((name, d));
        }
        Ok(Self {
            engine: Engine::new(policy),
            servers: conns,
            routes,
            tools,
            audit: None,
            stats: Stats::default(),
        })
    }

    pub fn with_audit(mut self, w: Box<dyn Write + Send>) -> Self {
        self.audit = Some(w);
        self
    }

    /// Serve one client over newline-delimited JSON until EOF.
    pub fn serve<R: BufRead, W: Write>(
        &mut self,
        mut input: R,
        mut output: W,
    ) -> std::io::Result<()> {
        let mut line = String::new();
        loop {
            line.clear();
            if input.read_line(&mut line)? == 0 {
                return Ok(());
            }
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            if let Some(reply) = self.handle_text(t) {
                serde_json::to_writer(&mut output, &reply)?;
                output.write_all(b"\n")?;
                output.flush()?;
            }
        }
    }

    pub fn handle_text(&mut self, text: &str) -> Option<Value> {
        let v: Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(_) => {
                return Some(jsonrpc::error_response(
                    Value::Null,
                    &RpcError::parse_error(),
                ))
            }
        };
        if let Value::Array(items) = v {
            if items.is_empty() {
                return Some(jsonrpc::error_response(
                    Value::Null,
                    &RpcError::invalid_request("empty batch"),
                ));
            }
            let out: Vec<Value> = items
                .into_iter()
                .filter_map(|m| self.handle_value(m))
                .collect();
            return if out.is_empty() {
                None
            } else {
                Some(Value::Array(out))
            };
        }
        self.handle_value(v)
    }

    pub fn handle_value(&mut self, v: Value) -> Option<Value> {
        match jsonrpc::validate(&v) {
            Err((id, e)) => Some(jsonrpc::error_response(id, &e)),
            Ok(Incoming::Notification { .. }) | Ok(Incoming::Response) => None,
            Ok(Incoming::Request { id, method, params }) => {
                Some(match self.request(&method, params.unwrap_or(json!({}))) {
                    Ok(r) => jsonrpc::response(&id, r),
                    Err(e) => jsonrpc::error_response(id.to_value(), &e),
                })
            }
        }
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value, RpcError> {
        match method {
            "initialize" => {
                let asked = params.get("protocolVersion").and_then(Value::as_str);
                let version = asked
                    .filter(|v| SUPPORTED.contains(v))
                    .unwrap_or(downstream::PROTOCOL_VERSION);
                Ok(json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "taintgate", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": "Tool calls pass through taintgate. Calls that would send \
                        private data to an untrusted destination after untrusted content was \
                        read are refused with a tool error explaining why.",
                }))
            }
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": self.tools })),
            "tools/call" => self.call(params),
            other => Err(RpcError::method_not_found(other)),
        }
    }

    fn call(&mut self, params: Value) -> Result<Value, RpcError> {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::invalid_params("missing tool name"))?
            .to_string();
        let args = params.get("arguments").cloned().unwrap_or(json!({}));
        let (idx, orig) = self
            .routes
            .get(&name)
            .cloned()
            .ok_or_else(|| RpcError::invalid_params(format!("unknown tool {name:?}")))?;
        let server = self.servers[idx].0.clone();
        self.stats.calls += 1;

        let decision = self.engine.check_call(&server, &orig, &args);
        let record = decision.to_json(&server, &orig);
        if decision.verdict == Verdict::Block {
            self.stats.blocked += 1;
            self.audit(&record);
            let why = format!(
                "taintgate refused this call ({}): its arguments carry {} data and the \
                 destination {:?} is not trusted, after untrusted content was read in this \
                 session.",
                decision.rule.unwrap_or("policy"),
                decision.carried.names().join("+"),
                decision.destinations,
            );
            return Ok(json!({
                "content": [{"type": "text", "text": why}],
                "isError": true,
                "_meta": {"taintgate": record},
            }));
        }

        let mut fwd = params.clone();
        fwd["name"] = Value::String(orig.clone());
        let resp = self.servers[idx]
            .1
            .request("tools/call", fwd)
            .map_err(RpcError::internal)?;
        if let Some(e) = resp.get("error") {
            self.audit(&record);
            return Err(RpcError {
                code: e.get("code").and_then(Value::as_i64).unwrap_or(-32603),
                message: e
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("downstream error")
                    .to_string(),
                data: e.get("data").cloned(),
            });
        }
        let mut result = resp.get("result").cloned().unwrap_or(json!({}));
        let labels = self
            .engine
            .record_result(&server, &orig, &args, &decision, &result);
        if !labels.is_empty() {
            self.stats.labelled_results += 1;
        }
        let mut rec = record;
        rec["result_labels"] = json!(labels.names());
        self.audit(&rec);
        if let Some(obj) = result.as_object_mut() {
            let meta = obj.entry("_meta").or_insert_with(|| json!({}));
            if let Some(m) = meta.as_object_mut() {
                m.insert(
                    "taintgate".into(),
                    json!({"labels": labels.names(), "action": decision.action}),
                );
            }
        }
        Ok(result)
    }

    fn audit(&mut self, rec: &Value) {
        if let Some(w) = self.audit.as_mut() {
            let _ = writeln!(w, "{rec}");
            let _ = w.flush();
        }
    }
}
