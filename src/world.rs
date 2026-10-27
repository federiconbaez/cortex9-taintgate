//! A data-driven mock MCP server used by the scenario suite: tools return
//! canned texts (with injection vectors that can be filled with attacker
//! text), and every call to a sink tool is appended to a log file, which is
//! the ground truth for "the data left".

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::sync::Mutex;

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::jsonrpc::{self, Incoming, RpcError};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldTool {
    pub name: String,
    pub description: String,
    /// Argument name -> JSON Schema type.
    #[serde(default)]
    pub params: BTreeMap<String, String>,
    #[serde(default)]
    pub sink: bool,
    /// Fixed reply text; `{{vector}}` placeholders are filled in.
    #[serde(default)]
    pub returns: Option<String>,
    /// Pick the reply by the value of this argument from `returns_map`.
    #[serde(default)]
    pub by_arg: Option<String>,
    #[serde(default)]
    pub returns_map: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Suite {
    pub suite: String,
    pub tools: Vec<WorldTool>,
    /// Injection vector -> benign default text.
    #[serde(default)]
    pub vectors: BTreeMap<String, String>,
    #[serde(default)]
    pub user_tasks: Vec<Value>,
    #[serde(default)]
    pub injection_tasks: Vec<Value>,
    #[serde(default)]
    pub note: Option<String>,
}

pub struct World {
    pub suite: Suite,
    pub injections: BTreeMap<String, String>,
    pub log: Option<Mutex<std::fs::File>>,
}

impl World {
    pub fn new(suite: Suite) -> Self {
        Self {
            suite,
            injections: BTreeMap::new(),
            log: None,
        }
    }

    /// Configure from `TAINTGATE_WORLD_INJECT` (JSON object vector -> text)
    /// and `TAINTGATE_WORLD_LOG` (append-only JSON lines of sink calls).
    pub fn from_env(suite: Suite) -> Result<Self, String> {
        let mut w = World::new(suite);
        if let Ok(s) = std::env::var("TAINTGATE_WORLD_INJECT") {
            w.injections =
                serde_json::from_str(&s).map_err(|e| format!("TAINTGATE_WORLD_INJECT: {e}"))?;
        }
        if let Ok(p) = std::env::var("TAINTGATE_WORLD_LOG") {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&p)
                .map_err(|e| format!("{p}: {e}"))?;
            w.log = Some(Mutex::new(f));
        }
        Ok(w)
    }

    fn fill(&self, text: &str) -> String {
        let mut out = text.to_string();
        for (k, default) in &self.suite.vectors {
            let v = self.injections.get(k).unwrap_or(default);
            out = out.replace(&format!("{{{{{k}}}}}"), v);
        }
        out
    }

    pub fn tool_list(&self) -> Vec<Value> {
        self.suite
            .tools
            .iter()
            .map(|t| {
                let mut props = Map::new();
                for (k, ty) in &t.params {
                    let schema = if ty == "array" {
                        json!({"type":"array","items":{"type":"string"}})
                    } else {
                        json!({ "type": ty })
                    };
                    props.insert(k.clone(), schema);
                }
                json!({
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": {"type":"object","properties": props,
                        "required": t.params.keys().collect::<Vec<_>>()},
                })
            })
            .collect()
    }

    pub fn call(&self, name: &str, args: &Value) -> Value {
        let Some(t) = self.suite.tools.iter().find(|t| t.name == name) else {
            return json!({"content":[{"type":"text","text":format!("unknown tool {name}")}],"isError":true});
        };
        for k in t.params.keys() {
            if args.get(k).is_none() {
                return json!({"content":[{"type":"text","text":format!("missing argument {k}")}],"isError":true});
            }
        }
        if t.sink {
            if let Some(log) = &self.log {
                let mut f = log.lock().unwrap();
                let _ = writeln!(f, "{}", json!({"tool": name, "args": args}));
                let _ = f.flush();
            }
        }
        let text = if let Some(arg) = &t.by_arg {
            let key = match args.get(arg) {
                Some(Value::String(s)) => s.clone(),
                Some(v) => v.to_string(),
                None => String::new(),
            };
            match t.returns_map.get(&key) {
                Some(s) => s.clone(),
                None => {
                    return json!({"content":[{"type":"text","text":format!("{arg} {key:?} not found")}],"isError":true})
                }
            }
        } else {
            t.returns.clone().unwrap_or_else(|| "ok".into())
        };
        json!({"content":[{"type":"text","text": self.fill(&text)}]})
    }

    pub fn handle(&self, v: &Value) -> Option<Value> {
        match jsonrpc::validate(v) {
            Err((id, e)) => Some(jsonrpc::error_response(id, &e)),
            Ok(Incoming::Request { id, method, params }) => {
                let p = params.unwrap_or(json!({}));
                let r = match method.as_str() {
                    "initialize" => Ok(json!({
                        "protocolVersion": p.get("protocolVersion").cloned().unwrap_or(json!("2025-06-18")),
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": format!("world-{}", self.suite.suite), "version": "0"},
                    })),
                    "ping" => Ok(json!({})),
                    "tools/list" => Ok(json!({"tools": self.tool_list()})),
                    "tools/call" => {
                        let name = p.get("name").and_then(Value::as_str).unwrap_or("");
                        Ok(self.call(name, p.get("arguments").unwrap_or(&json!({}))))
                    }
                    m => Err(RpcError::method_not_found(m)),
                };
                Some(match r {
                    Ok(r) => jsonrpc::response(&id, r),
                    Err(e) => jsonrpc::error_response(id.to_value(), &e),
                })
            }
            Ok(_) => None,
        }
    }

    pub fn serve_stdio<R: BufRead, W: Write>(
        &self,
        mut input: R,
        mut out: W,
    ) -> std::io::Result<()> {
        let mut line = String::new();
        loop {
            line.clear();
            if input.read_line(&mut line)? == 0 {
                return Ok(());
            }
            let Ok(v) = serde_json::from_str::<Value>(line.trim()) else {
                continue;
            };
            if let Some(r) = self.handle(&v) {
                writeln!(out, "{r}")?;
                out.flush()?;
            }
        }
    }

    /// Minimal Streamable HTTP endpoint (JSON responses, 202 for
    /// notifications). Prints the bound address on the first line of stdout.
    pub fn serve_http(&self, addr: &str) -> Result<(), String> {
        let server = tiny_http::Server::http(addr).map_err(|e| e.to_string())?;
        println!("{}", server.server_addr());
        let _ = std::io::stdout().flush();
        let header =
            |k: &str, v: &str| tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()).unwrap();
        for mut req in server.incoming_requests() {
            if req.method() != &tiny_http::Method::Post {
                let _ = req.respond(tiny_http::Response::empty(405));
                continue;
            }
            let mut body = String::new();
            let _ = req.as_reader().read_to_string(&mut body);
            let Ok(v) = serde_json::from_str::<Value>(&body) else {
                let _ = req.respond(tiny_http::Response::empty(400));
                continue;
            };
            let is_init = v.get("method").and_then(Value::as_str) == Some("initialize");
            match self.handle(&v) {
                None => {
                    let _ = req.respond(tiny_http::Response::empty(202));
                }
                Some(r) => {
                    let mut resp = tiny_http::Response::from_string(r.to_string())
                        .with_header(header("Content-Type", "application/json"));
                    if is_init {
                        resp = resp.with_header(header("Mcp-Session-Id", "world-session-1"));
                    }
                    let _ = req.respond(resp);
                }
            }
        }
        Ok(())
    }
}
