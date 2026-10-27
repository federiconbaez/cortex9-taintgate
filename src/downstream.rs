//! Connections from the gateway to the MCP servers it fronts: a child
//! process over stdio, or a Streamable HTTP endpoint.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{json, Value};

use crate::policy::Server;

pub const PROTOCOL_VERSION: &str = "2025-06-18";

pub trait Downstream: Send {
    /// Send a request and wait for the response object (`result` or `error`).
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String>;
    fn notify(&mut self, method: &str, params: Value) -> Result<(), String>;
}

pub fn connect(s: &Server) -> Result<Box<dyn Downstream>, String> {
    if let Some(cmd) = &s.command {
        Ok(Box::new(StdioDownstream::spawn(cmd, &s.env)?))
    } else if let Some(url) = &s.url {
        Ok(Box::new(HttpDownstream::new(url)))
    } else {
        Err(format!("server {:?} has no command or url", s.name))
    }
}

/// Run the MCP handshake and return the server's tool list.
pub fn initialize(d: &mut dyn Downstream) -> Result<Vec<Value>, String> {
    let r = d.request(
        "initialize",
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "taintgate", "version": env!("CARGO_PKG_VERSION")},
        }),
    )?;
    if let Some(e) = r.get("error") {
        return Err(format!("initialize failed: {e}"));
    }
    d.notify("notifications/initialized", json!({}))?;
    list_tools(d)
}

pub fn list_tools(d: &mut dyn Downstream) -> Result<Vec<Value>, String> {
    let mut tools = Vec::new();
    let mut cursor: Option<Value> = None;
    loop {
        let params = match &cursor {
            Some(c) => json!({ "cursor": c }),
            None => json!({}),
        };
        let r = d.request("tools/list", params)?;
        let res = r
            .get("result")
            .ok_or_else(|| format!("tools/list failed: {r}"))?;
        if let Some(a) = res.get("tools").and_then(Value::as_array) {
            tools.extend(a.iter().cloned());
        }
        match res.get("nextCursor") {
            Some(c) if !c.is_null() => cursor = Some(c.clone()),
            _ => return Ok(tools),
        }
    }
}

pub struct StdioDownstream {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: i64,
}

impl StdioDownstream {
    pub fn spawn(
        cmd: &[String],
        env: &std::collections::BTreeMap<String, String>,
    ) -> Result<Self, String> {
        let (prog, args) = cmd.split_first().ok_or("empty command")?;
        let mut child = Command::new(prog)
            .args(args)
            .envs(env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("cannot start {prog}: {e}"))?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = BufReader::new(child.stdout.take().ok_or("no stdout")?);
        Ok(Self {
            child,
            stdin,
            stdout,
            next_id: 1,
        })
    }

    fn send(&mut self, msg: &Value) -> Result<(), String> {
        let mut line = serde_json::to_vec(msg).map_err(|e| e.to_string())?;
        line.push(b'\n');
        self.stdin
            .write_all(&line)
            .and_then(|_| self.stdin.flush())
            .map_err(|e| format!("downstream write: {e}"))
    }
}

impl Downstream for StdioDownstream {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))?;
        let mut line = String::new();
        loop {
            line.clear();
            let n = self
                .stdout
                .read_line(&mut line)
                .map_err(|e| format!("downstream read: {e}"))?;
            if n == 0 {
                return Err("downstream closed its stdout".into());
            }
            let Ok(v) = serde_json::from_str::<Value>(line.trim()) else {
                continue;
            };
            if v.get("id") == Some(&json!(id))
                && (v.get("result").is_some() || v.get("error").is_some())
            {
                return Ok(v);
            }
            // A request from the server (sampling, roots, elicitation): the
            // gateway does not relay those, so refuse it explicitly.
            if let (Some(sid), Some(_)) = (v.get("id"), v.get("method")) {
                let reply = json!({"jsonrpc":"2.0","id":sid,
                    "error":{"code":-32601,"message":"not supported through taintgate"}});
                self.send(&reply)?;
            }
            // notifications are dropped
        }
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), String> {
        self.send(&json!({"jsonrpc":"2.0","method":method,"params":params}))
    }
}

impl Drop for StdioDownstream {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Streamable HTTP client: POSTs each message, accepts a JSON body or an SSE
/// stream, and keeps the `Mcp-Session-Id` the server assigns.
pub struct HttpDownstream {
    url: String,
    agent: ureq::Agent,
    session: Option<String>,
    negotiated: Option<String>,
    next_id: i64,
}

impl HttpDownstream {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(60))
                .build(),
            session: None,
            negotiated: None,
            next_id: 1,
        }
    }

    fn post(&mut self, msg: &Value) -> Result<Option<Vec<String>>, String> {
        let mut req = self
            .agent
            .post(&self.url)
            .set("Content-Type", "application/json")
            .set("Accept", "application/json, text/event-stream");
        if let Some(s) = &self.session {
            req = req.set("Mcp-Session-Id", s);
        }
        if let Some(v) = &self.negotiated {
            req = req.set("MCP-Protocol-Version", v);
        }
        let resp = match req.send_string(&msg.to_string()) {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                let body = r.into_string().unwrap_or_default();
                return Err(format!("HTTP {code}: {body}"));
            }
            Err(e) => return Err(format!("HTTP: {e}")),
        };
        if let Some(s) = resp.header("Mcp-Session-Id") {
            self.session = Some(s.to_string());
        }
        if resp.status() == 202 {
            return Ok(None);
        }
        let sse = resp
            .header("Content-Type")
            .is_some_and(|c| c.starts_with("text/event-stream"));
        let body = resp.into_string().map_err(|e| e.to_string())?;
        Ok(Some(if sse { sse_data(&body) } else { vec![body] }))
    }
}

/// `data:` payloads of an SSE body, one per event.
pub fn sse_data(body: &str) -> Vec<String> {
    let mut events = Vec::new();
    let mut cur = String::new();
    for line in body.lines() {
        if let Some(d) = line.strip_prefix("data:") {
            if !cur.is_empty() {
                cur.push('\n');
            }
            cur.push_str(d.strip_prefix(' ').unwrap_or(d));
        } else if line.is_empty() && !cur.is_empty() {
            events.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        events.push(cur);
    }
    events
}

impl Downstream for HttpDownstream {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let body = self
            .post(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))?
            .ok_or("HTTP 202 for a request")?;
        for chunk in &body {
            if let Ok(v) = serde_json::from_str::<Value>(chunk.trim()) {
                if v.get("id") == Some(&json!(id)) {
                    if method == "initialize" {
                        self.negotiated = v
                            .pointer("/result/protocolVersion")
                            .and_then(Value::as_str)
                            .map(str::to_string);
                    }
                    return Ok(v);
                }
            }
        }
        Err(format!("no response with id {id} in HTTP body"))
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), String> {
        self.post(&json!({"jsonrpc":"2.0","method":method,"params":params}))
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sse_events() {
        let body = "event: message\ndata: {\"a\":1}\n\ndata: {\"b\":\ndata: 2}\n\n";
        assert_eq!(sse_data(body), vec!["{\"a\":1}", "{\"b\":\n2}"]);
    }
}
