//! Mock MCP server for the scenario suite. Not a real service.

use std::io::{stdin, stdout};

use taintgate::world::{Suite, World};

fn main() {
    let mut args = std::env::args().skip(1);
    let mut suite = None;
    let mut http = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--suite" => suite = args.next(),
            "--http" => http = args.next(),
            "-h" | "--help" => {
                println!("usage: taintgate-world --suite FILE.json [--http ADDR]");
                return;
            }
            other => fail(&format!("unknown argument {other}")),
        }
    }
    let path = suite.unwrap_or_else(|| fail("--suite is required"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| fail(&format!("{path}: {e}")));
    let s: Suite = serde_json::from_str(&text).unwrap_or_else(|e| fail(&format!("{path}: {e}")));
    let w = World::from_env(s).unwrap_or_else(|e| fail(&e));
    let r = match http {
        Some(addr) => w.serve_http(&addr),
        None => w
            .serve_stdio(stdin().lock(), stdout().lock())
            .map_err(|e| e.to_string()),
    };
    if let Err(e) = r {
        fail(&e);
    }
}

fn fail(msg: &str) -> ! {
    eprintln!("taintgate-world: {msg}");
    std::process::exit(2)
}
