use std::io::{stdin, stdout};
use std::path::PathBuf;

use taintgate::policy::Policy;
use taintgate::proxy::Gateway;

const USAGE: &str = "usage:
  taintgate serve --policy POLICY.toml [--audit FILE.jsonl]
      MCP gateway on stdin/stdout in front of the [[server]]s of the policy.
  taintgate check --policy POLICY.toml
      Parse the policy and print how each rule resolves.";

fn main() {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    let mut policy = None;
    let mut audit = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--policy" => policy = args.next().map(PathBuf::from),
            "--audit" => audit = args.next().map(PathBuf::from),
            "-h" | "--help" => {
                println!("{USAGE}");
                return;
            }
            other => fail(&format!("unknown argument {other}\n{USAGE}")),
        }
    }
    match cmd.as_str() {
        "serve" | "check" => {}
        "-h" | "--help" | "help" => {
            println!("{USAGE}");
            return;
        }
        _ => fail(USAGE),
    }
    let path = policy.unwrap_or_else(|| fail("--policy is required"));
    let p = Policy::load(&path).unwrap_or_else(|e| fail(&e));
    if cmd == "check" {
        println!("gateway: {:?}", p.gateway);
        for s in &p.server {
            println!("server {}: {:?}{:?}", s.name, s.command, s.url);
        }
        for (i, t) in p.tool.iter().enumerate() {
            println!(
                "rule {i}: {} source={:?} sink={} destination={:?} url_destination={:?} trusted={:?} propagate={}",
                t.pattern, t.source, t.sink, t.destination, t.url_destination, t.trusted, t.propagate
            );
        }
        return;
    }
    let mut gw = Gateway::start(p).unwrap_or_else(|e| fail(&e));
    if let Some(a) = audit {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&a)
            .unwrap_or_else(|e| fail(&format!("{}: {e}", a.display())));
        gw = gw.with_audit(Box::new(f));
    }
    if let Err(e) = gw.serve(stdin().lock(), stdout().lock()) {
        fail(&e.to_string());
    }
    eprintln!(
        "taintgate: {} calls, {} blocked, {} labelled results",
        gw.stats.calls, gw.stats.blocked, gw.stats.labelled_results
    );
}

fn fail(msg: &str) -> ! {
    eprintln!("taintgate: {msg}");
    std::process::exit(2)
}
