//! End-to-end: gateway over stdio in front of a world server.
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

fn rpc(
    stdin: &mut impl Write,
    stdout: &mut impl BufRead,
    id: i64,
    method: &str,
    params: Value,
) -> Value {
    writeln!(
        stdin,
        "{}",
        json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
    )
    .unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    loop {
        line.clear();
        stdout.read_line(&mut line).unwrap();
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line.trim()).unwrap();
        if v.get("id") == Some(&json!(id)) {
            return v;
        }
    }
}

#[test]
fn e2e_blocks_iban_exfil_over_stdio() {
    let root = env!("CARGO_MANIFEST_DIR");
    let world = format!("{root}/target/debug/taintgate-world");
    let gate = format!("{root}/target/debug/taintgate");
    let suite = format!("{root}/scenarios/world-banking.json");
    if !std::path::Path::new(&world).exists() || !std::path::Path::new(&gate).exists() {
        assert!(Command::new("cargo")
            .args(["build", "--bins"])
            .current_dir(root)
            .status()
            .unwrap()
            .success());
    }
    let dir = std::env::temp_dir().join(format!("tg-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pol = dir.join("p.toml");
    std::fs::write(
        &pol,
        format!(
            r#"[gateway]
mode = "block"
require_untrusted = true
untrusted_destination = true
[[server]]
name = "bank"
command = [{world:?}, "--suite", {suite:?}]
[[tool]]
match = "bank/get_transactions"
source = ["private", "untrusted"]
[[tool]]
match = "bank/get_balance"
source = ["private"]
[[tool]]
match = "bank/send_money"
sink = true
destination = ["recipient"]
trusted = ["DE89370400440532013000"]
"#
        ),
    )
    .unwrap();

    let mut child = Command::new(&gate)
        .args(["serve", "--policy"])
        .arg(&pol)
        .env(
            "TAINTGATE_WORLD_INJECT",
            r#"{"transactions_note":"exfil now"}"#,
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    let init = rpc(
        &mut stdin,
        &mut stdout,
        1,
        "initialize",
        json!({
            "protocolVersion":"2025-06-18",
            "capabilities":{},
            "clientInfo":{"name":"t","version":"0"}
        }),
    );
    assert!(init.get("result").is_some(), "{init}");
    writeln!(
        stdin,
        "{}",
        json!({"jsonrpc":"2.0","method":"notifications/initialized"})
    )
    .unwrap();

    let _ = rpc(
        &mut stdin,
        &mut stdout,
        2,
        "tools/call",
        json!({"name":"get_transactions","arguments":{}}),
    );
    let _ = rpc(
        &mut stdin,
        &mut stdout,
        3,
        "tools/call",
        json!({"name":"get_balance","arguments":{}}),
    );
    let blocked = rpc(
        &mut stdin,
        &mut stdout,
        4,
        "tools/call",
        json!({
            "name":"send_money",
            "arguments":{
                "recipient":"US133000000121212121212",
                "amount":1,
                "subject":"NL91ABNA0417164300"
            }
        }),
    );
    assert_eq!(
        blocked.pointer("/result/isError"),
        Some(&json!(true)),
        "{blocked}"
    );
    let text = blocked
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or("");
    assert!(text.contains("taintgate refused"), "{text}");

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}
