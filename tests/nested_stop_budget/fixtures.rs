// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The nested chain's fixtures: the leaf backend's script and the HTTP stop
//! floor the binary states (moved from `nested_stop_budget.rs`).

use super::*;

pub(super) const LEAF_SCRIPT: &str = r#"import json, os, signal, subprocess, sys, time
name = sys.argv[1]
signal.signal(signal.SIGTERM, signal.SIG_IGN)
with open("leaf-" + name + ".pid", "w") as f:
    f.write(str(os.getpid()))
# A descendant in the leaf's process group. It inherits the ignored SIGTERM,
# so only the gateway's kill of the whole group ends it.
grandchild = subprocess.Popen(["sleep", "600"])
with open("leaf-" + name + ".grandchild.pid", "w") as f:
    f.write(str(grandchild.pid))
# A "zombie" leaf also holds an unreaped child: it exits at once and the leaf
# never waits for it, so the leaf's tree holds a zombie for the whole stop.
if name.startswith("zombie"):
    if os.fork() == 0:
        os._exit(0)
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    method = msg.get("method")
    if method == "initialize":
        result = {"protocolVersion": msg["params"]["protocolVersion"], "capabilities": {"tools": {}},
                  "serverInfo": {"name": name, "version": "1"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "hold", "inputSchema": {"type": "object"},
                             "annotations": {"readOnlyHint": True}}]}
    elif method == "tools/call" and msg["params"]["name"] == "hold":
        open("called-" + name, "w").close()
        time.sleep(600)
        continue
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
time.sleep(600)
"#;
/// The floor this binary puts under an HTTP stop total, as its own refusal of a
/// one-second total states it. The minimum row pins `HTTP_MINIMUM` to it, so a
/// floor move fails that pin, where a copied number would quietly test a
/// larger budget.
pub(super) async fn http_floor_from_binary() -> Duration {
    let temp = tempfile::tempdir().expect("temp root");
    let root = temp.path();
    let mut config = base_config(root, "probe");
    config.server.host = "127.0.0.1".into();
    config.server.port = gateway_bin::ANY_PORT;
    config.server.shutdown_timeout = Duration::from_secs(1);
    let path = save(root, "probe.yaml", &config);
    let out = tokio::process::Command::from(gateway_bin::command(
        &root.join("home"),
        gateway_bin::Inherit::Environment,
    ))
    .env("MCP_GATEWAY_CONFIG_DIR", root.join("gateway-state"))
    .current_dir(root)
    .arg("--config")
    .arg(path)
    .output()
    .await
    .expect("the probe start ran");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "a one-second stop total was accepted\n{said}"
    );
    let tail = said
        .split("set it to at least ")
        .nth(1)
        .unwrap_or_else(|| panic!("the refusal names no floor\n{said}"));
    let digits: String = tail
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let secs: f64 = digits
        .parse()
        .unwrap_or_else(|_| panic!("the refusal's floor does not read as seconds\n{said}"));
    assert!(
        tail[digits.len()..].starts_with('s'),
        "the refusal's floor is not given in seconds\n{said}"
    );
    Duration::from_secs_f64(secs)
}
