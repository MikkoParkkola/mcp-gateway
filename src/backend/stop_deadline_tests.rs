// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A gateway stop waits for the kill of a stdio tree it does not stop itself:
//! a capability-executor child let go while idle. The child joined the
//! registry's stop deadline when it was built, but sits outside the registry,
//! so `stop_all_by` stops no transport of it and would return while the tree
//! is still in its exit waits.

use std::sync::Arc;
use std::time::Duration;

use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};

use super::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};

/// Answers `initialize` and `tools/list`, records its pid, and on EOF ignores
/// SIGTERM and keeps running: only the group SIGKILL ends it.
const PEER: &str = r#"import json, os, signal, sys, time
open("leader.pid", "w").write(str(os.getpid()))
for line in sys.stdin:
    req = json.loads(line)
    if "id" not in req:
        continue
    if req.get("method") == "initialize":
        body = {"result": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "serverInfo": {"name": "stays", "version": "1"}}}
    elif req.get("method") == "tools/list":
        body = {"result": {"tools": []}}
    else:
        body = {"error": {"code": -32601, "message": "not found"}}
    print(json.dumps({"jsonrpc": "2.0", "id": req["id"], **body}), flush=True)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
while True:
    time.sleep(0.05)
"#;

/// `Some(false)` running, `Some(true)` exited unreaped, `None` reaped.
fn kernel_view(pid: Pid) -> Option<bool> {
    let options = WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT;
    match waitid(WaitId::Pid(pid), options) {
        Ok(status) => Some(status.is_some()),
        Err(rustix::io::Errno::CHILD) => None,
        Err(e) => panic!("waitid: {e}"),
    }
}

#[tokio::test]
async fn a_gateway_stop_waits_for_an_idle_released_child_to_be_killed() {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::write(dir.path().join("peer.py"), PEER).expect("write peer");
    let registry = BackendRegistry::new();
    let child = Arc::new(Backend::new(
        "capability:stays",
        BackendConfig {
            transport: TransportConfig::Stdio {
                command: "python3 peer.py".to_string(),
                cwd: Some(dir.path().display().to_string()),
                protocol_version: None,
            },
            timeout: Duration::from_secs(10),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    // As the capability executor builds it: joined to the registry's stop
    // deadline, never registered.
    let _ = child.stop_deadline.set(registry.stop_deadline());
    child.ensure_started().await.expect("the child starts");
    let raw: i32 = std::fs::read_to_string(dir.path().join("leader.pid"))
        .expect("pid file")
        .trim()
        .parse()
        .expect("pid");
    let pid = Pid::from_raw(raw).expect("non-zero pid");

    // Let go while idle, with a long plan of its own.
    child.hand_over_now(Duration::from_secs(120));
    let stop_by = tokio::time::Instant::now()
        + crate::transport::KILL_RESERVE_FOR_TEST
        + Duration::from_secs(2);
    registry.stop_all_by(stop_by).await;

    assert_ne!(
        kernel_view(pid),
        Some(false),
        "the gateway stop returned while the released child still ran"
    );
}
