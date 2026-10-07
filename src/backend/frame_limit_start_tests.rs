// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7867: a stdio backend's `max_frame_bytes` reaches the transport it
//! spawns. A child whose `initialize` answer is one 70 000-byte line starts
//! under the default limit and is refused under a 64 KiB one.

use std::sync::Arc;
use std::time::Duration;

use super::Backend;
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};

/// Answers `initialize` with one line padded past 64 KiB, `tools/list` with
/// no tools, and any other request with -32601.
const PEER: &str = r#"import json, sys
for line in sys.stdin:
    req = json.loads(line)
    if "id" not in req:
        continue
    if req.get("method") == "initialize":
        body = {"result": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "serverInfo": {"name": "big", "version": "1", "pad": "x" * 70000}}}
    elif req.get("method") == "tools/list":
        body = {"result": {"tools": []}}
    else:
        body = {"error": {"code": -32601, "message": "not found"}}
    print(json.dumps({"jsonrpc": "2.0", "id": req["id"], **body}), flush=True)
"#;

fn backend(script: &std::path::Path, max_frame_bytes: Option<usize>) -> Arc<Backend> {
    let config = BackendConfig {
        transport: TransportConfig::Stdio {
            command: format!("python3 {}", script.display()),
            cwd: None,
            protocol_version: None,
        },
        max_frame_bytes,
        timeout: Duration::from_secs(10),
        ..BackendConfig::default()
    };
    Arc::new(Backend::new(
        "frame-limit",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

#[tokio::test]
async fn a_configured_frame_limit_refuses_an_oversized_handshake_answer() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("peer.py");
    std::fs::write(&script, PEER).unwrap();

    let default = backend(&script, None);
    tokio::time::timeout(Duration::from_secs(20), default.start())
        .await
        .expect("the default-limit start finished in time")
        .expect("premise: the 70 000-byte answer fits the default limit");

    let raised = backend(&script, Some(128 * 1024));
    tokio::time::timeout(Duration::from_secs(20), raised.start())
        .await
        .expect("the raised-limit start finished in time")
        .expect("control: a configured limit above the answer admits it");

    let limited = backend(&script, Some(64 * 1024));
    let started = tokio::time::timeout(Duration::from_secs(20), limited.start())
        .await
        .expect("the limited start finished in time");
    assert!(
        started.is_err(),
        "a 64 KiB max_frame_bytes must refuse the 70 000-byte initialize answer"
    );
}
