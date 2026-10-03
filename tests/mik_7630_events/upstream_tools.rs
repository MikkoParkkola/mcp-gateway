// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7630 I5b (design section 14): a backend's own
//! `notifications/tools/list_changed` becomes `backend.<x>.tools_changed`.
//! Rows T39l (modern HTTP) and T39m (legacy stdio).

use super::*;

const TOOLS_CHANGED: &str = "notifications/tools/list_changed";

/// T39l: a modern HTTP backend's tools notice reaches a `tools_changed`
/// subscriber, and the listen asked for it.
#[tokio::test]
async fn t39l_a_modern_backend_tools_notice_becomes_an_event() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let peer = HttpPeer::start(Era::Modern).await;
    let gw = start_listed(
        dir.path(),
        &receiver,
        upstream_config(dir.path(), http_backend(&peer), &[]),
    )
    .await;
    let name = event("tools_changed");
    let id = sub(&gw, ALICE, &name, &receiver, json!({})).await;
    eventually("the listen asks for tools", || {
        peer.open_listens()
            .iter()
            .any(|f| f["notifications"]["toolsListChanged"] == true)
    })
    .await;
    peer.push(TOOLS_CHANGED, json!({}));
    expect_events(&receiver, &id, &name, 1).await;
}

/// T39m: a legacy stdio backend's tools notice, on the shared channel.
#[tokio::test]
async fn t39m_a_legacy_stdio_tools_notice_becomes_an_event() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let (command, peer) = upstream_peer::stdio_peer(&dir.path().join("peer"), Era::Legacy);
    let cfg = upstream_config(dir.path(), json!({"command": command}), &[]);
    let gw = start_listed(dir.path(), &receiver, cfg).await;
    let name = event("tools_changed");
    let id = sub(&gw, ALICE, &name, &receiver, json!({})).await;
    // The backend starts for the subscription; give the listener its channel.
    tokio::time::sleep(QUIET).await;
    peer.push(TOOLS_CHANGED, json!({}));
    expect_events(&receiver, &id, &name, 1).await;
}
