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

/// MIK-7937 REFILL.1: a tools notice starts a refill of the cached list. With
/// the backend's `tools/list` hanging, another notice on the same session is
/// still delivered promptly: the refill must not hold the session loop for
/// its 30 s bound.
#[tokio::test]
async fn a_hanging_tools_refill_does_not_hold_other_notices() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let peer = HttpPeer::start(Era::Modern).await;
    let gw = start_listed(
        dir.path(),
        &receiver,
        upstream_config(dir.path(), http_backend(&peer), &[]),
    )
    .await;
    let resources = event("resources_changed");
    let tools_name = event("tools_changed");
    let tools = sub(&gw, ALICE, &tools_name, &receiver, json!({})).await;
    let res = sub(&gw, ALICE, &resources, &receiver, json!({})).await;
    eventually("the listen asks for tools and resources", || {
        peer.open_listens().iter().any(|f| {
            f["notifications"]["toolsListChanged"] == true
                && f["notifications"]["resourcesListChanged"] == true
        })
    })
    .await;
    let lists_before = peer.frames("tools/list").len();
    let tools_before = delivered(&receiver, &tools, &tools_name).len();
    peer.hang_tools_list();
    peer.push(TOOLS_CHANGED, json!({}));
    eventually("the refill reached the backend", || {
        peer.frames("tools/list").len() > lists_before
    })
    .await;

    peer.push("notifications/resources/list_changed", json!({}));
    let prompt = wait_until(Duration::from_secs(10), || {
        !delivered(&receiver, &res, &resources).is_empty()
    })
    .await;
    assert!(
        prompt,
        "a resources notice waited behind the hanging tools refill"
    );
    // REFILL.2: the tools change is still announced, once the refill ends
    // (here by its 30 s bound, the peer holding the list for a minute).
    let announced = wait_until(Duration::from_secs(45), || {
        delivered(&receiver, &tools, &tools_name).len() > tools_before
    })
    .await;
    assert!(announced, "the tools change was never announced");
}

/// MIK-7937: a refill in flight is not restarted by the next tools notice
/// (that notice waits for the refill to end), and a session that ends during
/// the refill still waits for it and announces the change before it closes.
#[tokio::test]
async fn a_refill_in_flight_is_kept_and_announced_when_the_session_ends() {
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
    let tools = sub(&gw, ALICE, &name, &receiver, json!({})).await;
    eventually("the listen asks for tools", || {
        peer.open_listens()
            .iter()
            .any(|f| f["notifications"]["toolsListChanged"] == true)
    })
    .await;
    let lists_before = peer.frames("tools/list").len();
    let tools_before = delivered(&receiver, &tools, &name).len();
    peer.hang_tools_list();
    peer.push(TOOLS_CHANGED, json!({}));
    eventually("the refill reached the backend", || {
        peer.frames("tools/list").len() > lists_before
    })
    .await;

    peer.push(TOOLS_CHANGED, json!({}));
    let restarted = wait_until(Duration::from_secs(3), || {
        peer.frames("tools/list").len() > lists_before + 1
    })
    .await;
    assert!(!restarted, "a notice restarted the refill in flight");

    // The session ends while the refill hangs; the change is announced once
    // the refill ends (its 30 s bound, the peer holding the list a minute).
    peer.drop_streams();
    let announced = wait_until(Duration::from_secs(45), || {
        delivered(&receiver, &tools, &name).len() > tools_before
    })
    .await;
    assert!(announced, "a session end dropped the refill's tools change");
}
