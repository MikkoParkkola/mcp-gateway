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
    // A legacy peer shows no attach signal: send the notice until the
    // listener, which attaches some time after the subscribe, passes one on.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while delivered(&receiver, &id, &name).is_empty() && tokio::time::Instant::now() < deadline {
        peer.push(TOOLS_CHANGED, json!({}));
        wait_until(QUIET, || !delivered(&receiver, &id, &name).is_empty()).await;
    }
    expect_events(&receiver, &id, &name, 1).await;
}

/// An HTTP backend whose calls time out after 2 s, which bounds a hanging
/// tools refill too (MIK-7951 REFILLFU.4).
fn quick_backend(peer: &HttpPeer) -> Value {
    let mut backend = http_backend(peer);
    backend["timeout"] = json!("2s");
    backend
}

/// MIK-7937 REFILL.1: a tools notice starts a refill of the cached list. With
/// the backend's `tools/list` hanging, another notice on the same session is
/// still delivered promptly: the refill must not hold the session loop.
#[tokio::test]
async fn a_hanging_tools_refill_does_not_hold_other_notices() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let peer = HttpPeer::start(Era::Modern).await;
    let gw = start_listed(
        dir.path(),
        &receiver,
        upstream_config(dir.path(), quick_backend(&peer), &[]),
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
    // REFILL.2, MIK-7951 REFILLFU.3: a refill that ends without filling
    // (here the backend's 2 s timeout, the peer holding the list for a
    // minute) still announces the tools change.
    let announced = wait_until(Duration::from_secs(10), || {
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

    // The session ends while the refill hangs (the pause lets it see the
    // stream close first, or the loop would announce as usual); the change
    // is announced once the refill ends, here when the peer answers.
    peer.drop_streams();
    tokio::time::sleep(QUIET).await;
    peer.release_tools_list();
    let announced = wait_until(Duration::from_secs(10), || {
        delivered(&receiver, &tools, &name).len() > tools_before
    })
    .await;
    assert!(announced, "a session end dropped the refill's tools change");
}

/// Distinct `tools/list` requests the peer saw (a request is logged once per
/// id, whatever its retries or timeouts).
fn tools_lists(peer: &HttpPeer) -> usize {
    peer.frames("tools/list")
        .iter()
        .map(|f| f["id"].to_string())
        .collect::<std::collections::BTreeSet<_>>()
        .len()
}

/// Subscribe to `tools_changed` on a modern HTTP peer and wait for the listen
/// to ask for it: the gateway, the subscription and the counts before.
async fn tools_session(
    dir: &Path,
    receiver: &Receiver,
    peer: &HttpPeer,
) -> (Gateway, String, String) {
    let cfg = upstream_config(dir, http_backend(peer), &[]);
    let gw = start_listed(dir, receiver, cfg).await;
    let name = event("tools_changed");
    let tools = sub(&gw, ALICE, &name, receiver, json!({})).await;
    eventually("the listen asks for tools", || {
        peer.open_listens()
            .iter()
            .any(|f| f["notifications"]["toolsListChanged"] == true)
    })
    .await;
    (gw, name, tools)
}

/// MIK-7951 REFILLFU.5: a second tools notice during a refill is served by
/// the next refill, which runs once the first ends, and the change is
/// announced.
#[tokio::test]
async fn a_notice_during_a_refill_is_served_by_the_next_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let peer = HttpPeer::start(Era::Modern).await;
    let (_gw, name, tools) = tools_session(dir.path(), &receiver, &peer).await;
    let lists_before = tools_lists(&peer);
    peer.hang_tools_list();
    peer.push(TOOLS_CHANGED, json!({}));
    eventually("the first refill reached the backend", || {
        tools_lists(&peer) > lists_before
    })
    .await;
    peer.push(TOOLS_CHANGED, json!({}));
    tokio::time::sleep(QUIET).await;
    assert_eq!(
        tools_lists(&peer),
        lists_before + 1,
        "the second notice waits for the refill in flight"
    );
    peer.release_tools_list();
    eventually("the next refill served the second notice", || {
        tools_lists(&peer) > lists_before + 1
    })
    .await;
    expect_events(&receiver, &tools, &name, 1).await;
}

/// MIK-8007: a tools notice still owed when the session ends (it came during
/// a refill) is served once the backend is listened to again, not dropped
/// with the session.
#[tokio::test]
async fn a_notice_owed_when_the_session_ends_is_still_served() {
    let dir = tempfile::tempdir().expect("tempdir");
    let receiver = Receiver::start(dir.path()).await;
    let peer = HttpPeer::start(Era::Modern).await;
    let (_gw, _name, _tools) = tools_session(dir.path(), &receiver, &peer).await;
    let lists_before = tools_lists(&peer);
    peer.hang_tools_list();
    peer.push(TOOLS_CHANGED, json!({}));
    eventually("the first refill reached the backend", || {
        tools_lists(&peer) > lists_before
    })
    .await;
    peer.push(TOOLS_CHANGED, json!({}));
    // Let the second notice be noted, then end the session mid-refill.
    tokio::time::sleep(Duration::from_secs(1)).await;
    peer.drop_streams();
    tokio::time::sleep(QUIET).await;
    peer.release_tools_list();
    eventually("the owed notice was served after the session ended", || {
        tools_lists(&peer) > lists_before + 1
    })
    .await;
    // Served once: a later session owes nothing.
    let served = tools_lists(&peer);
    peer.drop_streams();
    eventually("the backend is listened to again", || {
        !peer.open_listens().is_empty()
    })
    .await;
    tokio::time::sleep(QUIET).await;
    assert_eq!(
        tools_lists(&peer),
        served,
        "a served notice was refilled again"
    );
}
