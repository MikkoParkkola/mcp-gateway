// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Per-subscriber isolation of backend upstream events, end to end.
//!
//! Two users, each verified by the key server from their own OIDC token,
//! subscribe to one identity-bound backend whose catalogue differs per user.
//! The backend pushes a change to one user's view; only that user's
//! subscription is delivered it, and each user is served.
//!
//! Unix: the issuer is the owned HTTPS OIDC issuer of the upstream-recovery
//! proof, trusted by the child through `SSL_CERT_FILE` and the debug-only
//! `MCP_GATEWAY_TEST_TRUST_CA`.
#![cfg(unix)]

#[path = "mik_7630_events/delivery.rs"]
#[allow(dead_code, reason = "shared helpers; each binary uses a subset")]
mod delivery;
#[path = "mik_7630_events/gateway.rs"]
#[allow(dead_code, reason = "shared harness; each binary uses a subset")]
mod gateway;
#[path = "task_upstream_recovery_sdk/issuer.rs"]
#[allow(dead_code, reason = "shared fixture; this binary uses a subset")]
mod issuer;
#[path = "mik_7630_events/oidc_gateway.rs"]
#[allow(dead_code, reason = "shared harness; each binary uses a subset")]
mod oidc_gateway;
#[path = "task_upstream_recovery_sdk/pins.rs"]
#[allow(dead_code, reason = "shared fixture; this binary uses a subset")]
mod pins;
#[path = "mik_7630_events/receiver.rs"]
#[allow(dead_code, reason = "shared receiver; each binary uses a subset")]
mod receiver;
#[path = "mik_7630_events/subject_peer.rs"]
#[allow(dead_code, reason = "shared fixture; each binary uses a subset")]
mod subject_peer;
#[path = "mik_7630_events/upstream_sub.rs"]
#[allow(dead_code, reason = "shared helpers; each binary uses a subset")]
mod upstream_sub;

use std::time::Duration;

use delivery::{DEADLINE, wait_until};
use gateway::Gateway;
use oidc_gateway::{email, start};
use receiver::Receiver;
use serde_json::{Value, json};
use subject_peer::{SubjectPeer, TokenEndpoint, resource_of};
use upstream_sub::{delivered, expect_events, sub};

/// Past the 1 s coalescing window plus delivery: "nothing more arrived".
const QUIET: Duration = Duration::from_secs(3);
const TOOLS: &str = "backend.x.tools_changed";
const UPDATED: &str = "backend.x.resource_updated";

/// An identity-bound backend `x` on `peer`, observed per subscriber.
fn signed_backend(peer: &SubjectPeer) -> Value {
    json!({
        "http_url": peer.url,
        "identity_propagation": {
            "strategy": "signed_assertion",
            "audience": "https://subject-peer.test",
            "required": true,
            "session_mode": "per_user",
        },
    })
}

/// Backend `x` on `peer` with each credential exchanged at `endpoint`.
fn exchanged_backend(peer: &SubjectPeer, endpoint: &TokenEndpoint) -> Value {
    json!({
        "http_url": peer.url,
        "identity_propagation": {
            "strategy": "token_exchange",
            "audience": "https://subject-peer.test",
            "token_exchange_endpoint": endpoint.url,
            "required": true,
            "session_mode": "per_user",
        },
    })
}

/// Wait until `subject` holds an open stream on `peer`, or panic with the log.
async fn listening(peer: &SubjectPeer, gw: &Gateway, subject: &str) {
    let open = wait_until(DEADLINE, || peer.open_streams(subject) > 0).await;
    assert!(
        open,
        "no listener stream as {subject}; peer saw {:?}\n{}",
        peer.seen(),
        gw.logs()
    );
}

/// Wait until `peer` holds `subject`'s subscription to its resource, so a
/// resource update pushed next is not dropped for want of one.
async fn subscribed(peer: &SubjectPeer, gw: &Gateway, subject: &str) {
    let uri = resource_of(subject);
    let done = wait_until(DEADLINE, || peer.subscribed_to(subject, &uri)).await;
    assert!(
        done,
        "no resources/subscribe as {subject}; peer saw {:?}\n{}",
        peer.seen(),
        gw.logs()
    );
}

/// ISO-T1, `signed_assertion`: each user's change reaches that user only, and
/// each user is served.
#[tokio::test]
async fn iso_t1_signed_assertion_each_user_receives_only_their_own_changes() {
    let root = tempfile::tempdir().expect("root");
    let issuer = issuer::Issuer::start(root.path()).await;
    let rx = Receiver::start(root.path()).await;
    let peer = SubjectPeer::start().await;
    let gw = start(root.path(), &rx, &issuer, signed_backend(&peer), &[]).await;
    each_user_only_their_own(&peer, &gw, &rx, &issuer).await;
}

/// ISO-T1, `token_exchange`: the same, with each user's credential exchanged at
/// the backend's token endpoint.
#[tokio::test]
async fn iso_t1_token_exchange_each_user_receives_only_their_own_changes() {
    let root = tempfile::tempdir().expect("root");
    let issuer = issuer::Issuer::start(root.path()).await;
    let rx = Receiver::start(root.path()).await;
    let peer = SubjectPeer::start().await;
    let endpoint = TokenEndpoint::start(root.path()).await;
    let backend = exchanged_backend(&peer, &endpoint);
    let gw = start(root.path(), &rx, &issuer, backend, &[&endpoint.ca_file]).await;
    each_user_only_their_own(&peer, &gw, &rx, &issuer).await;
    for user in ["u1", "u2"] {
        assert!(
            endpoint.exchanged().iter().any(|s| s == user),
            "{user}'s credential was exchanged: {:?}",
            endpoint.exchanged()
        );
    }
}

/// Two users subscribe to `x`'s tools and their own resource; each user's
/// change reaches that user only, each is served, and no listener stream
/// opens as anyone else.
async fn each_user_only_their_own(
    peer: &SubjectPeer,
    gw: &Gateway,
    rx: &Receiver,
    issuer: &issuer::Issuer,
) {
    let users = ["u1", "u2"];
    let mut subs = Vec::new();
    for user in users {
        let bearer = issuer.mint(user, &email(user));
        let tools = sub(gw, &bearer, TOOLS, rx, json!({})).await;
        let updated = sub(gw, &bearer, UPDATED, rx, json!({"uri": resource_of(user)})).await;
        subs.push((user, tools, updated));
    }
    for user in users {
        listening(peer, gw, user).await;
        subscribed(peer, gw, user).await;
    }

    for (n, (user, tools, updated)) in subs.iter().enumerate() {
        peer.push_to(user, "notifications/tools/list_changed", json!({}));
        peer.push_to(
            user,
            "notifications/resources/updated",
            json!({"uri": resource_of(user)}),
        );
        expect_events(rx, tools, TOOLS, 1).await;
        expect_events(rx, updated, UPDATED, 1).await;
        // timing: absence
        tokio::time::sleep(QUIET).await;
        for (m, (other, other_tools, other_updated)) in subs.iter().enumerate() {
            // Users already pushed to have their one delivery; later ones none yet.
            let want = usize::from(m <= n);
            assert_eq!(
                delivered(rx, other_tools, TOOLS).len(),
                want,
                "{user}'s tools change and {other}'s subscription"
            );
            assert_eq!(
                delivered(rx, other_updated, UPDATED).len(),
                want,
                "{user}'s resource change and {other}'s subscription"
            );
        }
    }

    // A required backend is never listened to as the gateway.
    let gateway_streams: Vec<_> = peer
        .seen()
        .into_iter()
        .filter(|r| r.method == "GET" && !users.contains(&r.subject.as_str()))
        .collect();
    assert!(gateway_streams.is_empty(), "{gateway_streams:?}");
}

/// Requests from index `from` on that carried no user's own subject. A
/// backend with per-user sessions only gets no gateway session at all, so
/// nothing is exempt: not warm-start, not the health probe.
fn as_anyone_else(peer: &SubjectPeer, from: usize) -> Vec<subject_peer::Request> {
    peer.seen()
        .into_iter()
        .skip(from)
        .filter(|r| !["u1", "u2"].contains(&r.subject.as_str()))
        .collect()
}

/// Requests from index `from` on whose session is another subject's: each
/// listener's requests carry the subject its own session was issued to.
fn in_anothers_session(peer: &SubjectPeer, from: usize) -> Vec<subject_peer::Request> {
    peer.seen()
        .into_iter()
        .skip(from)
        .filter(|r| !r.session.is_empty() && r.session != format!("session-{}", r.subject))
        .collect()
}

/// ISO-T7: a required backend is never reached as the gateway for a per-user
/// listener. Every request after the users subscribe carries a user's own
/// subject: the listener's cold start, its stream, and the re-initialization
/// after the backend drops one user's session.
#[tokio::test]
async fn iso_t7_signed_assertion_listener_only_presents_its_users_credential() {
    let root = tempfile::tempdir().expect("root");
    let issuer = issuer::Issuer::start(root.path()).await;
    let rx = Receiver::start(root.path()).await;
    let peer = SubjectPeer::start().await;
    let gw = start(root.path(), &rx, &issuer, signed_backend(&peer), &[]).await;
    only_its_users_credential(&peer, &gw, &rx, &issuer).await;
}

/// ISO-T7, `token_exchange`: the same, each credential exchanged first.
#[tokio::test]
async fn iso_t7_token_exchange_listener_only_presents_its_users_credential() {
    let root = tempfile::tempdir().expect("root");
    let issuer = issuer::Issuer::start(root.path()).await;
    let rx = Receiver::start(root.path()).await;
    let peer = SubjectPeer::start().await;
    let endpoint = TokenEndpoint::start(root.path()).await;
    let gw = start(
        root.path(),
        &rx,
        &issuer,
        exchanged_backend(&peer, &endpoint),
        &[&endpoint.ca_file],
    )
    .await;
    only_its_users_credential(&peer, &gw, &rx, &issuer).await;
}

/// Every request after the users subscribe carries a user's own subject, and
/// the subject its session was issued to: cold start including the era probe
/// (`server/discover`), stream, the resource
/// subscription, and re-initialization after a dropped session (the refused
/// request that triggers it included).
async fn only_its_users_credential(
    peer: &SubjectPeer,
    gw: &Gateway,
    rx: &Receiver,
    issuer: &issuer::Issuer,
) {
    let from = peer.seen().len();
    for user in ["u1", "u2"] {
        let bearer = issuer.mint(user, &email(user));
        sub(gw, &bearer, TOOLS, rx, json!({})).await;
        sub(gw, &bearer, UPDATED, rx, json!({"uri": resource_of(user)})).await;
        listening(peer, gw, user).await;
        subscribed(peer, gw, user).await;
    }
    let cold: Vec<_> = peer.seen().into_iter().skip(from).collect();
    for user in ["u1", "u2"] {
        // `server/discover` is the era probe: it is seen, and it is the user's.
        for method in ["server/discover", "initialize", "resources/subscribe"] {
            assert!(
                cold.iter().any(|r| r.subject == user && r.method == method),
                "{user}'s listener sent {method} as {user}: {cold:?}"
            );
        }
    }
    assert!(
        as_anyone_else(peer, from).is_empty(),
        "cold start: {:?}",
        as_anyone_else(peer, from)
    );
    assert!(
        in_anothers_session(peer, from).is_empty(),
        "cold start: {:?}",
        in_anothers_session(peer, from)
    );

    let before = peer.seen().len();
    peer.expire_session("u1");
    // Recovered: re-initialized, streaming, and subscribed again, so the
    // checks below see every request recovery sends.
    let recovered = wait_until(DEADLINE, || {
        let after: Vec<_> = peer.seen().into_iter().skip(before).collect();
        peer.open_streams("u1") > 0
            && ["initialize", "resources/subscribe"]
                .iter()
                .all(|m| after.iter().any(|r| r.subject == "u1" && r.method == *m))
    })
    .await;
    assert!(
        recovered,
        "u1's listener re-initialized after its session was dropped; peer saw {:?}\n{}",
        peer.seen(),
        gw.logs()
    );
    assert!(
        as_anyone_else(peer, from).is_empty(),
        "after recovery: {:?}",
        as_anyone_else(peer, from)
    );
    assert!(
        in_anothers_session(peer, from).is_empty(),
        "after recovery: {:?}",
        in_anothers_session(peer, from)
    );
}
