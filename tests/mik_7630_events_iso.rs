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

use std::path::Path;
use std::time::Duration;

use delivery::{DEADLINE, wait_until};
use gateway::Gateway;
use receiver::{Receiver, TRUST_CA};
use serde_json::{Value, json};
use subject_peer::{SubjectPeer, TokenEndpoint, resource_of};
use upstream_sub::{delivered, expect_events, sub, upstream_config};

/// Past the 1 s coalescing window plus delivery: "nothing more arrived".
const QUIET: Duration = Duration::from_secs(3);
const TOOLS: &str = "backend.x.tools_changed";
const UPDATED: &str = "backend.x.resource_updated";

fn email(user: &str) -> String {
    format!("{user}@example.test")
}

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

/// A gateway with backend `x` = `backend`, verifying `issuer`'s bearers, and
/// trusting both the receiver's CA and the issuer's.
async fn start(
    root: &Path,
    rx: &Receiver,
    issuer: &issuer::Issuer,
    backend: Value,
    extra_trust: &[&Path],
) -> Gateway {
    let mut cfg = upstream_config(root, backend, &[]);
    cfg["key_server"] = json!({
        "enabled": true,
        "delegated_bearer": true,
        "max_oidc_token_age_secs": 3600,
        "oidc": [{"issuer": issuer.url, "auto_discover": true,
                  "audiences": [issuer::AUDIENCE]}],
        "policies": ["u1", "u2"].map(|user| json!({
            "match": {"issuer": issuer.url, "email": email(user)},
            "scopes": {"backends": ["x"], "tools": ["*"]},
        })),
    });
    let both = root.join("trust-both.pem");
    let mut pem = std::fs::read_to_string(&rx.ca_file).expect("receiver CA");
    pem.push_str(&std::fs::read_to_string(&issuer.ca_file).expect("issuer CA"));
    for ca in extra_trust {
        pem.push_str(&std::fs::read_to_string(ca).expect("extra CA"));
    }
    std::fs::write(&both, pem).expect("combined trust file");
    let trust = both.to_string_lossy();
    Gateway::start_with_env(root, cfg, &[("SSL_CERT_FILE", &trust), (TRUST_CA, &trust)]).await
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

/// ISO-T1, signed_assertion: each user's change reaches that user only, and
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

/// ISO-T1, token_exchange: the same, with each user's credential exchanged at
/// the backend's token endpoint.
#[tokio::test]
async fn iso_t1_token_exchange_each_user_receives_only_their_own_changes() {
    let root = tempfile::tempdir().expect("root");
    let issuer = issuer::Issuer::start(root.path()).await;
    let rx = Receiver::start(root.path()).await;
    let peer = SubjectPeer::start().await;
    let endpoint = TokenEndpoint::start(root.path()).await;
    let backend = json!({
        "http_url": peer.url,
        "identity_propagation": {
            "strategy": "token_exchange",
            "audience": "https://subject-peer.test",
            "token_exchange_endpoint": endpoint.url,
            "required": true,
            "session_mode": "per_user",
        },
    });
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

/// ISO-T6: removing one user's access on reload closes that user's listener
/// with the backend silent, and leaves the other user's open.
#[tokio::test]
async fn iso_t6_a_revoked_user_holds_no_listener_open() {
    let root = tempfile::tempdir().expect("root");
    let issuer = issuer::Issuer::start(root.path()).await;
    let rx = Receiver::start(root.path()).await;
    let peer = SubjectPeer::start().await;
    let mut gw = start(root.path(), &rx, &issuer, signed_backend(&peer), &[]).await;
    for user in ["u1", "u2"] {
        let bearer = issuer.mint(user, &email(user));
        sub(&gw, &bearer, TOOLS, &rx, json!({})).await;
        listening(&peer, &gw, user).await;
    }

    let mut cfg = gw.config().clone();
    let policies = cfg["key_server"]["policies"]
        .as_array_mut()
        .expect("policies");
    policies.retain(|p| p["match"]["email"] != email("u1"));
    gw.rewrite_config(cfg);

    let closed = wait_until(DEADLINE, || peer.open_streams("u1") == 0).await;
    assert!(
        closed,
        "u1's listener stayed open after u1 lost access; peer saw {:?}\n{}",
        peer.seen(),
        gw.logs()
    );
    tokio::time::sleep(QUIET).await;
    assert_eq!(
        peer.open_streams("u1"),
        0,
        "u1's listener did not come back"
    );
    assert!(peer.open_streams("u2") > 0, "u2 keeps its listener");
}
