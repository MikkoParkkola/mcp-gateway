// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend with per-user sessions only gets no gateway shared session, end
//! to end.
//!
//! The backend records the credential on every request it receives. Across
//! the gateway's start, its warm-start, several health-loop ticks, an
//! operator's restart of the backend, and a reload that makes an optional
//! binding required, all paths with no subscriber in them, no request reaches
//! it without a subscriber's credential. Not covered here: a subscriber's own
//! per-user session still starts with only the backend's static headers.
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
use oidc_gateway::start_with;
use receiver::Receiver;
use serde_json::{Value, json};
use subject_peer::SubjectPeer;

/// The health loop's period in these rows.
const TICK: Duration = Duration::from_secs(2);

/// Backend `x` on `peer`, its identity binding `required` with per-user
/// sessions.
fn per_user_backend(peer: &SubjectPeer, required: bool) -> Value {
    json!({
        "http_url": peer.url,
        "identity_propagation": {
            "strategy": "signed_assertion",
            "audience": "https://subject-peer.test",
            "required": required,
            "session_mode": "per_user",
        },
    })
}

/// A short health loop, and an admin key for the operator dashboard.
fn probed_with_admin(cfg: &mut Value) {
    cfg["failsafe"]["health_check"] = json!({"enabled": true, "interval": "2s", "timeout": "1s"});
    let admin = json!({
        "name": "admin",
        "key_sha256": mcp_gateway::config::api_key_digest_spec(gateway::ADMIN.as_bytes()),
        "backends": [],
        "admin": true,
    });
    cfg["auth"]["api_keys"]
        .as_array_mut()
        .expect("api keys")
        .push(admin);
}

/// Requests from index `from` on that carried no subscriber's credential.
fn credential_less(peer: &SubjectPeer, from: usize) -> Vec<subject_peer::Request> {
    peer.seen()
        .into_iter()
        .skip(from)
        .filter(|r| r.subject.is_empty())
        .collect()
}

/// SHARED.3: across gateway start, warm-start, three health-loop ticks and an
/// operator's restart of the backend, no request without a subscriber
/// credential reaches it, and the restart is refused rather than rebuilt.
/// The restart is the operator dashboard's, so it needs `webui`.
#[cfg(feature = "webui")]
#[tokio::test]
async fn a_per_user_backend_is_never_reached_as_the_gateway() {
    let root = tempfile::tempdir().expect("root");
    let issuer = issuer::Issuer::start(root.path()).await;
    let rx = Receiver::start(root.path()).await;
    let peer = SubjectPeer::start().await;
    let backend = per_user_backend(&peer, true);
    let gw = start_with(root.path(), &rx, &issuer, backend, &[], probed_with_admin).await;
    // timing: absence
    tokio::time::sleep(TICK * 3 + Duration::from_secs(1)).await;
    let (status, answer) = gw
        .admin(Some(gateway::ADMIN), "POST", "/ui/api/backends/x/revive")
        .await;
    assert_eq!(
        status, 200,
        "premise: the operator's restart was served: {answer}"
    );
    assert_eq!(
        answer["transport_rebuilt"],
        json!(false),
        "a shared session was rebuilt: {answer}"
    );
    // timing: absence
    tokio::time::sleep(TICK).await;
    let reached = credential_less(&peer, 0);
    assert!(
        reached.is_empty(),
        "reached without a subscriber credential: {reached:?}\n{}",
        gw.logs()
    );
}

/// A reload that makes an optional binding required closes the gateway's
/// shared session and never opens another: the backend is replaced, and the
/// new instance has none.
#[tokio::test]
async fn a_binding_made_required_on_reload_ends_the_gateway_session() {
    let root = tempfile::tempdir().expect("root");
    let issuer = issuer::Issuer::start(root.path()).await;
    let rx = Receiver::start(root.path()).await;
    let peer = SubjectPeer::start().await;
    let backend = per_user_backend(&peer, false);
    let mut gw = start_with(root.path(), &rx, &issuer, backend, &[], probed_with_admin).await;
    // Premise: an optional binding may share, so warm-start reaches it as the
    // gateway.
    let warmed = wait_until(DEADLINE, || !credential_less(&peer, 0).is_empty()).await;
    assert!(
        warmed,
        "premise: warm-start reached the backend\n{}",
        gw.logs()
    );

    let mut cfg = gw.config().clone();
    cfg["backends"]["x"]["identity_propagation"]["required"] = json!(true);
    gw.rewrite_config(cfg);
    let reloaded = wait_until(DEADLINE, || gw.logs().contains("Config reload: complete")).await;
    assert!(reloaded, "the reload did not complete\n{}", gw.logs());
    let from = peer.seen().len();
    // timing: absence
    tokio::time::sleep(TICK * 3 + Duration::from_secs(1)).await;
    let reached = credential_less(&peer, from);
    assert!(
        reached.is_empty(),
        "reached as the gateway after the binding became required: {reached:?}\n{}",
        gw.logs()
    );
    assert_eq!(
        peer.open_streams(""),
        0,
        "the gateway's shared stream stayed open"
    );
}

/// START.2: a subscriber's first call opens their own per-user slot, and that
/// slot's start (connect, `server/discover`, a legacy `initialize`) carries
/// the subscriber's credential like every call after it. The backend sees no
/// request at all without a subscriber's credential.
#[tokio::test]
async fn a_per_user_slots_own_start_carries_the_subscribers_credential() {
    let root = tempfile::tempdir().expect("root");
    let issuer = issuer::Issuer::start(root.path()).await;
    let rx = Receiver::start(root.path()).await;
    let peer = SubjectPeer::start().await;
    let backend = per_user_backend(&peer, true);
    let gw = oidc_gateway::start(root.path(), &rx, &issuer, backend, &[]).await;
    let bearer = issuer.mint("u1", &oidc_gateway::email("u1"));
    // The call's catalogue check fills the subscriber's own slot, which
    // starts it; the tool name does not matter.
    gw.rpc(
        Some(&bearer),
        "tools/call",
        json!({"name": "gateway_invoke", "arguments": {
            "server": "x", "tool": "any", "arguments": {}
        }}),
    )
    .await;
    let seen = peer.seen();
    assert!(
        seen.iter().any(|r| r.subject == "u1"),
        "premise: the subscriber's requests reached the backend: {seen:?}"
    );
    let others: Vec<_> = seen.iter().filter(|r| r.subject != "u1").collect();
    assert!(
        others.is_empty(),
        "the per-user slot reached the backend other than as its subscriber: {others:?}\n{}",
        gw.logs()
    );
}

/// `gateway_invoke` of `user`'s own tool on `x` (the peer lists `tool_<user>`
/// to each user): its first call opens the caller's own per-user slot and
/// reaches the backend as a `tools/call`.
async fn invoke_as(gw: &gateway::Gateway, bearer: &str, user: &str) {
    gw.rpc(
        Some(bearer),
        "tools/call",
        json!({"name": "gateway_invoke", "arguments": {
            "server": "x", "tool": format!("tool_{user}"), "arguments": {}
        }}),
    )
    .await;
}

/// START.6: two subscribers on one required per-user backend each reach it
/// only as themselves, start included, each on their own session.
#[tokio::test]
async fn two_subscribers_each_reach_a_per_user_backend_only_as_themselves() {
    let root = tempfile::tempdir().expect("root");
    let issuer = issuer::Issuer::start(root.path()).await;
    let rx = Receiver::start(root.path()).await;
    let peer = SubjectPeer::start().await;
    let gw = oidc_gateway::start(
        root.path(),
        &rx,
        &issuer,
        per_user_backend(&peer, true),
        &[],
    )
    .await;
    for user in ["u1", "u2"] {
        invoke_as(&gw, &issuer.mint(user, &oidc_gateway::email(user)), user).await;
    }
    let seen = peer.seen();
    for user in ["u1", "u2"] {
        assert!(
            seen.iter().any(|r| r.subject == user),
            "premise: {user}'s requests reached the backend: {seen:?}"
        );
    }
    let stray: Vec<_> = seen
        .iter()
        .filter(|r| !matches!(r.subject.as_str(), "u1" | "u2"))
        .collect();
    assert!(
        stray.is_empty(),
        "reached as no subscriber: {stray:?}\n{}",
        gw.logs()
    );
    let crossed: Vec<_> = seen
        .iter()
        .filter(|r| !r.session.is_empty() && r.session != format!("session-{}", r.subject))
        .collect();
    assert!(
        crossed.is_empty(),
        "a request rode another's session: {crossed:?}"
    );
}

/// START.7: a required per-user backend's static credential header reaches
/// none of its per-user requests, its calls included.
#[tokio::test]
async fn a_static_header_never_reaches_a_per_user_send() {
    let root = tempfile::tempdir().expect("root");
    let issuer = issuer::Issuer::start(root.path()).await;
    let rx = Receiver::start(root.path()).await;
    let peer = SubjectPeer::start().await;
    let mut backend = per_user_backend(&peer, true);
    // A placeholder value, built at run time: the header is what is tested.
    backend["headers"][subject_peer::STATIC_HEADER] = json!(format!("static-{}", "marker"));
    let gw = oidc_gateway::start(root.path(), &rx, &issuer, backend, &[]).await;
    invoke_as(&gw, &issuer.mint("u1", &oidc_gateway::email("u1")), "u1").await;
    let seen = peer.seen();
    assert!(
        seen.iter()
            .any(|r| r.subject == "u1" && r.method == "tools/call"),
        "premise: the subscriber's call reached the backend: {seen:?}\n{}",
        gw.logs()
    );
    let carried: Vec<_> = seen.iter().filter(|r| r.static_header).collect();
    assert!(
        carried.is_empty(),
        "a per-user request carried the backend's static header: {carried:?}"
    );
}
