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
