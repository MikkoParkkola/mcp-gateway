// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7971: a keyless legacy request (authentication off, or on with the
//! path public) that resumes no established session must not get a fresh
//! control identity per request. The per-caller controls (tenant guard here)
//! key such requests on one shared identity, so their breadth accumulates; an
//! established session and a keyed caller keep their own.

use super::*;

/// A meta `gateway_invoke` of `alpha/t` naming `tenant`, as a legacy client
/// sends it, carrying `session` as its `mcp-session-id` when given.
async fn invoke(fx: &Fixture, session: Option<&str>, tenant: &str) -> StatusCode {
    invoke_as(fx, session, None, tenant).await
}

/// [`invoke`], presenting `bearer` as its credential when given.
async fn invoke_as(
    fx: &Fixture,
    session: Option<&str>,
    bearer: Option<&str>,
    tenant: &str,
) -> StatusCode {
    let arguments = json!({"server": "alpha", "tool": "t",
                           "arguments": {"rows": [{"customer_id": tenant}]}});
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                      "params": {"name": "gateway_invoke", "arguments": arguments}});
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json");
    if let Some(session) = session {
        builder = builder.header("mcp-session-id", session);
    }
    if let Some(bearer) = bearer {
        builder = builder.header("authorization", format!("Bearer {bearer}"));
    }
    let request = builder
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    fx.router.clone().oneshot(request).await.unwrap().status()
}

/// A legacy session the gateway established, by its `mcp-session-id`.
async fn open_session(fx: &Fixture) -> String {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                      "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                 "clientInfo": {"name": "t", "version": "1"}}});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let session = response
        .headers()
        .get("mcp-session-id")
        .expect("initialize establishes a session")
        .to_str()
        .unwrap()
        .to_string();
    assert!(!session.is_empty());
    session
}

async fn guarded() -> Fixture {
    fixture(Setup {
        tenant_limit: Some(1),
        ..Setup::default()
    })
    .await
}

/// No session header at all: each request used to be minted its own session,
/// so the second tenant was a first call again and dispatched.
#[tokio::test]
async fn requests_without_a_session_share_one_tenant_window() {
    let fx = guarded().await;
    assert_eq!(invoke(&fx, None, "cust-1").await, StatusCode::OK);
    let _ = invoke(&fx, None, "cust-2").await;
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "the second tenant must be refused: both requests are one caller"
    );
}

/// An `mcp-session-id` the gateway never issued is not an established
/// session: it must not buy a fresh window either.
#[tokio::test]
async fn an_unestablished_session_id_shares_the_same_window() {
    let fx = guarded().await;
    assert_eq!(invoke(&fx, Some("sess-a"), "cust-1").await, StatusCode::OK);
    let _ = invoke(&fx, Some("sess-b"), "cust-2").await;
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "one shared window");
}

/// Positive control: an established session keeps its own window, apart
/// from other sessions and from the shared one.
#[tokio::test]
async fn an_established_session_keeps_its_own_window() {
    let fx = guarded().await;
    let (a, b) = (open_session(&fx).await, open_session(&fx).await);
    assert_ne!(a, b);
    assert_eq!(invoke(&fx, None, "cust-1").await, StatusCode::OK);
    assert_eq!(invoke(&fx, Some(&a), "cust-2").await, StatusCode::OK);
    assert_eq!(invoke(&fx, Some(&b), "cust-3").await, StatusCode::OK);
    assert_eq!(fx.calls.load(Ordering::SeqCst), 3, "three separate windows");
    let _ = invoke(&fx, Some(&a), "cust-4").await;
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        3,
        "session a's own window still counts"
    );
}

/// Authentication on with `/mcp` public, as the shipped presets set it:
/// keyless callers there are as anonymous as with authentication off, and
/// share the one window; a keyed caller on the same path keeps its own.
#[tokio::test]
async fn keyless_callers_on_a_public_path_share_one_window_and_a_key_keeps_its_own() {
    let fx = fixture(Setup {
        auth: Some(AuthConfig {
            public_paths: vec!["/mcp".to_string()],
            ..key_for_alpha(None)
        }),
        tenant_limit: Some(1),
        ..Setup::default()
    })
    .await;
    assert_eq!(invoke(&fx, None, "cust-1").await, StatusCode::OK);
    let _ = invoke(&fx, None, "cust-2").await;
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "keyless: one shared window"
    );
    assert_eq!(
        invoke_as(&fx, None, Some("k"), "cust-3").await,
        StatusCode::OK
    );
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        2,
        "the key has its own window"
    );
}

/// The anomaly default, pinned: session-less callers share one history, so
/// their interleaved sequences produce transitions neither made. Without an
/// `anomaly_block_threshold` that is scored and logged, never refused; the
/// same history under a threshold is refused (positive control).
#[test]
fn a_shared_session_less_history_is_never_blocked_without_a_block_threshold() {
    use crate::security::firewall::{Firewall, FirewallConfig};
    use crate::transition::TransitionTracker;
    let key = super::super::identity::ANONYMOUS_SESSION_LESS_CALLER;
    let admits_all = |block: Option<f64>| {
        let config = FirewallConfig {
            anomaly_detection: true,
            anomaly_block_threshold: block,
            anomaly_min_observations: 1,
            ..FirewallConfig::default()
        };
        let fw = Firewall::from_config(config, Some(Arc::new(TransitionTracker::new())));
        let call = |tool: &str| {
            fw.check_request(key, "alpha", tool, &json!({}), "anonymous", key)
                .allowed
        };
        // Two clients' a1->a2 and b1->b2, interleaved into one history.
        let mut all = true;
        for _ in 0..25 {
            for tool in ["a1", "a2", "b1", "b2"] {
                all &= call(tool);
            }
        }
        // A transition no client ever made.
        all & call("z")
    };
    assert!(
        admits_all(None),
        "no block threshold: scored, never refused"
    );
    assert!(
        !admits_all(Some(0.9)),
        "positive control: the shared history is refused at 0.9"
    );
}
