// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7885: a direct-route notification is charged to the credential's slot
//! principal, the one its request arm uses, not to the display label two
//! credentials can share. The two arms then resolve one upstream-session
//! binding for one credential, and two credentials with the same label get
//! two bindings (so two slot budgets).

use axum::http::StatusCode;
use serde_json::json;
use sha2::Digest as _;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

use super::create_router;
use super::direct_notification_credential_tests::{
    NOTE, PASSTHROUGH, Seen, SlotWire, backend_config, http,
};
use crate::backend::{Backend, PoolKey};
use crate::config::{ApiKeyConfig, AuthConfig, FailsafeConfig};
use crate::gateway::auth::QuotaPrincipal;
use crate::identity_propagation::PropagationStrategyKind;
use crate::security::{TransparencyLogConfig, TransparencyLogger};

const LABEL: &str = "shared label";
const VALUE: &str = "Bearer caller-own";
const ONE: &str = "secret-one-0123456789";
const TWO: &str = "secret-two-0123456789";

/// An API key. Every key carries the same label; the secret is its identity.
fn api_key(secret: &str) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(secret.as_bytes())),
        expires_at: None,
        name: LABEL.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        kind: crate::config::ApiKeyKind::Shared,
    }
}

/// The upstream-session binding the request arm gives the key `secret` for
/// `VALUE`: the credential's slot principal, then the value's digest.
fn request_binding(secret: &str) -> String {
    let key_digest =
        crate::config::parse_api_key_digest(&crate::config::api_key_digest_spec(secret.as_bytes()))
            .expect("a computed digest parses");
    let slot = QuotaPrincipal::api_key(&key_digest)
        .as_store_key()
        .to_owned();
    let digest = hex::encode(sha2::Sha256::digest(VALUE.as_bytes()));
    crate::backend::passthrough_binding(&format!("proven:{slot}"), &digest)
}

struct Fixture {
    router: axum::Router,
    seen: Seen,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

/// A required-passthrough backend behind auth with two same-label keys, whose
/// slot for each key's request-arm binding records what it is handed.
async fn fixture() -> Fixture {
    let seen = Seen::default();
    let backend = Arc::new(Backend::new(
        "ledger",
        backend_config(http(), PropagationStrategyKind::Passthrough, true),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    for (secret, slot) in [(ONE, "one"), (TWO, "two")] {
        backend.set_pooled_transport_for_test(
            &PoolKey::PerUser {
                binding: request_binding(secret),
            },
            Arc::new(SlotWire {
                slot,
                seen: Arc::clone(&seen),
            }),
        );
    }
    let audit = tempfile::tempdir().expect("tempdir");
    let log = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: audit
                .path()
                .join("audit.jsonl")
                .to_string_lossy()
                .into_owned(),
            key_id: "mik-7885".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("transparency logger opens"),
    );
    let auth = AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: vec![api_key(ONE), api_key(TWO)],
        public_paths: vec!["/health".to_string()],
        ..AuthConfig::default()
    };
    let (mut state, store) = super::tests::test_router_app_state_with_auth(&auth).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    assert!(state_mut.backends.register(backend), "fixture registration");
    // A required credential is not forwarded without a route log.
    state_mut.transparency_log = Some(log);
    Fixture {
        router: create_router(state),
        seen,
        _dirs: (audit, store),
    }
}

async fn notify_as(fx: &Fixture, secret: &str) -> StatusCode {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/ledger")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {secret}"))
        .header(PASSTHROUGH, VALUE)
        .body(axum::body::Body::from(
            json!({ "jsonrpc": "2.0", "method": NOTE, "params": { "requestId": 7 } }).to_string(),
        ))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let _ = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    status
}

/// SLOT.1 and SLOT.3: the notification lands on the slot the same
/// credential's request uses. Mutant: it resolves its binding from the
/// label, so it reaches no slot the request arm owns.
#[tokio::test]
async fn a_notification_lands_on_the_slot_its_credentials_request_uses() {
    let fx = fixture().await;

    assert_eq!(notify_as(&fx, ONE).await, StatusCode::ACCEPTED);

    assert_eq!(
        *fx.seen.lock(),
        vec![("one", NOTE.to_string(), Some(VALUE.to_string()))]
    );
}

/// SLOT.2: two credentials with one label hold two bindings, so each charges
/// its own slot budget. Mutant: both resolve the label's binding and share
/// one budget, so one can exhaust the other's.
#[tokio::test]
async fn two_credentials_with_one_label_notify_on_separate_slots() {
    let fx = fixture().await;

    assert_eq!(notify_as(&fx, ONE).await, StatusCode::ACCEPTED);
    assert_eq!(notify_as(&fx, TWO).await, StatusCode::ACCEPTED);

    let slots: Vec<&str> = fx.seen.lock().iter().map(|(slot, ..)| *slot).collect();
    assert_eq!(slots, vec!["one", "two"]);
}
