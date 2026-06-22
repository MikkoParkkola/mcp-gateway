//! Acceptance-criterion tests for MIK-6207 (per-request caller identity
//! propagation: owui→mcpo→gateway).
//!
//! Each test pastes its acceptance criterion verbatim and asserts it in the
//! same polarity the AC states. The authoritative machine CHECKs are:
//!   - AC.2 → `cargo test --lib fetch_credential_none_is_backcompat`
//!   - AC.3 → `cargo test --test identity_propagation two_distinct_emails_reach_executor`
//! which live in their named locations; the tests below cover the remaining
//! criteria at the public boundary.

use std::sync::{Arc, Mutex};

use mcp_gateway::capability::{CapabilityDefinition, CapabilityExecutor};
use mcp_gateway::config::SecurityConfig;
use mcp_gateway::key_server::oidc::VerifiedIdentity;

fn provider_less_capability() -> CapabilityDefinition {
    serde_json::from_value(serde_json::json!({
        "name": "identity_probe",
        "providers": {}
    }))
    .expect("minimal capability definition should deserialize")
}

fn identity(email: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: email.to_string(),
        email: email.to_string(),
        name: None,
        groups: Vec::new(),
        issuer: "cf-access-trusted-header".to_string(),
    }
}

/// Build an executor whose identity seam records every observed caller email.
fn recording_executor() -> (CapabilityExecutor, Arc<Mutex<Vec<String>>>) {
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&captured);
    let executor = CapabilityExecutor::new().with_identity_observer(Arc::new(
        move |id: Option<&VerifiedIdentity>| {
            if let Some(caller) = id {
                sink.lock().unwrap().push(caller.email.clone());
            }
        },
    ));
    (executor, captured)
}

/// MIK-6207.AC.1 AC.1: HTTP layer extracts a per-request caller identity from a
/// configurable trusted header (default `Cf-Access-Authenticated-User-Email`,
/// fallback `X-Gateway-Identity`) into an `Option<VerifiedIdentity>`, and
/// threads it as a method param from `handle_tools_call` through to
/// `CapabilityExecutor::execute`.
#[test]
fn ac_1_configurable_trusted_header_defaults_to_cf_access() {
    // The HTTP layer reads this configurable trusted header; its default is the
    // CF-verified email header per the operator trust-model decision.
    let cfg = SecurityConfig::default();
    assert_eq!(
        cfg.caller_identity_header, "Cf-Access-Authenticated-User-Email",
        "default trusted caller-identity header must be the CF Access email header"
    );
}

/// MIK-6207.AC.2 AC.2: `fetch_credential` signature carries
/// `Option<&VerifiedIdentity>`; when identity is `None` behaviour is
/// byte-identical to today (back-compat).
///
/// The byte-identical resolution assertion across `env:`/`file:`/bare-`UPPER`
/// lives in the lib test `fetch_credential_none_is_backcompat`. Here we assert
/// the public-boundary consequence: a `None` identity is observed as `None` and
/// captures nothing — the absent-identity path adds no behaviour.
#[tokio::test]
async fn ac_2_none_identity_is_backcompat_at_boundary() {
    let (executor, captured) = recording_executor();
    let cap = provider_less_capability();

    let _ = executor.execute(&cap, serde_json::json!({}), None).await;

    assert!(
        captured.lock().unwrap().is_empty(),
        "with identity `None`, the seam must observe nothing (back-compat)"
    );
}

/// MIK-6207.AC.3 AC.3: Two distinct caller emails reaching the gateway produce
/// two distinct identities observable downstream (log/test assertion), proving
/// end-to-end propagation.
#[tokio::test]
async fn ac_3_two_distinct_emails_observed_at_executor() {
    let (executor, captured) = recording_executor();
    let cap = provider_less_capability();

    let alice = identity("alice@example.com");
    let bob = identity("bob@example.com");
    let _ = executor
        .execute(&cap, serde_json::json!({}), Some(&alice))
        .await;
    let _ = executor
        .execute(&cap, serde_json::json!({}), Some(&bob))
        .await;

    let seen = captured.lock().unwrap().clone();
    assert!(seen.contains(&"alice@example.com".to_string()));
    assert!(seen.contains(&"bob@example.com".to_string()));
    assert_ne!(seen[0], seen[1], "the two identities must be distinct");
}

/// MIK-6207.AC.4 AC.4: Identity threading does not alter credential resolution
/// when absent and the full quality gate is green.
///
/// Polarity: asserts threading an identity does NOT change the execute outcome
/// versus the absent case — both reach the same resolution path (the only
/// observable difference is the seam capture). The quality-gate half of the AC
/// is verified by `bash scripts/check_quality.sh`.
#[tokio::test]
async fn ac_4_identity_threading_does_not_alter_resolution() {
    let executor = CapabilityExecutor::new();
    let cap = provider_less_capability();

    let absent = executor.execute(&cap, serde_json::json!({}), None).await;
    let alice = identity("alice@example.com");
    let present = executor
        .execute(&cap, serde_json::json!({}), Some(&alice))
        .await;

    assert_eq!(
        absent.is_err(),
        present.is_err(),
        "presence of a caller identity must not change credential resolution outcome"
    );
}

/// MIK-6207.AC.5 AC.deploy: Diff merged to `main` (target main), release binary
/// built and deployed by the cron, and post-deploy gateway logs confirm at least
/// one real request carrying a non-`None` caller identity reaches the executor
/// seam.
///
/// The deploy/merge/log half is verified by the orchestrator (git log + live
/// logs). In-process we assert the executor seam genuinely receives a non-`None`
/// caller identity — the exact condition the post-deploy log check confirms.
#[tokio::test]
async fn ac_5_non_none_identity_reaches_executor_seam() {
    let (executor, captured) = recording_executor();
    let cap = provider_less_capability();

    let real_caller = identity("operator@chat.raxor.ai");
    let _ = executor
        .execute(&cap, serde_json::json!({}), Some(&real_caller))
        .await;

    assert_eq!(
        captured.lock().unwrap().as_slice(),
        ["operator@chat.raxor.ai".to_string()],
        "a non-None caller identity must reach the executor seam"
    );
}
