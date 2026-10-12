// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7512 route-parity row for provable agent identity.
//!
//! Its own file because `router/tests.rs` is already over the 800-line
//! ceiling and the gate ratchets: a file that big may shrink, never grow.
//! The shared fixtures stay in `tests.rs`, where the rows that also use
//! them live.

use axum::http::StatusCode;
use tower::ServiceExt;

use super::create_router;
use super::tests::{direct_route_call, direct_route_state_with_identity};

#[tokio::test]
async fn direct_route_refuses_a_declared_label_that_names_an_allowlisted_agent() {
    // Anchor: funded change 3. `known_agents` admits proven principals only, so
    // a caller that merely sets the header cannot satisfy it — on this route as
    // much as on /mcp. Before the split this request was admitted with 200.
    let (state, _store) = direct_route_state_with_identity(crate::config::AgentIdentityConfig {
        enabled: true,
        require_id: true,
        known_agents: vec![crate::security::KnownAgent {
            source: crate::security::AgentSourceKey::Mtls,
            id: "known-agent".to_string(),
        }],
        ..Default::default()
    })
    .await;
    let response = create_router(state)
        .oneshot(direct_route_call(Some("known-agent")))
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a self-declared label satisfied the allowlist on the direct route"
    );
}

// ── #1783: the contradiction refusal is audited on both routes ───────────────
//
// A caller proven by mTLS as A that declares B in `X-Agent-ID` is refused
// (403, -32600) by `check_declared_label`. Each route's refusal arm also
// writes one WARN `agent identity refused` record naming both identities
// (`handlers.rs`, `backend_handlers.rs`); that record is the detection signal,
// so each route's call is pinned here through the real router.

const PROVEN_A: &str = "spiffe://cluster/ns/agents/sa/runner";
const DECLARED_B: &str = "runner";
const AUDIT_TARGET: &str = "mcp_gateway::security::agent_identity";

#[derive(Clone, Default)]
struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("sink").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Send `request` through the router with a JSON subscriber attached to that
/// one future, and return the status plus the identity audit records it wrote.
/// A process-wide TRACE registry keeps every callsite's interest open, as in
/// `agent_identity_audit_tests`, so no record is filtered before capture.
async fn send_and_capture(
    state: std::sync::Arc<super::AppState>,
    request: axum::http::Request<axum::body::Body>,
) -> (StatusCode, serde_json::Value, Vec<serde_json::Value>) {
    use tracing::instrument::WithSubscriber;
    crate::test_log_capture::keep_interest_open();
    let sink = Sink::default();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let response = create_router(state)
        .oneshot(request)
        .with_subscriber(subscriber)
        .await
        .expect("router answers");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let bytes = sink.0.lock().expect("sink").clone();
    let records = String::from_utf8(bytes)
        .expect("utf-8 log output")
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line).expect("one JSON object per line")
        })
        .filter(|record| record["target"] == AUDIT_TARGET)
        .collect();
    (status, json, records)
}

/// `request` as a caller proven as `PROVEN_A` by an mTLS SAN: both routes
/// read the certificate identity from the request extensions.
fn proven_as_a(
    mut request: axum::http::Request<axum::body::Body>,
) -> axum::http::Request<axum::body::Body> {
    request
        .extensions_mut()
        .insert(crate::mtls::identity::CertIdentity {
            san_uris: vec![PROVEN_A.to_string()],
            ..Default::default()
        });
    request
}

/// The refusal happened, and it left exactly one record naming both ids.
fn assert_refusal_audited(
    route: &str,
    (status, json, records): (StatusCode, serde_json::Value, Vec<serde_json::Value>),
) {
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "control: {route} did not refuse: {json}"
    );
    assert_eq!(
        json.pointer("/error/code"),
        Some(&serde_json::json!(-32600)),
        "control: {route}: {json}"
    );
    let refusals: Vec<_> = records
        .iter()
        .filter(|r| r["fields"]["message"] == "agent identity refused")
        .collect();
    assert_eq!(
        refusals.len(),
        1,
        "{route}: expected one `agent identity refused` record, got {records:#?}"
    );
    let record = refusals[0];
    let fields = &record["fields"];
    assert_eq!(record["level"], "WARN", "{route}: {record:#}");
    assert_eq!(fields["refused"], true, "{route}: {record:#}");
    assert_eq!(
        fields["agent_proven"], PROVEN_A,
        "{route}: proven id missing: {record:#}"
    );
    assert_eq!(
        fields["agent_declared"], DECLARED_B,
        "{route}: declared id missing: {record:#}"
    );
    assert_eq!(
        fields["agent_declared_source"], "header",
        "{route}: declared source missing: {record:#}"
    );
    assert_eq!(
        fields["agent_proof"],
        crate::security::ProofSource::MutualTls.to_string(),
        "{route}: {record:#}"
    );
    assert!(
        fields["reason"]
            .as_str()
            .is_some_and(|r| r.contains("contradicts the proven principal")),
        "{route}: not the contradiction refusal: {record:#}"
    );
}

fn contradiction_config() -> crate::config::AgentIdentityConfig {
    crate::config::AgentIdentityConfig {
        enabled: true,
        require_id: true,
        ..Default::default()
    }
}

#[tokio::test]
async fn meta_route_contradiction_refusal_is_audited() {
    let (state, _store) = direct_route_state_with_identity(contradiction_config()).await;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("x-agent-id", DECLARED_B)
        .body(axum::body::Body::from(
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string(),
        ))
        .expect("request");
    let request = proven_as_a(request);
    assert_refusal_audited("/mcp", send_and_capture(state, request).await);
}

#[tokio::test]
async fn direct_route_contradiction_refusal_is_audited() {
    let (state, _store) = direct_route_state_with_identity(contradiction_config()).await;
    let request = proven_as_a(direct_route_call(Some(DECLARED_B)));
    assert_refusal_audited("/mcp/{name}", send_and_capture(state, request).await);
}
