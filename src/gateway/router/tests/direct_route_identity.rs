// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Agent-identity enforcement on the direct route.

use super::*;
use pretty_assertions::assert_eq;

#[tokio::test]
async fn direct_route_rejects_a_missing_agent_id_when_require_id_is_set() {
    let (state, _store) = direct_route_state_with_identity(crate::config::AgentIdentityConfig {
        enabled: true,
        require_id: true,
        known_agents: vec![],
        ..Default::default()
    })
    .await;
    let response = create_router(state)
        .oneshot(direct_route_call(None))
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "require_id is enforced on /mcp, so /mcp/{{name}} must refuse too"
    );
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json.pointer("/error/code"), Some(&json!(-32600)));
    let message = json
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        message.contains("require_id"),
        "the refusal must name the policy that caused it, got: {message}"
    );
}

#[tokio::test]
async fn direct_route_rejects_an_agent_outside_the_allowlist() {
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
        .oneshot(direct_route_call_proven("stranger", None))
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "an agent absent from known_agents must not be admitted by URL choice"
    );
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json.pointer("/error/code"), Some(&json!(-32600)));
    let message = json
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        message.contains("known_agents"),
        "the refusal must name the allowlist, got: {message}"
    );
}

#[tokio::test]
async fn direct_route_rejects_an_unlisted_agent_even_when_id_is_optional() {
    // The allowlist is independent of require_id: it applies whenever an
    // identity resolves. Documented wrongly before this row existed.
    let (state, _store) = direct_route_state_with_identity(crate::config::AgentIdentityConfig {
        enabled: true,
        require_id: false,
        known_agents: vec![crate::security::KnownAgent {
            source: crate::security::AgentSourceKey::Mtls,
            id: "known-agent".to_string(),
        }],
        ..Default::default()
    })
    .await;
    let response = create_router(state)
        .oneshot(direct_route_call_proven("stranger", None))
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "require_id: false governs the absent-ID case only, not the allowlist"
    );
}

#[tokio::test]
async fn direct_route_admits_an_absent_agent_id_when_it_is_optional() {
    // Control for the row above: with require_id false and no ID supplied the
    // guard stays out of the way, so the refusal there is the allowlist.
    let (state, _store) = direct_route_state_with_identity(crate::config::AgentIdentityConfig {
        enabled: true,
        require_id: false,
        known_agents: vec![crate::security::KnownAgent {
            source: crate::security::AgentSourceKey::Mtls,
            id: "known-agent".to_string(),
        }],
        ..Default::default()
    })
    .await;
    let response = create_router(state)
        .oneshot(direct_route_call(None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

/// A direct-route call whose caller PROVED an mTLS identity.
///
/// The parity rows below were written when a header was the only way to supply
/// an agent id, so they exercised a declared label and called it an agent. A
/// proven principal has to arrive the way the handler actually reads one — out
/// of request extensions, put there by the TLS layer — which is what this adds.
fn direct_route_call_proven(
    subject: &str,
    declared: Option<&str>,
) -> axum::http::Request<axum::body::Body> {
    let mut request = direct_route_call(declared);
    request
        .extensions_mut()
        .insert(crate::mtls::identity::CertIdentity {
            common_name: Some(subject.to_string()),
            display_name: "cosmetic".to_string(),
            ..Default::default()
        });
    request
}

#[tokio::test]
async fn direct_route_admits_an_allowlisted_agent() {
    // Control: the guard refuses the two rows above because of identity, not
    // because it refuses the direct route outright.
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
        .oneshot(direct_route_call_proven("known-agent", None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
