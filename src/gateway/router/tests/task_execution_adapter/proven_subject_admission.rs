// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7688: a keyed call from a caller proven only by an OAuth agent token or
//! a client certificate is admitted, keyed on that proven subject (the agent's
//! client id; the certificate's SAN URI, else its CN), never on a display name.
//! `/mcp` is public here, as in the shipped presets, so such a caller reaches
//! dispatch as the public client with an empty credential principal.
use super::super::*;
use super::support::*;

use crate::gateway::oauth::AgentIdentity as OAuthAgentIdentity;
use crate::mtls::CertIdentity;

enum Proof {
    Agent(&'static str),
    Cert {
        san: Option<&'static str>,
        cn: Option<&'static str>,
    },
}

async fn public_mcp_state(mock: &Arc<MockBackend>) -> (Arc<AppState>, tempfile::TempDir) {
    let mut auth = two_principal_auth();
    auth.public_paths.push("/mcp".to_string());
    let (state, store) = fixture_state(&auth).await;
    register(&state, BACKEND, mock);
    (state, store)
}

/// A keyed synchronous `gateway_invoke` presenting only `proof`.
async fn keyed_call(state: &Arc<AppState>, proof: &Proof, key: &str) -> Value {
    let body = keyed(sync_invoke(1, json!({"q": 1})), key);
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .body(axum::body::Body::from(body.to_string()))
        .expect("a fixture request builds");
    match proof {
        Proof::Agent(client_id) => {
            request.extensions_mut().insert(OAuthAgentIdentity {
                client_id: (*client_id).to_string(),
                agent_name: "one display name for every agent".to_string(),
                scopes: vec![crate::gateway::oauth::Scope::parse("tools:*").expect("a scope")],
                raw_scopes: vec!["tools:*".to_string()],
                quota_principal: None,
            });
        }
        Proof::Cert { san, cn } => {
            request.extensions_mut().insert(CertIdentity {
                san_uris: san.map(str::to_string).into_iter().collect(),
                common_name: cn.map(str::to_string),
                display_name: "one display name for every certificate".to_string(),
                ..Default::default()
            });
        }
    }
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("the router must answer");
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    serde_json::from_slice(&bytes).expect("a JSON body")
}

fn assert_admitted(body: &Value, what: &str) {
    assert!(
        body.get("error").is_none() && body.get("result").is_some(),
        "{what} must be admitted: {body}"
    );
}

#[tokio::test]
async fn an_agent_only_keyed_call_is_admitted_on_its_client_id() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = public_mcp_state(&mock).await;
    let first = keyed_call(&state, &Proof::Agent("agent-a"), "agent-key").await;
    assert_admitted(&first, "an agent-only keyed call");
    let replay = keyed_call(&state, &Proof::Agent("agent-a"), "agent-key").await;
    assert_admitted(&replay, "its replay");
    std::assert_eq!(mock.calls(), 1, "the replay is the same agent's record");
    let other = keyed_call(&state, &Proof::Agent("agent-b"), "agent-key").await;
    assert_admitted(&other, "another agent on the same key");
    std::assert_eq!(mock.calls(), 2, "two agents never share a record");
}

#[tokio::test]
async fn a_certificate_only_keyed_call_is_admitted_on_its_subject() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = public_mcp_state(&mock).await;
    let by_uri = Proof::Cert {
        san: Some("spiffe://example.test/a"),
        cn: Some("shared-cn"),
    };
    assert_admitted(&keyed_call(&state, &by_uri, "cert-key").await, "a SAN URI");
    assert_admitted(&keyed_call(&state, &by_uri, "cert-key").await, "its replay");
    std::assert_eq!(mock.calls(), 1, "the replay is the same subject's record");
    let by_cn = Proof::Cert {
        san: None,
        cn: Some("shared-cn"),
    };
    assert_admitted(&keyed_call(&state, &by_cn, "cert-key").await, "a CN");
    std::assert_eq!(mock.calls(), 2, "the SAN URI, not the CN, keyed the first");

    let unnamed = Proof::Cert {
        san: None,
        cn: None,
    };
    let refused = keyed_call(&state, &unnamed, "cert-key").await;
    std::assert_eq!(
        refused.pointer("/error/code"),
        Some(&json!(-32003)),
        "a certificate naming no subject is still refused: {refused}"
    );
}
