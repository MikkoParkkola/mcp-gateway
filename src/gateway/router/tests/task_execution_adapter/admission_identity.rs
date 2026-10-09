// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8193 (lead conditions on option a): one admission identity for every
//! kind of caller, and no pooling of proven callers on an auth-off gateway.
//!
//! - FP4a/FP4b: an agent-only caller, and a certificate-only caller on an
//!   auth-off gateway, run a keyed call synchronously and then retry it as a
//!   task under the same key: refused, never run twice.
//! - ISO1: two certificate-only callers on an auth-off gateway own their
//!   tasks apart; neither can read or cancel the other's.
use super::super::*;
use super::support::*;

use crate::gateway::oauth::AgentIdentity as OAuthAgentIdentity;
use crate::mtls::CertIdentity;

#[derive(Clone, Copy)]
enum Proof {
    Agent(&'static str),
    Cert(&'static str),
}

/// POST `body` to `/mcp`, proven only by `proof`.
async fn send(state: &Arc<AppState>, proof: Proof, body: &Value) -> Value {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28");
    // The modern era mirrors the method, and the tool name or task id, in headers.
    if let Some(method) = body["method"].as_str() {
        builder = builder.header("mcp-method", method);
    }
    let params = &body["params"];
    if let Some(name) = params["name"]
        .as_str()
        .or_else(|| params["taskId"].as_str())
    {
        builder = builder.header("mcp-name", name);
    }
    let mut request = builder
        .body(axum::body::Body::from(body.to_string()))
        .expect("a fixture request builds");
    match proof {
        Proof::Agent(client_id) => {
            request.extensions_mut().insert(OAuthAgentIdentity {
                client_id: client_id.to_string(),
                agent_name: "agent".to_string(),
                scopes: vec![crate::gateway::oauth::Scope::parse("tools:*").expect("a scope")],
                raw_scopes: vec!["tools:*".to_string()],
                quota_principal: None,
            });
        }
        Proof::Cert(san) => {
            request.extensions_mut().insert(CertIdentity {
                san_uris: vec![san.to_string()],
                display_name: "certificate".to_string(),
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

/// A gateway with `/mcp` public (auth on) or with authentication off.
async fn gateway(auth_on: bool, mock: &Arc<MockBackend>) -> (Arc<AppState>, tempfile::TempDir) {
    let auth = if auth_on {
        let mut auth = two_principal_auth();
        auth.public_paths.push("/mcp".to_string());
        auth
    } else {
        AuthConfig::default()
    };
    let (state, store) = fixture_state(&auth).await;
    register(&state, BACKEND, mock);
    (state, store)
}

/// FP4a/FP4b body: a keyed sync call, then the same call as a task under the
/// same key. Mutant: the sync lease admitting under the proven subject while
/// the task admits under the routed owner.
async fn sync_then_task_is_refused(auth_on: bool, proof: Proof, what: &str) {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = gateway(auth_on, &mock).await;
    let sync = send(
        &state,
        proof,
        &keyed(sync_invoke(1, json!({"q": 1})), "op-fp4"),
    )
    .await;
    assert!(
        sync.get("result").is_some(),
        "{what}: the sync call runs: {sync}"
    );
    let task = send(&state, proof, &task_invoke(2, "op-fp4", json!({"q": 1}))).await;
    assert!(
        task.get("result").is_none(),
        "{what}: admitted again: {task}"
    );
    assert!(task.get("error").is_some(), "{what}: refused: {task}");
    std::assert_eq!(mock.calls(), 1, "{what}: the operation ran twice");
}

#[tokio::test]
async fn fp4a_an_agent_only_caller_cannot_run_one_key_twice() {
    sync_then_task_is_refused(true, Proof::Agent("agent-a"), "agent, auth on").await;
    sync_then_task_is_refused(false, Proof::Agent("agent-a"), "agent, auth off").await;
}

#[tokio::test]
async fn fp4b_a_certificate_only_caller_cannot_run_one_key_twice_with_auth_off() {
    sync_then_task_is_refused(false, Proof::Cert("spiffe://test/a"), "cert, auth off").await;
}

/// ISO1 (lead condition 2): on an auth-off gateway, a certificate-only
/// caller's task belongs to its certificate subject. Another certificate
/// cannot read or cancel it. Before MIK-8193 both were pooled under one
/// anonymous owner. Mutant: the auth-off arm owning by the pooled constant.
#[tokio::test]
async fn iso1_two_certificates_cannot_reach_each_others_tasks_with_auth_off() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = gateway(false, &mock).await;
    let (a, b) = (
        Proof::Cert("spiffe://test/a"),
        Proof::Cert("spiffe://test/b"),
    );
    let created = send(&state, a, &task_invoke(1, "op-iso", json!({"q": 1}))).await;
    let id = task_id(&created);
    let get = task_method(2, "tasks/get", json!({"taskId": id}));
    let own = send(&state, a, &get).await;
    assert!(
        own.get("result").is_some(),
        "the owner reads its task: {own}"
    );
    let read = send(&state, b, &get).await;
    std::assert_eq!(read["error"]["message"], "no such task", "{read}");
    let cancel = task_method(3, "tasks/cancel", json!({"taskId": id}));
    let cancelled = send(&state, b, &cancel).await;
    std::assert_eq!(cancelled["error"]["message"], "no such task", "{cancelled}");
}
