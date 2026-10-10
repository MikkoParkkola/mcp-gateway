// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8293: one caller cannot fill the shared continuation pool. A caller
//! holds at most 64 open rounds per replica; the 65th is refused the way a
//! full pool refuses, and every other caller keeps its room. Rows on the
//! direct route `POST /mcp/{name}`, both arms.

use serde_json::{Value, json};

use super::direct_continuation_tests::{BACKENDS, answers, call, code, held, state_of};
use super::direct_guards_fixture::{Answer, Fx, fixture, fixture_propagating};

/// The per-caller cap the rows expect (design r3 D3: `IN_FLIGHT_CAPACITY / 64`).
const CAP: usize = 64;

/// `CAP` fresh calls as `subject`, each asserted to have been asked.
async fn fill(fx: &Fx, backend: &str, subject: &str) -> Vec<Value> {
    let mut asked = Vec::with_capacity(CAP);
    for i in 0..CAP {
        let (_, body) = call(fx, backend, Some(subject), json!({})).await;
        assert_eq!(
            body["result"]["resultType"], "input_required",
            "setup: {backend} call {i} as {subject} was not asked: {body}"
        );
        asked.push(body);
    }
    asked
}

/// Redeem the round `asked` carries, as `subject`.
async fn redeem(fx: &Fx, backend: &str, subject: &str, asked: &Value) -> Value {
    let retry = json!({"requestState": state_of(asked), "inputResponses": answers()});
    call(fx, backend, Some(subject), retry).await.1
}

/// S1 (SLOTQ.1, SLOTQ.2): alice at her cap is refused her 65th round, and bob
/// can still be asked and answer. Red on base: the 65th is served.
/// Mutants m1 (no cap check), m2 (one count for every caller).
#[tokio::test]
async fn s1_a_caller_at_its_cap_leaves_room_for_another() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskAlways, |_| {}).await;
        fill(&fx, backend, "alice").await;
        assert_eq!(
            held(&fx).await,
            CAP,
            "setup: {backend}: alice's rounds are held"
        );

        let (_, over) = call(&fx, backend, Some("alice"), json!({})).await;
        assert_eq!(
            code(&over),
            Some(-32003),
            "{backend}: alice's 65th round was served: {over}"
        );

        let (_, bobs) = call(&fx, backend, Some("bob"), json!({})).await;
        assert_eq!(
            bobs["result"]["resultType"], "input_required",
            "{backend}: {bobs}"
        );
        let done = redeem(&fx, backend, "bob", &bobs).await;
        assert!(
            done.get("error").is_none(),
            "{backend}: bob's answer: {done}"
        );
    }
}

/// S2 (SLOTQ.1, rule 4): the refusal at the cap is the one a full pool gives,
/// field for field, and nothing alice already holds is evicted: all 64 rounds
/// still redeem. Red on base: the 65th is served, so there is no refusal.
#[tokio::test]
async fn s2_the_cap_refuses_like_a_full_pool_and_evicts_nothing() {
    for backend in BACKENDS {
        let full = fixture(Answer::AskAlways, |meta| {
            meta.set_continuation_for_test(
                crate::protocol::continuation::ContinuationState::full_for_test(),
            );
        })
        .await;
        let (_, pool_full) = call(&full, backend, Some("alice"), json!({})).await;
        assert_eq!(
            code(&pool_full),
            Some(-32003),
            "setup: {backend}: {pool_full}"
        );

        let fx = fixture(Answer::AskAlways, |_| {}).await;
        let asked = fill(&fx, backend, "alice").await;
        let (_, over) = call(&fx, backend, Some("alice"), json!({})).await;
        assert_eq!(
            over.get("error"),
            pool_full.get("error"),
            "{backend}: the cap's refusal differs from a full pool's"
        );

        for (i, round) in asked.iter().enumerate() {
            let done = redeem(&fx, backend, "alice", round).await;
            assert!(
                done.get("error").is_none(),
                "{backend}: round {i} was evicted: {done}"
            );
        }
    }
}

/// S4a (SLOTQ.4): a redeem gives alice's slot back. At her cap her 65th is
/// refused; after one redeem 63 are held and her next round is served. Red
/// on base: the 65th is served.
#[tokio::test]
async fn s4a_a_redeem_frees_a_slot_under_the_cap() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskAlways, |_| {}).await;
        let asked = fill(&fx, backend, "alice").await;
        let (_, over) = call(&fx, backend, Some("alice"), json!({})).await;
        assert_eq!(
            code(&over),
            Some(-32003),
            "{backend}: the 65th was served: {over}"
        );

        let done = redeem(&fx, backend, "alice", &asked[0]).await;
        assert!(done.get("error").is_none(), "setup: {backend}: {done}");
        assert_eq!(
            held(&fx).await,
            CAP - 1,
            "setup: {backend}: the redeem freed nothing"
        );

        let (_, again) = call(&fx, backend, Some("alice"), json!({})).await;
        assert_eq!(
            again["result"]["resultType"], "input_required",
            "{backend}: the freed slot was not reusable: {again}"
        );
    }
}

/// A propagation strategy that records every binding it mints for.
#[derive(Default)]
struct Recording(std::sync::Mutex<std::collections::BTreeSet<String>>);

#[async_trait::async_trait]
impl crate::identity_propagation::IdentityPropagation for Recording {
    async fn propagate(
        &self,
        identity: &crate::key_server::oidc::VerifiedIdentity,
        backend: &crate::identity_propagation::BackendDescriptor,
    ) -> Result<
        crate::identity_propagation::PropagatedCredential,
        crate::identity_propagation::PropagationError,
    > {
        let binding = format!("{}@{}", identity.subject, backend.audience);
        self.0.lock().unwrap().insert(binding.clone());
        Ok(crate::identity_propagation::PropagatedCredential {
            headers: vec![("Authorization".to_string(), "Bearer minted".to_string())],
            expires_at: i64::MAX,
            cache_binding: binding,
            subject_key: identity.subject.clone(),
            audience: backend.audience.clone(),
            scopes: Vec::new(),
        })
    }
}

/// S3c (SLOTQ.3): one caller reaching two backends under two propagated
/// bindings still has one cap. Alice asks 32 questions on each backend; her
/// 65th, on either, is refused. Setup check: two distinct bindings were
/// minted. Red on base: the 65th is served. Mutant m5: the direct site keys
/// the cap on the bound source, giving one cap per binding.
#[tokio::test]
async fn s3c_one_caller_has_one_cap_across_propagated_bindings() {
    let recording = std::sync::Arc::new(Recording::default());
    let strategy = std::sync::Arc::clone(&recording);
    let fx = fixture_propagating(Answer::AskAlways, move |meta| {
        meta.set_identity_propagation(strategy);
    })
    .await;
    seed_caller_slots(&fx, "alice");
    for backend in BACKENDS {
        for i in 0..CAP / 2 {
            let (_, body) = call(&fx, backend, Some("alice"), json!({})).await;
            assert_eq!(
                body["result"]["resultType"], "input_required",
                "setup: {backend} call {i} was not asked: {body}"
            );
        }
    }
    let bindings = recording.0.lock().unwrap().clone();
    assert_eq!(
        bindings.len(),
        2,
        "setup: two distinct bindings: {bindings:?}"
    );
    assert_eq!(held(&fx).await, CAP, "setup: alice's rounds are held");

    let (_, over) = call(&fx, BACKENDS[0], Some("alice"), json!({})).await;
    assert_eq!(
        code(&over),
        Some(-32003),
        "alice's 65th round, across two bindings, was served: {over}"
    );
}

/// A propagated call dispatches on the caller's own pool slot, keyed by its
/// binding; seed `subject`'s slot on each backend with the fixture's scripted
/// backend so the call reaches it.
fn seed_caller_slots(fx: &Fx, subject: &str) {
    for backend in BACKENDS {
        let registered = fx.state.backends.get(backend).expect("fixture backend");
        let shared = registered
            .pooled_transport_for_test(&crate::backend::PoolKey::Shared)
            .expect("the fixture's scripted transport");
        registered.set_pooled_transport_for_test(
            &crate::backend::PoolKey::PerUser {
                binding: format!("{subject}@aud-{backend}"),
            },
            shared,
        );
    }
}

/// `gateway_invoke` of `read` on `server` through `/mcp`, as key `k-std`
/// carrying `subject`'s verified identity, from a modern client that declares
/// form elicitation (so the question may be asked).
async fn meta_call(fx: &Fx, server: &str, subject: &str) -> Value {
    let params = json!({
        "name": "gateway_invoke",
        "arguments": {"server": server, "tool": "read", "arguments": {}},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}},
        },
    });
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", "Bearer k-std")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
                .to_string(),
        ))
        .unwrap();
    request
        .extensions_mut()
        .insert(crate::key_server::oidc::VerifiedIdentity {
            subject: subject.to_string(),
            email: format!("{subject}@example.invalid"),
            name: None,
            groups: vec![],
            issuer: "https://a.example.invalid".to_string(),
        });
    let response = tower::ServiceExt::oneshot(fx.router.clone(), request)
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap_or(Value::Null)
}

/// S3b2 (SLOTQ.3): on the meta route too, one identity reaching two backends
/// under two propagated bindings has one cap. Setup check: two distinct
/// bindings were minted and 64 rounds are held. Red on base: the 65th is
/// served. Mutant: the meta site keys the cap on its bound source.
#[tokio::test]
async fn s3b2_one_identity_has_one_cap_across_bindings_on_the_meta_route() {
    let recording = std::sync::Arc::new(Recording::default());
    let strategy = std::sync::Arc::clone(&recording);
    let fx = fixture_propagating(Answer::AskAlways, move |meta| {
        meta.set_identity_propagation(strategy);
    })
    .await;
    seed_caller_slots(&fx, "alice");
    for backend in BACKENDS {
        for i in 0..CAP / 2 {
            let body = meta_call(&fx, backend, "alice").await;
            assert_eq!(
                body["result"]["resultType"], "input_required",
                "setup: meta call {i} to {backend} was not asked: {body}"
            );
        }
    }
    let bindings = recording.0.lock().unwrap().clone();
    assert_eq!(
        bindings.len(),
        2,
        "setup: two distinct bindings: {bindings:?}"
    );
    assert_eq!(held(&fx).await, CAP, "setup: alice's rounds are held");

    let over = meta_call(&fx, BACKENDS[0], "alice").await;
    assert_eq!(
        code(&over),
        Some(-32003),
        "alice's 65th meta round, across two bindings, was served: {over}"
    );
}

/// S3b1 (SLOTQ.3): one API key has one cap whether it calls live or through a
/// task worker. A live caller carries its credential digest bare; the worker
/// is rebuilt with the task owner, the same digest under the
/// `credential:` prefix (`task_service/execution/context.rs`). Alice's key
/// asks 32 rounds each way; her 65th is refused. Red on base: the 65th is
/// served. Mutant m4: the credential normalisation dropped, so the two
/// spellings are two caps.
#[tokio::test]
async fn s3b1_one_key_has_one_cap_live_and_in_a_task_worker() {
    let fx = fixture(Answer::AskAlways, |_| {}).await;
    let declared = crate::protocol::meta::classify_request(
        Some(&json!({"_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}}
        }})),
        Some("2026-07-28"),
    )
    .declared_capabilities();
    let task_owner = format!(
        "{}digest-alice",
        crate::gateway::auth::CREDENTIAL_OWNER_PREFIX
    );
    let fresh: &'static crate::protocol::mrtr::RetryFields = Box::leak(Box::default());
    let caller = |principal: &'static str| crate::gateway::meta_mcp::MetaMcpCallerContext {
        credential_principal: Some(principal),
        authentication: crate::gateway::meta_mcp::Authentication::Authenticated,
        input_capabilities: declared,
        retry: fresh,
        ..crate::gateway::meta_mcp::anonymous_caller()
    };
    let task_owner: &'static str = Box::leak(task_owner.into_boxed_str());
    let args = json!({"server": "alpha", "tool": "read", "arguments": {}});
    let meta = &fx.state.meta_mcp;
    for (who, principal) in [("live", "digest-alice"), ("task worker", task_owner)] {
        for i in 0..CAP / 2 {
            let asked = meta
                .invoke_tool_for_test(&args, None, &caller(principal))
                .await;
            assert!(
                asked
                    .as_ref()
                    .is_ok_and(|v| v.get("resultType") == Some(&json!("input_required"))),
                "setup: {who} call {i} was not asked: {asked:?}"
            );
        }
    }
    assert_eq!(held(&fx).await, CAP, "setup: alice's rounds are held");

    let over = meta
        .invoke_tool_for_test(&args, None, &caller("digest-alice"))
        .await;
    assert!(
        over.as_ref().is_err_and(|e| e.to_rpc_code() == -32003),
        "alice's 65th round, live after task-worker rounds, was served: {over:?}"
    );
}

/// S3e (SLOTQ.3, SLOTQ.5): one stdio process has one cap across its live
/// calls and its task workers. Both carry the process nonce (a worker gets
/// the host's, `LiveHost::stdio_nonce`) under different credential
/// principals. 32 rounds each way; the 65th is refused, and an HTTP caller
/// can still be asked. Red on base: the 65th is served. Mutant: the cap keyed
/// on the credential before the stdio nonce.
#[tokio::test]
async fn s3e_one_stdio_process_has_one_cap_live_and_in_a_task_worker() {
    let fx = fixture(Answer::AskAlways, |_| {}).await;
    let declared = crate::protocol::meta::classify_request(
        Some(&json!({"_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}}
        }})),
        Some("2026-07-28"),
    )
    .declared_capabilities();
    let nonce = crate::gateway::StdioNonce::leaked_for_test();
    let fresh: &'static crate::protocol::mrtr::RetryFields = Box::leak(Box::default());
    let caller =
        |stdio: bool, principal: &'static str| crate::gateway::meta_mcp::MetaMcpCallerContext {
            stdio_nonce: stdio.then_some(nonce),
            credential_principal: Some(principal),
            authentication: crate::gateway::meta_mcp::Authentication::Authenticated,
            input_capabilities: declared,
            retry: fresh,
            ..crate::gateway::meta_mcp::anonymous_caller()
        };
    let args = json!({"server": "alpha", "tool": "read", "arguments": {}});
    let meta = &fx.state.meta_mcp;
    for (who, principal) in [
        ("live", "local-operator"),
        ("task worker", "credential:task-owner"),
    ] {
        for i in 0..CAP / 2 {
            let asked = meta
                .invoke_tool_for_test(&args, None, &caller(true, principal))
                .await;
            assert!(
                asked
                    .as_ref()
                    .is_ok_and(|v| v.get("resultType") == Some(&json!("input_required"))),
                "setup: stdio {who} call {i} was not asked: {asked:?}"
            );
        }
    }
    assert_eq!(
        held(&fx).await,
        CAP,
        "setup: the stdio process's rounds are held"
    );

    let over = meta
        .invoke_tool_for_test(&args, None, &caller(true, "local-operator"))
        .await;
    let http = meta
        .invoke_tool_for_test(&args, None, &caller(false, "digest-bob"))
        .await;
    let over_refused = over.as_ref().is_err_and(|e| e.to_rpc_code() == -32003);
    let http_asked = http
        .as_ref()
        .is_ok_and(|v| v.get("resultType") == Some(&json!("input_required")));
    assert!(
        over_refused && http_asked,
        "stdio 65th refused = {over_refused} (want true), HTTP caller asked = {http_asked} \
         (want true): {over:?}"
    );
}
