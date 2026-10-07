// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8078`: the direct route `POST /mcp/{name}` seals a backend's
//! `requestState` the way the meta route does (`MIK-7212.MRTR.2a`). The client
//! sees a gateway continuation bound to it and to the call; only a retry
//! presenting that continuation, once, reaches the backend with the backend's
//! own state. Every row runs on `alpha` (the sanitized arm) and `alpha-pt` (the
//! pass-through arm).

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::direct_guards_fixture::{Answer, Fx, fixture};
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;

const BACKENDS: [&str; 2] = ["alpha", "alpha-pt"];
/// The state the fixture backend issues with its question.
const BACKEND_STATE: &str = "backend-state-1";

fn identity(subject: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: subject.to_string(),
        email: format!("{subject}@example.invalid"),
        name: None,
        groups: vec![],
        issuer: "https://a.example.invalid".to_string(),
    }
}

/// `tools/call read` on `/mcp/{backend}` as key `k-std`, carrying `subject`'s
/// verified identity when one is given, with `extra` merged into the params.
async fn call(fx: &Fx, backend: &str, subject: Option<&str>, extra: Value) -> (StatusCode, Value) {
    let mut params = json!({"name": "read", "arguments": {}});
    if let (Some(params), Some(extra)) = (params.as_object_mut(), extra.as_object()) {
        params.extend(extra.clone());
    }
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/mcp/{backend}"))
        .header("authorization", "Bearer k-std")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
                .to_string(),
        ))
        .unwrap();
    if let Some(subject) = subject {
        request.extensions_mut().insert(identity(subject));
    }
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

fn code(body: &Value) -> Option<i64> {
    body.get("error")
        .and_then(|e| e.get("code"))
        .and_then(Value::as_i64)
}

fn answers() -> Value {
    json!({"k1": {"action": "accept", "content": {"account": "work"}}})
}

/// The continuation the interim answer carries.
fn state_of(body: &Value) -> String {
    body["result"]["requestState"]
        .as_str()
        .unwrap_or_else(|| panic!("an interim answer with a state: {body}"))
        .to_owned()
}

fn dispatched(fx: &Fx) -> usize {
    fx.calls.load(std::sync::atomic::Ordering::SeqCst)
}

/// R1 (`MRTR.2a`): the backend's own state never reaches the client.
/// Mutant: the seal removed.
#[tokio::test]
async fn r1_the_client_sees_a_sealed_state_never_the_backends() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let (_, body) = call(&fx, backend, Some("alice"), json!({})).await;
        assert_eq!(
            body["result"]["resultType"], "input_required",
            "{backend}: {body}"
        );
        assert_ne!(state_of(&body), BACKEND_STATE, "{backend}");
        assert!(
            !body.to_string().contains(BACKEND_STATE),
            "{backend}: the backend's state leaked: {body}"
        );
    }
}

/// R2: the issued continuation, presented once by its caller, reaches the
/// backend as the backend's own state, with the answers beside it.
#[tokio::test]
async fn r2_the_issued_state_resumes_with_the_backends_own_state() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let (_, asked) = call(&fx, backend, Some("alice"), json!({})).await;
        let retry = json!({"requestState": state_of(&asked), "inputResponses": answers()});
        let (_, done) = call(&fx, backend, Some("alice"), retry).await;
        assert!(done.get("error").is_none(), "{backend}: {done}");
        assert_eq!(dispatched(&fx), 2, "{backend}");
        let seen = fx.seen.lock().unwrap().last().cloned().unwrap();
        assert_eq!(seen["requestState"], BACKEND_STATE, "{backend}: {seen}");
        assert_eq!(seen["inputResponses"], answers(), "{backend}: {seen}");
    }
}

/// R3: a state the gateway did not issue (the backend's literal, or the
/// envelope altered) is refused before the backend. Mutant: the redeem removed.
#[tokio::test]
async fn r3_a_state_the_gateway_did_not_issue_is_refused() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let (_, asked) = call(&fx, backend, Some("alice"), json!({})).await;
        let mut altered = state_of(&asked);
        let last = altered.pop().unwrap();
        altered.push(if last == 'A' { 'B' } else { 'A' });
        for forged in [BACKEND_STATE.to_owned(), altered] {
            let retry = json!({"requestState": forged, "inputResponses": answers()});
            let (_, body) = call(&fx, backend, Some("alice"), retry).await;
            assert_eq!(code(&body), Some(-32602), "{backend} {forged}: {body}");
        }
        assert_eq!(dispatched(&fx), 1, "{backend}: a forged state dispatched");
    }
}

/// R4: another caller cannot redeem a continuation issued to alice.
#[tokio::test]
async fn r4_another_caller_cannot_redeem_it() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let (_, asked) = call(&fx, backend, Some("alice"), json!({})).await;
        let retry = json!({"requestState": state_of(&asked), "inputResponses": answers()});
        let (_, body) = call(&fx, backend, Some("mallory"), retry).await;
        assert_eq!(code(&body), Some(-32602), "{backend}: {body}");
        assert_eq!(dispatched(&fx), 1, "{backend}: mallory's retry dispatched");
    }
}

/// R5: a continuation is redeemed once.
#[tokio::test]
async fn r5_a_continuation_is_redeemed_once() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let (_, asked) = call(&fx, backend, Some("alice"), json!({})).await;
        let retry = json!({"requestState": state_of(&asked), "inputResponses": answers()});
        let (_, first) = call(&fx, backend, Some("alice"), retry.clone()).await;
        assert!(first.get("error").is_none(), "{backend}: {first}");
        let (_, again) = call(&fx, backend, Some("alice"), retry).await;
        assert_eq!(code(&again), Some(-32602), "{backend}: {again}");
        assert_eq!(dispatched(&fx), 2, "{backend}: the replay dispatched");
    }
}

/// R6: a caller no continuation can be bound to is refused, and is not handed
/// the backend's state instead.
#[tokio::test]
async fn r6_an_unbindable_caller_is_refused_not_handed_the_state() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let (_, body) = call(&fx, backend, None, json!({})).await;
        assert_eq!(code(&body), Some(-32003), "{backend}: {body}");
        assert!(
            !body.to_string().contains(BACKEND_STATE),
            "{backend}: {body}"
        );
    }
}

/// R7: an interim answer is not settled under the idempotency key, as on the
/// meta route: the backend did not act, it stopped to ask. Re-sending the
/// opening call under the same key reaches the backend again rather than
/// replaying the stored question. Mutant: the interim answer settled.
#[tokio::test]
async fn r7_an_interim_answer_does_not_settle_the_key() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let opening = json!({"_meta": { IDEMPOTENCY_KEY_META: format!("k-8078-{backend}") }});
        let (_, asked) = call(&fx, backend, Some("alice"), opening.clone()).await;
        assert_eq!(
            asked["result"]["resultType"], "input_required",
            "{backend}: {asked}"
        );
        let (_, again) = call(&fx, backend, Some("alice"), opening).await;
        assert_eq!(
            dispatched(&fx),
            2,
            "{backend}: answered from the cache: {again}"
        );
        assert!(
            !again.to_string().contains(BACKEND_STATE),
            "{backend}: {again}"
        );
    }
}

/// R8: answers with no continuation are refused, as on the meta route: every
/// interim answer now carries one, so an honest retry always presents it.
#[tokio::test]
async fn r8_answers_without_a_continuation_are_refused() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let _ = call(&fx, backend, Some("alice"), json!({})).await;
        let (_, body) = call(
            &fx,
            backend,
            Some("alice"),
            json!({"inputResponses": answers()}),
        )
        .await;
        assert_eq!(code(&body), Some(-32602), "{backend}: {body}");
        assert_eq!(
            dispatched(&fx),
            1,
            "{backend}: answers without a state dispatched"
        );
    }
}
