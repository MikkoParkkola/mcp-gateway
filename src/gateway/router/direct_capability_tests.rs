// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8089`: the direct route `POST /mcp/{name}` never puts a question to a
//! client that did not declare it can answer it (`MIK-7212.MRTR.9` and `9a`),
//! as `/mcp` does: the round is refused before a continuation is minted or the
//! answer cached, with the refusal naming what to declare. Every row runs on
//! `alpha` (the sanitized arm) and `alpha-pt` (the pass-through arm).

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::direct_guards_fixture::{Answer, Fx, fixture};
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;

const BACKENDS: [&str; 2] = ["alpha", "alpha-pt"];

/// `tools/call read` on `/mcp/{backend}` as `alice`. `declared` is the modern
/// request's client capabilities, or `None` for a legacy request (which
/// declares nothing). `extra` is merged into the params' `_meta`.
async fn call(fx: &Fx, backend: &str, declared: Option<Value>, extra: Value) -> Value {
    call_with(fx, backend, (declared, "read"), extra).await
}

/// [`call`] whose modern `Mcp-Name` header names `header_name`.
async fn call_named(fx: &Fx, backend: &str, declared: Option<Value>, header_name: &str) -> Value {
    call_with(fx, backend, (declared, header_name), json!({})).await
}

async fn call_with(
    fx: &Fx,
    backend: &str,
    (declared, header_name): (Option<Value>, &str),
    extra: Value,
) -> Value {
    let mut meta = extra.as_object().cloned().unwrap_or_default();
    if let Some(declared) = &declared {
        meta.insert(
            "io.modelcontextprotocol/protocolVersion".into(),
            json!("2026-07-28"),
        );
        meta.insert(
            "io.modelcontextprotocol/clientCapabilities".into(),
            declared.clone(),
        );
    }
    let mut params = json!({"name": "read", "arguments": {}});
    if !meta.is_empty() {
        params["_meta"] = Value::Object(meta);
    }
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/mcp/{backend}"))
        .header("authorization", "Bearer k-std")
        .header("content-type", "application/json");
    if declared.is_some() {
        request = request
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", "tools/call")
            .header("mcp-name", header_name);
    }
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params});
    let mut request = request
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    request.extensions_mut().insert(VerifiedIdentity {
        subject: "alice".to_string(),
        email: "alice@example.invalid".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://a.example.invalid".to_string(),
    });
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

fn form() -> Value {
    json!({"elicitation": {"form": {}}})
}

/// The exchanges the continuation store holds open.
async fn held(fx: &Fx) -> usize {
    let now = crate::protocol::continuation::now_unix_secs();
    fx.state.meta_mcp.continuation().in_flight().len(now).await
}

/// The capability refusal, carrying no question and naming `data`.
fn assert_refused(body: &Value, data: &Value, at: &str) {
    assert_eq!(body["error"]["code"], -32021, "{at}: {body}");
    assert_eq!(&body["error"]["data"], data, "{at}: {body}");
    assert!(
        !body.to_string().contains("inputRequests"),
        "{at}: a question reached the client: {body}"
    );
}

/// G1 (`MRTR.9`): a modern client that declared no capability is not asked an
/// elicitation, and no continuation is minted for it. Mutant: the gate removed.
#[tokio::test]
async fn g1_an_undeclared_elicitation_is_refused_and_nothing_is_minted() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let body = call(&fx, backend, Some(json!({})), json!({})).await;
        let data = json!({"requiredCapabilities": ["elicitation"]});
        assert_refused(&body, &data, backend);
        assert_eq!(held(&fx).await, 0, "{backend}: a continuation was minted");
    }
}

/// G2 (`MRTR.9a`): a client that declared elicitation in `url` mode only is
/// not asked a form.
#[tokio::test]
async fn g2_an_undeclared_elicitation_mode_is_refused() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let declared = json!({"elicitation": {"url": {}}});
        let body = call(&fx, backend, Some(declared), json!({})).await;
        let data = json!({"unsupportedElicitationMode": "form"});
        assert_refused(&body, &data, backend);
    }
}

/// G3: a client that declared the form is asked, sealed (MIK-8078).
#[tokio::test]
async fn g3_a_declared_elicitation_is_asked() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let body = call(&fx, backend, Some(form()), json!({})).await;
        assert!(body.get("error").is_none(), "{backend}: {body}");
        assert!(
            body.to_string().contains("inputRequests"),
            "{backend}: {body}"
        );
        assert_eq!(held(&fx).await, 1, "{backend}");
    }
}

/// G4: a legacy request declares nothing, so it is refused like G1.
#[tokio::test]
async fn g4_a_legacy_request_is_refused() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let body = call(&fx, backend, None, json!({})).await;
        let data = json!({"requiredCapabilities": ["elicitation"]});
        assert_refused(&body, &data, backend);
    }
}

/// G5: the refusal releases the idempotency key: the backend asked and did
/// not act, so the same call under the same key reaches it again.
#[tokio::test]
async fn g5_a_refused_round_releases_the_key() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let key = json!({ IDEMPOTENCY_KEY_META: format!("k-8089-{backend}") });
        let _ = call(&fx, backend, Some(json!({})), key.clone()).await;
        let _ = call(&fx, backend, Some(json!({})), key).await;
        let calls = fx.calls.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(calls, 2, "{backend}: the key was held");
    }
}

/// G6: every question in the round is checked: an elicitation the client
/// declared does not carry a sampling it did not.
#[tokio::test]
async fn g6_a_mixed_round_is_refused_for_its_undeclared_part() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskMixed, |_| {}).await;
        let body = call(&fx, backend, Some(form()), json!({})).await;
        let data = json!({"requiredCapabilities": ["sampling"]});
        assert_refused(&body, &data, backend);
    }
}

/// G7: a round `InputRequired::from_result` declines (a non-string state) but
/// whose questions are readable is still checked, so the client is not shown
/// an undeclared question through the malformed path.
#[tokio::test]
async fn g7_a_malformed_round_with_undeclared_questions_is_refused() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskBadState, |_| {}).await;
        let body = call(&fx, backend, Some(json!({})), json!({})).await;
        let data = json!({"requiredCapabilities": ["elicitation"]});
        assert_refused(&body, &data, backend);
    }
}

/// G8: a modern request `/mcp` would refuse is relayed as legacy, so what it
/// declared does not count: refused like G4. Here its `Mcp-Name` header names
/// another tool than its body.
#[tokio::test]
async fn g8_a_declaration_on_a_request_relayed_as_legacy_does_not_count() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let body = call_named(&fx, backend, Some(form()), "other").await;
        let data = json!({"requiredCapabilities": ["elicitation"]});
        assert_refused(&body, &data, backend);
    }
}
