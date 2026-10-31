// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct route `/mcp/{name}`: a call refused inside its backend's own
//! send, before any byte leaves, releases its idempotency key, as a call the
//! gateway refused before its backend does.

use serde_json::{Value, json};

use super::direct_continuation_tests::{call, signed_call};
use super::direct_guards_fixture::{fixture_signed_with_secrets, fixture_with_secrets};
use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;
use crate::secret_injection::{CredentialRule, CredentialType, InjectTarget};

/// A `query` rule: no route can carry it, so every send refuses it in
/// `outbound`, before the backend.
fn query_rule() -> CredentialRule {
    CredentialRule {
        name: "api".to_string(),
        credential_type: CredentialType::ApiKey,
        value: "direct-presend-secret-77a2".to_string(),
        inject_as: InjectTarget::Query,
        inject_key: "api_key".to_string(),
        tools: vec!["*".to_string()],
    }
}

/// One direct call under idempotency key `key` with `arguments`.
fn keyed(key: &str, arguments: Value) -> Value {
    json!({"arguments": arguments, "_meta": {IDEMPOTENCY_KEY_META: key}})
}

fn message(body: &Value) -> String {
    body.pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// R10: refused in its send, the call's key is released. Read through a
/// second call under the same key with other arguments: a kept key refuses
/// it as a key reused for a different request; a released one lets it reach
/// the send again, which refuses it for the rule. On this route the key is
/// held by the call's execution lease, so the release read here is the
/// lease's withdrawal.
#[tokio::test]
async fn a_direct_call_refused_in_its_send_releases_its_key() {
    let fx = fixture_with_secrets(vec![query_rule()], None, None).await;
    let (_, first) = call(
        &fx,
        "alpha",
        None,
        keyed("k-direct", json!({"cmd": "first"})),
    )
    .await;
    assert!(
        message(&first).contains("secret rule 'api'"),
        "premise: refused for the rule: {first}"
    );
    assert!(
        fx.seen.lock().expect("recorder").is_empty(),
        "premise: nothing was sent"
    );
    let (_, second) = call(
        &fx,
        "alpha",
        None,
        keyed("k-direct", json!({"cmd": "second"})),
    )
    .await;
    assert!(
        !message(&second).contains("already in use for a different request"),
        "the refused call kept its key: {second}"
    );
    assert!(
        message(&second).contains("secret rule 'api'"),
        "the second call did not reach the send: {second}"
    );
}

/// R10b: refused in its send, a signed call gives its nonce back. The tool
/// list is warmed first, as in R24: a cold schema fill is itself a request to
/// the backend, which keeps the nonce. Read through the same nonce again: a
/// kept nonce refuses it as a replay; a returned one lets it reach the send
/// again, which refuses it for the rule.
#[tokio::test]
async fn a_signed_direct_call_refused_in_its_send_gives_its_nonce_back() {
    let fx = fixture_signed_with_secrets(vec![query_rule()]).await;
    let target = fx.state.backends.get("alpha").expect("fixture backend");
    target.get_tools_shared().await.expect("warm the tool list");
    let fills = target.list_fills();
    let who = ("k-std", "alpha");
    let (_, first) = signed_call(&fx, who, "alpha-presend-n1", json!({})).await;
    assert!(
        message(&first).contains("secret rule 'api'"),
        "premise: refused for the rule: {first}"
    );
    assert!(
        fx.seen.lock().expect("recorder").is_empty(),
        "premise: nothing was sent"
    );
    assert_eq!(target.list_fills(), fills, "premise: no fill");
    let (_, again) = signed_call(&fx, who, "alpha-presend-n1", json!({})).await;
    assert!(
        !again.to_string().to_lowercase().contains("replay"),
        "the nonce was kept after a call refused in its send: {again}"
    );
    assert!(
        message(&again).contains("secret rule 'api'"),
        "the second call did not reach the send: {again}"
    );
}
