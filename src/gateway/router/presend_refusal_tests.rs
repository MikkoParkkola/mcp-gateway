// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct route `/mcp/{name}`: a call refused inside its backend's own
//! send, before any byte leaves, releases its idempotency key, as a call the
//! gateway refused before its backend does.

use serde_json::{Value, json};

use super::direct_continuation_tests::call;
use super::direct_guards_fixture::fixture_with_secrets;
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
/// the send again, which refuses it for the rule.
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
