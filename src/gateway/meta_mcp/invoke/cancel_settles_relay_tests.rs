// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend's question relayed to a modern client as `input_required` hands
//! the client's idempotency key to the continuation: the client's answer, sent
//! under the same key, runs the second round and completes the exchange.
//!
//! Shares the scripted backend and the gateway of `cancel_settles_tests`.

use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use super::{ALLOW_ALL, Client, KEY, Step, answering, done, gateway, interim};
use crate::gateway::meta_mcp::MetaMcpCallerContext;
use crate::protocol::mrtr::RetryFields;

/// One call to `svc:act` from a modern client that declared elicitation, under
/// the retry fields `retry`. A continuation is minted only for a caller it can
/// name, so the caller is a verified identity.
async fn modern(
    meta: &super::MetaMcp,
    client: &Client,
    retry: &RetryFields,
) -> crate::Result<Value> {
    let alice = crate::key_server::oidc::VerifiedIdentity {
        subject: "alice".to_string(),
        email: "alice@example.invalid".to_string(),
        name: None,
        groups: Vec::new(),
        issuer: "https://issuer.example.invalid".to_string(),
    };
    let declared = crate::protocol::meta::classify_request(
        Some(&json!({"_meta": {
            crate::protocol::meta::KEY_PROTOCOL_VERSION: "2026-07-28",
            crate::protocol::meta::KEY_CLIENT_CAPABILITIES: {"elicitation": {"form": {}}}
        }})),
        None,
    )
    .declared_capabilities();
    let context = MetaMcpCallerContext {
        task: None,
        signing: None,
        execution: None,
        credential_principal: None,
        record_principal: crate::gateway::record_principal::RecordPrincipal::none(),
        authentication: crate::gateway::meta_mcp::Authentication::Authenticated,
        credential_kind: crate::security::audit::CredentialKind::None,
        is_modern: true,
        protocol_revision: Some(crate::protocol::PROTOCOL_VERSION),
        authorizer: &ALLOW_ALL,
        stdio_nonce: None,
        caller_key: None,
        verified_identity: Some(&alice),
        api_key_name: None,
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        is_admin: false,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
        input_capabilities: declared,
        retry,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        era: crate::protocol::meta::Era::Modern,
        channel: client,
    };
    let args = json!({"server": "svc", "tool": "act", "arguments": {}});
    meta.invoke_tool(&args, Some("session-relay"), &context)
        .await
}

/// R23b(i), control: a two-round exchange relayed to a modern client completes
/// under one key. Round one is relayed as `input_required`; the client's
/// answer, under the same key and the continuation it was handed, is the
/// second `tools/call`, and the exchange completes with the backend's result.
#[tokio::test]
async fn a_relayed_two_round_exchange_completes_under_one_key() {
    let (meta, wire) = gateway(vec![Step::Answer(interim()), Step::Answer(done())]);
    let client = answering();
    let first_fields = RetryFields {
        idempotency_key: Some(KEY.to_owned()),
        ..RetryFields::default()
    };

    let first = modern(&meta, &client, &first_fields)
        .await
        .expect("premise: round one is answered");
    assert_eq!(
        first.get("resultType"),
        Some(&json!("input_required")),
        "premise: round one is relayed to the client as input required: {first}"
    );
    let state = first
        .get("requestState")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: round one carries a continuation: {first}"))
        .to_owned();
    assert_eq!(
        wire.calls.load(Ordering::SeqCst),
        1,
        "premise: round one sent one tools/call"
    );

    let answer_fields = RetryFields {
        idempotency_key: Some(KEY.to_owned()),
        request_state: Some(state),
        input_responses: Some(json!({"q1": {"action": "accept", "content": {"ok": true}}})),
        ..RetryFields::default()
    };
    let second = modern(&meta, &client, &answer_fields).await;

    assert_eq!(
        wire.calls.load(Ordering::SeqCst),
        2,
        "the answered round did not reach the backend under the same key: {second:?}"
    );
    let second = second.expect("the answered round completes the exchange");
    assert!(
        second.to_string().contains("done"),
        "the exchange did not complete with the backend's result: {second}"
    );
}
