// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! SIGNING.5 at the `gateway_invoke` boundary: a raw nonce that never becomes a
//! string is refused BEFORE the nonce store, so the store's own telemetry cannot
//! see it. That is a real operational path — a client sending `null`, a number,
//! an empty string or an oversized string produces a refusal nobody can count.
//!
//! Every case captures from a RAW request value the way the adapters do and then
//! drives `MetaMcp::prepare_signing_invocation`. None emits a product metric by
//! hand, and none asserts anything about the parser in isolation: a claim about
//! the parser is not a claim about the boundary.
//!
//! Harness: `security/message_signing_nonce_metrics_support.rs`.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::super::{MetaMcp, MetaMcpCallerContext};
use super::SigningInvocationContext;
use crate::backend::BackendRegistry;
use crate::gateway::authz::{AllowAll, DenyAll, ToolAuthorizer};
use crate::security::message_signing::MessageSigner;
use crate::security::message_signing::nonce_metrics_support::{
    INVALID_REFUSAL, assert_no_occupancy, assert_no_rejections, assert_occupancy, assert_refusal,
    assert_single_rejection, observe,
};

const KEY: &str = "signing-boundary-key-sentinel-0123456789abcdef";

fn meta(signing_enabled: bool) -> MetaMcp {
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    if signing_enabled {
        meta.enable_message_signing(
            MessageSigner::new(KEY.as_bytes().to_vec(), None, "boundary-current".into()),
            Duration::from_secs(300),
            false,
        );
    }
    meta
}

/// Built exactly as `router/handlers.rs` builds one; only the authorizer varies.
fn ctx(authorizer: &(dyn ToolAuthorizer + Sync)) -> MetaMcpCallerContext<'_> {
    MetaMcpCallerContext {
        task: None,
        execution: None,
        signing: None,
        is_modern: false,
        protocol_revision: None,
        credential_principal: None,
        authorizer,
        api_key_name: Some("test-caller"),
        agent_id: None,
        grant_subject: None,
        verified_identity: None,
        is_admin: false,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
    }
}

/// A raw external `gateway_invoke` request carrying `nonce` exactly as a client
/// would send it — including the values a client should not send.
fn raw_request(tool_name: &str, nonce: Option<Value>) -> Value {
    let mut arguments = json!({ "server": "alpha", "tool": "read", "arguments": {} });
    if let Some(nonce) = nonce {
        arguments
            .as_object_mut()
            .expect("arguments object")
            .insert("nonce".into(), nonce);
    }
    json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": { "name": tool_name, "arguments": arguments }
    })
}

/// Capture from the raw value the way the adapters do, and hand back the
/// arguments that survive it. Removing the nonce is intentional — what reaches
/// `prepare_signing_invocation` is what would reach it in production.
fn capture(tool_name: &str, nonce: Option<Value>) -> (SigningInvocationContext, Value) {
    let mut request = raw_request(tool_name, nonce);
    let context = SigningInvocationContext::capture(&mut request);
    let arguments = request
        .pointer("/params/arguments")
        .expect("arguments survive capture")
        .clone();
    (context, arguments)
}

/// Drive the boundary for a raw nonce and assert the refusal it must produce.
fn assert_invalid_raw_nonce_is_counted(nonce: Value) {
    let meta = meta(true);
    let (mut context, arguments) = capture("gateway_invoke", Some(nonce));

    let (result, events) = observe(|| {
        meta.prepare_signing_invocation(&mut context, &arguments, None, &ctx(&AllowAll))
    });

    assert_refusal(result, -32602, INVALID_REFUSAL);
    assert_single_rejection(&events, "invalid");
    // The store never saw this nonce, so nothing may publish an occupancy.
    assert_no_occupancy(&events);
}

// ── The four raw shapes that become an invalid capture ───────────────────────

#[tokio::test]
async fn null_raw_nonce_is_refused_and_counted_invalid() {
    assert_invalid_raw_nonce_is_counted(Value::Null);
}

#[tokio::test]
async fn non_string_raw_nonce_is_refused_and_counted_invalid() {
    assert_invalid_raw_nonce_is_counted(json!(42));
}

#[tokio::test]
async fn empty_raw_nonce_is_refused_and_counted_invalid() {
    assert_invalid_raw_nonce_is_counted(json!(""));
}

#[tokio::test]
async fn oversized_raw_nonce_is_refused_and_counted_invalid() {
    assert_invalid_raw_nonce_is_counted(json!("x".repeat(257)));
}

// ── Controls: the paths that must count nothing ──────────────────────────────

#[tokio::test]
async fn valid_raw_nonce_is_admitted_and_counts_no_rejection() {
    // Also the fixture's own canary: if the policy controls refused this
    // well-formed invocation, the four cases above would be passing on a policy
    // refusal rather than on the nonce, and this case says so first.
    let meta = meta(true);
    let (mut context, arguments) = capture("gateway_invoke", Some(json!("boundary-valid-nonce")));

    let (result, events) = observe(|| {
        meta.prepare_signing_invocation(&mut context, &arguments, None, &ctx(&AllowAll))
    });

    // Order is the diagnosis: a failure on this line means the fixture does not
    // pass policy and the four cases above prove nothing. A failure below it
    // means policy is fine and the telemetry is what is missing.
    result.expect("a well-formed nonce must be admitted");
    assert_no_rejections(&events);
    assert_occupancy(&events, 1);
}

#[tokio::test]
async fn disabled_signing_counts_nothing_for_an_invalid_raw_nonce() {
    let meta = meta(false);
    let (mut context, arguments) = capture("gateway_invoke", Some(Value::Null));

    let (result, events) = observe(|| {
        meta.prepare_signing_invocation(&mut context, &arguments, None, &ctx(&AllowAll))
    });

    result.expect("signing disabled returns before the nonce is judged");
    assert_no_rejections(&events);
    assert_no_occupancy(&events);
}

#[tokio::test]
async fn internal_origin_counts_nothing_for_an_invalid_raw_nonce() {
    // Not a literal external `gateway_invoke`, so capture never looks at the
    // nonce and the boundary returns before judging one.
    let meta = meta(true);
    let (mut context, arguments) = capture("some_other_tool", Some(Value::Null));

    let (result, events) = observe(|| {
        meta.prepare_signing_invocation(&mut context, &arguments, None, &ctx(&AllowAll))
    });

    result.expect("an internal origin carries no signing context");
    assert_no_rejections(&events);
    assert_no_occupancy(&events);
}

#[tokio::test]
async fn repeated_delivery_inspection_is_not_counted() {
    // `delivery()` is also consulted by the finalizer. A hook placed there
    // would count one client mistake several times and would count it again on
    // a path that is not an admission decision at all.
    let (context, _arguments) = capture("gateway_invoke", Some(Value::Null));

    let ((), events) = observe(|| {
        for _ in 0..3 {
            assert!(
                context.delivery().is_err(),
                "an invalid captured nonce cannot deliver"
            );
        }
    });

    assert_no_rejections(&events);
}

#[tokio::test]
async fn policy_refusal_is_not_counted_as_a_nonce_rejection() {
    // Policy runs before the nonce is judged. A denied invocation is a policy
    // event, and counting it as a nonce rejection would make the capacity
    // alerts fire on authorization noise.
    let meta = meta(true);
    let (mut context, arguments) = capture("gateway_invoke", Some(Value::Null));

    let (result, events) =
        observe(|| meta.prepare_signing_invocation(&mut context, &arguments, None, &ctx(&DenyAll)));

    assert!(result.is_err(), "a denied invocation must be refused");
    assert_no_rejections(&events);
    assert_no_occupancy(&events);
}
