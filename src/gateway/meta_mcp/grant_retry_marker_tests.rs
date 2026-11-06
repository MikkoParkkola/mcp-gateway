// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A withheld surfaced call that carries a continuation this gateway minted
//! routes to the backend that opened the exchange, as a retry. Its withheld
//! decision says the call has an invocation record only when that retry's own
//! dispatch recorded one.

use std::sync::Arc;

use serde_json::json;

use super::grant_audit_fixture::{CAPS, Endpoint, PERSONAL, invocations, wait_for_decisions};
use super::grant_decision_audit_tests::{api_key, context, gateway};
use crate::protocol::RequestId;
use crate::protocol::continuation::{Payload, QuotaKey, now_unix_secs};
use crate::protocol::mrtr::RetryFields;
use crate::security::audit::AuditFailurePolicy;

/// A live continuation for the personal capability's backend, minted by
/// `meta`'s own keyring.
async fn live_retry(meta: &super::MetaMcp) -> RetryFields {
    let state = meta.continuation();
    let now = now_unix_secs();
    let hold_key = state
        .in_flight()
        .hold(CAPS, &QuotaKey::for_test("caller"), now + 300, now)
        .await
        .expect("the in-flight table has room for one exchange");
    let payload = Payload::mint(
        CAPS.into(),
        Some("backend-state".into()),
        "caller".into(),
        "digest".into(),
        "replica-a".into(),
        hold_key,
        now,
    );
    RetryFields {
        request_state: Some(state.keyring().mint(&payload).expect("mint")),
        ..RetryFields::default()
    }
}

/// The decision a withheld direct-name call writes, with or without a
/// continuation, and whether the invocation append is made to fail.
async fn withheld_call(continuation: bool, fail_invocation: bool) -> (serde_json::Value, usize) {
    let (endpoint, dir) = (
        Endpoint::start(false).await,
        Arc::new(tempfile::tempdir().unwrap()),
    );
    let meta = gateway(&endpoint, vec![], Some(&dir), AuditFailurePolicy::BestEffort)
        .with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
            server: CAPS.to_string(),
            tool: PERSONAL.to_string(),
        }]);
    let retry = if continuation {
        live_retry(&meta).await
    } else {
        RetryFields::default()
    };
    if fail_invocation {
        let log = meta.transparency_logger.as_ref().expect("the gateway logs");
        log.fail_next_append_of_kind_for_test("meta");
    }
    let who = api_key("alice");
    let mut caller = context(&who);
    caller.retry = &retry;
    let _ = meta
        .handle_tools_call(RequestId::Number(1), PERSONAL, json!({}), Some("d12"), caller)
        .await;
    let held = wait_for_decisions(&dir, 1).await;
    assert_eq!(held.len(), 1, "{held:#?}");
    (held[0].clone(), invocations(&dir).len())
}

#[tokio::test]
async fn a_retry_that_recorded_its_invocation_makes_the_withheld_decision_recorded() {
    let (decision, recorded) = withheld_call(true, false).await;

    assert_eq!(recorded, 1, "the retry's own invocation record: {decision}");
    assert_eq!(decision["invocation_recorded"], json!(true), "{decision}");
}

#[tokio::test]
async fn a_retry_whose_invocation_append_failed_leaves_the_decision_unrecorded() {
    let (decision, recorded) = withheld_call(true, true).await;

    assert_eq!(recorded, 0, "{decision}");
    assert_eq!(decision["invocation_recorded"], json!(false), "{decision}");
}

#[tokio::test]
async fn a_withheld_call_without_a_continuation_is_unrecorded() {
    let (decision, recorded) = withheld_call(false, false).await;

    assert_eq!(recorded, 0, "{decision}");
    assert_eq!(decision["invocation_recorded"], json!(false), "{decision}");
}

/// One slot holds a granted call whose invocation record lands and a withheld
/// call whose continuation is refused, so its retry dispatches nothing. The
/// first call's trace id must not mark the second's decision.
#[tokio::test]
async fn another_calls_invocation_in_the_slot_never_marks_a_retry_note() {
    use super::grant_audit_fixture::{decisions, grant};
    let (endpoint, dir) = (
        Endpoint::start(false).await,
        Arc::new(tempfile::tempdir().unwrap()),
    );
    let alice = ("api_key", "alice");
    let meta = gateway(
        &endpoint,
        vec![grant("g1", alice, alice)],
        Some(&dir),
        AuditFailurePolicy::BestEffort,
    )
    .with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
        server: CAPS.to_string(),
        tool: PERSONAL.to_string(),
    }]);
    let (owner, other) = (api_key("alice"), api_key("bob"));
    let refused_retry = RetryFields {
        request_state: Some("not-a-continuation".to_string()),
        ..RetryFields::default()
    };

    let log = meta.transparency_logger.as_ref();
    let (_, written, _) = super::grant_audit::with_grant_slot(log, async {
        let invoke = json!({"server": CAPS, "tool": PERSONAL, "arguments": {}});
        let granted = super::grant_decision_audit_tests::call(&meta, &owner, "gateway_invoke", invoke);
        let _ = granted.await;
        let mut caller = context(&other);
        caller.retry = &refused_retry;
        let _ = meta
            .handle_tools_call(RequestId::Number(2), PERSONAL, json!({}), Some("d17"), caller)
            .await;
    })
    .await;

    written.expect("the slot's records are written");
    let held = wait_for_decisions(&dir, 2).await;
    assert_eq!(invocations(&dir).len(), 1, "only the granted call recorded");
    let denied = held.iter().find(|d| d["outcome"] == json!("denied"));
    let denied = denied.unwrap_or_else(|| panic!("no denied decision: {:#?}", decisions(&dir)));
    assert_eq!(denied["invocation_recorded"], json!(false), "{denied}");
}
