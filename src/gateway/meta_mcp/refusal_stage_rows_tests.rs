// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A refusal that ends a playbook or chain after an earlier step ran stays a
//! refusal: its own code on the wire and `refused` in the delivery record.
//! Keys are admitted per invocation, so the refusal frees no key a step that
//! ran still holds: a same-key retry replays that step instead of sending it
//! again.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Map, Value, json};

use super::playbook_dispatch_refusal::RefusesArguments;
use crate::gateway::authz::{AllowAll, ToolAuthorizer};
use crate::gateway::delivery_facts;
use crate::gateway::meta_mcp::authz_tests::{counted_backend, ctx, register_answering};
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext, STEP_NOT_PERMITTED};
use crate::protocol::RequestId;

/// Step `write` runs (no arguments, so the policy allows it); step `read`
/// carries arguments, so [`RefusesArguments`] refuses it at dispatch.
const RAN_THEN_REFUSED: &str = r"
name: ran-then-refused
description: a step that runs, then a step the policy refuses
on_error: abort
steps:
  - name: write
    server: alpha
    tool: write
    arguments: {}
  - name: read
    server: alpha
    tool: read
    arguments: {q: 1}
";

/// A meta route over counted backends `alpha` and `beta`, keyed calls
/// cached, holding [`RAN_THEN_REFUSED`].
fn meta() -> (MetaMcp, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let (registry, alpha) = counted_backend("alpha");
    let beta = register_answering(
        &registry,
        "beta",
        json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
    );
    let mut meta = MetaMcp::new(registry);
    meta.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        Duration::from_secs(300),
    );
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(crate::yaml::from_str(RAN_THEN_REFUSED).expect("the playbook parses"));
    meta.set_playbook_engine(engine);
    (meta, alpha, beta)
}

/// `tool` with `arguments`, by a caller judged by `authorizer` and keyed with
/// `key`: the answer and the delivery record's fields.
async fn call(
    meta: &MetaMcp,
    tool: &str,
    arguments: Value,
    authorizer: &(dyn ToolAuthorizer + Sync),
    key: &str,
) -> (Value, Map<String, Value>) {
    let retry = crate::protocol::mrtr::RetryFields {
        idempotency_key: Some(key.to_owned()),
        ..Default::default()
    };
    let caller = MetaMcpCallerContext {
        retry: &retry,
        ..ctx(authorizer)
    };
    let mut fields = Map::new();
    let answer = delivery_facts::scope(async {
        let response =
            Box::pin(meta.handle_tools_call(RequestId::Number(1), tool, arguments, None, caller))
                .await;
        delivery_facts::record_fields(delivery_facts::snapshot().as_ref(), false, &mut fields);
        serde_json::to_value(&response).expect("response is JSON")
    })
    .await;
    (answer, fields)
}

/// A playbook whose second step is refused after its first ran answers the
/// neutral refusal (-32003) and records `refused`; a same-key retry replays
/// the first step from its key and is refused again: the backend saw the
/// first step once.
#[tokio::test]
async fn a_same_key_playbook_retry_replays_the_step_that_ran() {
    let (meta, alpha, _) = meta();
    for attempt in 1..=2 {
        let (answer, fields) = call(
            &meta,
            "gateway_run_playbook",
            json!({"name": "ran-then-refused"}),
            &RefusesArguments,
            "ran-then-refused-key",
        )
        .await;
        assert_eq!(
            answer["error"]["message"], STEP_NOT_PERMITTED,
            "attempt {attempt}: {answer}"
        );
        assert_eq!(
            answer["error"]["code"], -32003,
            "attempt {attempt}: {answer}"
        );
        assert_eq!(
            fields.get("response_effect"),
            Some(&json!("refused")),
            "attempt {attempt}: {fields:?}"
        );
        assert_eq!(
            alpha.load(Ordering::SeqCst),
            1,
            "attempt {attempt}: the step that ran was sent again"
        );
    }
}

/// A chain whose second step is refused by the policy after its first ran
/// ends on the refusal: -32003 on the wire, `refused` recorded.
#[tokio::test]
async fn a_chain_ended_by_a_late_denial_records_refused() {
    let (meta, alpha, _) = meta();
    let chain = json!([
        {"tool": "alpha:write", "arguments": {}},
        {"tool": "alpha:read", "arguments": {"q": 1}},
    ]);
    let (answer, fields) = call(
        &meta,
        "gateway_execute",
        json!({"chain": chain}),
        &RefusesArguments,
        "late-denial-key",
    )
    .await;
    assert_eq!(
        alpha.load(Ordering::SeqCst),
        1,
        "premise: step one ran: {answer}"
    );
    assert_eq!(answer["error"]["code"], -32003, "{answer}");
    assert_eq!(
        fields.get("response_effect"),
        Some(&json!("refused")),
        "{fields:?}"
    );
}

/// A chain whose second step's server the operator has switched off ends on
/// the gateway's refusal after its first step ran, and records `refused`,
/// not `error`.
#[tokio::test]
async fn a_chain_ended_by_a_late_gateway_refusal_records_refused() {
    let (meta, alpha, beta) = meta();
    meta.kill_switch.kill("beta");
    let chain = json!([
        {"tool": "alpha:write", "arguments": {}},
        {"tool": "beta:write", "arguments": {}},
    ]);
    let (answer, fields) = call(
        &meta,
        "gateway_execute",
        json!({"chain": chain}),
        &AllowAll,
        "late-refusal-key",
    )
    .await;
    assert_eq!(
        alpha.load(Ordering::SeqCst),
        1,
        "premise: step one ran: {answer}"
    );
    assert_eq!(
        beta.load(Ordering::SeqCst),
        0,
        "premise: step two was not sent"
    );
    assert!(
        answer.get("error").is_some(),
        "the chain ended on the refusal: {answer}"
    );
    assert_eq!(
        fields.get("response_effect"),
        Some(&json!("refused")),
        "{fields:?}"
    );
}

/// Control: a refusal of a playbook's first step frees its key, so the
/// same-key retry is judged again, not answered from a held key.
#[tokio::test]
async fn a_refusal_at_the_first_step_holds_no_key() {
    let (meta, alpha, _) = meta();
    meta.kill_switch.kill("alpha");
    for attempt in 1..=2 {
        let (answer, _) = call(
            &meta,
            "gateway_run_playbook",
            json!({"name": "ran-then-refused"}),
            &AllowAll,
            "first-step-key",
        )
        .await;
        assert!(answer.get("error").is_some(), "attempt {attempt}: {answer}");
    }
    meta.kill_switch.revive("alpha");
    let (answer, _) = call(
        &meta,
        "gateway_run_playbook",
        json!({"name": "ran-then-refused"}),
        &RefusesArguments,
        "first-step-key",
    )
    .await;
    assert_eq!(
        answer["error"]["message"], STEP_NOT_PERMITTED,
        "the first step now runs and the second is refused: {answer}"
    );
    assert_eq!(
        alpha.load(Ordering::SeqCst),
        1,
        "the freed key let step one run"
    );
}

/// Both gateway refusals are raised before anything is sent, at the reviewed
/// sites the pre-send scan holds, so both read as never sent.
#[test]
fn the_gateway_refusals_read_as_never_sent() {
    let denial = crate::Error::Forbidden {
        code: -32003,
        status: 403,
        message: "refused".into(),
    };
    assert!(denial.is_pre_dispatch(), "a denial reads as may have run");
    let refusal = crate::Error::gateway_refused(-32000, "switched off by the operator");
    assert!(
        refusal.is_pre_dispatch(),
        "a gateway refusal reads as may have run"
    );
}
