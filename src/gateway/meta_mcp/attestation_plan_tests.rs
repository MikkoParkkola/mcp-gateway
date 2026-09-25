// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7570.ATTEST.1: under `enforce`, multi-step plans are refused with their
//! own message. A playbook step or a code-mode step is synthesized from a
//! definition and carries no token, so the only honest answer is a refusal
//! that says why, not a missing-token error that reads like a bad token.
//!
//! Each shape is driven through both dispatch paths: unkeyed (straight to the
//! handler) and keyed (admission checks the plan before any lookup).

use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use crate::attestation::{AttestationMode, AttestationValidator, BnautAttestationSigner};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::authz_tests::{counted_backend, ctx};
use crate::protocol::RequestId;
use crate::protocol::mrtr::RetryFields;

const PLAN_REFUSAL: &str = "multi-step plans carry no attestation";

const PLAYBOOK: &str = r"
name: one_step
description: a single step against a backend
on_error: abort
steps:
  - name: read
    server: alpha
    tool: read
";

fn meta_in(mode: AttestationMode) -> (MetaMcp, Arc<std::sync::atomic::AtomicUsize>) {
    let (registry, calls) = counted_backend("alpha");
    let validator = Arc::new(AttestationValidator::new(BnautAttestationSigner::new(
        b"plan-key".to_vec(),
        "plan",
    )));
    let meta = MetaMcp::new(registry)
        .with_code_mode(true)
        .with_attestation(validator, mode);
    let definition: crate::playbook::PlaybookDefinition =
        serde_yaml::from_str(PLAYBOOK).expect("playbook fixture must parse");
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(definition);
    meta.set_playbook_engine(engine);
    (meta, calls)
}

/// The two plan shapes, as `(tool, arguments)`.
fn plans() -> [(&'static str, Value); 2] {
    [
        ("gateway_run_playbook", json!({"name": "one_step"})),
        (
            "gateway_execute",
            json!({"tool": "alpha:read", "arguments": {}}),
        ),
    ]
}

fn assert_plan_refusal(tool: &str, code: i64, message: &str) {
    assert_eq!(code, -32002, "{tool}: {message}");
    assert!(message.contains(PLAN_REFUSAL), "{tool}: {message}");
}

#[tokio::test]
async fn playbook_refused_under_enforce_unkeyed() {
    unkeyed_refusal("gateway_run_playbook").await;
}

#[tokio::test]
async fn code_mode_refused_under_enforce_unkeyed() {
    unkeyed_refusal("gateway_execute").await;
}

async fn unkeyed_refusal(tool: &str) {
    let (meta, calls) = meta_in(AttestationMode::Enforce);
    let (_, args) = plans().into_iter().find(|(t, _)| *t == tool).unwrap();
    let response =
        Box::pin(meta.handle_tools_call(RequestId::Number(1), tool, args, None, ctx(&AllowAll)))
            .await;
    let error = response
        .error
        .expect("a plan must be refused under enforce");
    assert_plan_refusal(tool, i64::from(error.code), &error.message);
    assert_eq!(calls.load(Ordering::SeqCst), 0, "{tool}: no backend call");
}

#[tokio::test]
async fn playbook_and_code_mode_refused_under_enforce_keyed() {
    let (meta, calls) = meta_in(AttestationMode::Enforce);
    let retry = RetryFields {
        idempotency_key: Some("plan-key-1".into()),
        ..RetryFields::default()
    };
    let mut caller = ctx(&AllowAll);
    caller.retry = &retry;
    for (tool, args) in plans() {
        let error = meta
            .admit_meta_sync(&caller, tool, &args, None, &RequestId::Number(2))
            .err()
            .unwrap_or_else(|| panic!("{tool}: a keyed plan must be refused under enforce"));
        assert_plan_refusal(tool, i64::from(error.to_rpc_code()), &error.to_string());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no backend call");
}

/// Positive control: the same plans under observe run and reach the backend,
/// so the refusals above come from enforce and not from the fixture.
#[tokio::test]
async fn playbook_and_code_mode_run_under_observe() {
    let (meta, calls) = meta_in(AttestationMode::Observe);
    for (tool, args) in plans() {
        let response = Box::pin(meta.handle_tools_call(
            RequestId::Number(3),
            tool,
            args,
            None,
            ctx(&AllowAll),
        ))
        .await;
        assert!(response.error.is_none(), "{tool}: {response:?}");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2, "both plans must dispatch");
}
