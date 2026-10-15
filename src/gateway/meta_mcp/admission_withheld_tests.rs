// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8361 A5 ruling A at keyed admission: a plan step the caller cannot see
//! is never answered by its reason, here when the key is already in flight.

use serde_json::json;

use crate::gateway::authz::{AllowAll, DenyOne, ToolAuthorizer};
use crate::gateway::meta_mcp::authz_tests::{counted_backend, ctx};
use crate::gateway::meta_mcp::{AdmissionOwner, MetaMcp, MetaMcpCallerContext};
use crate::protocol::RequestId;
use crate::protocol::mrtr::RetryFields;

/// A modern caller with an owner the admission can key on, `retry` its
/// retry fields, judged by `authorizer`.
fn owned<'a>(
    retry: &'a RetryFields,
    authorizer: &'a (dyn ToolAuthorizer + Sync),
) -> MetaMcpCallerContext<'a> {
    MetaMcpCallerContext {
        retry,
        is_modern: true,
        credential_principal: Some("verified-credential-owner"),
        ..ctx(authorizer)
    }
}

/// Two keyed `gateway_execute` calls of `[beta:other, beta:read]`: the first,
/// judged while `read` is allowed, holds the key; the second, judged by
/// `authorizer`, asks while it is in flight. The second call's answer.
fn second_while_in_flight(authorizer: &(dyn ToolAuthorizer + Sync)) -> String {
    let (registry, _calls) = counted_backend("beta");
    let meta = MetaMcp::new(registry).with_code_mode(true);
    let retry = RetryFields {
        idempotency_key: Some("in-flight".into()),
        ..RetryFields::default()
    };
    let args = json!({"chain": [
        {"tool": "beta:other", "arguments": {}},
        {"tool": "beta:read", "arguments": {}}
    ]});
    let admit = |caller: &MetaMcpCallerContext<'_>, id| {
        meta.admit_meta_sync_for_test(
            AdmissionOwner::for_test(caller.owner_principal()),
            caller,
            "gateway_execute",
            &args,
            Some("legacy:session"),
            &RequestId::Number(id),
        )
    };
    let held = admit(&owned(&retry, &AllowAll), 1);
    assert!(
        matches!(held, Ok(super::SyncAdmission::Owned(_))),
        "premise: the first, allowed call owns the key"
    );
    let second = admit(&owned(&retry, authorizer), 2)
        .err()
        .map(|error| error.to_string());
    drop(held);
    second.expect("premise: a key in flight refuses the second call")
}

/// Ruling A, addition 2: with the key in flight, a call whose last step the
/// policy now withholds gets exactly the answer a call whose last step it
/// allows gets (a missing step passes admission the same way): the key's own
/// answer, never the withheld step's reason.
#[test]
fn a_key_in_flight_answers_a_withheld_step_as_a_missing_one() {
    let withheld = second_while_in_flight(&DenyOne { tool: "read" });
    let missing = second_while_in_flight(&AllowAll);
    assert!(
        !withheld.contains("denied by test authorizer"),
        "the withheld step's reason reached the caller: {withheld}"
    );
    assert_eq!(withheld, missing, "in flight: withheld vs missing");
}

/// Ruling A (lead correction): on a REGISTERED backend, a key admitted and
/// completed while `read` was allowed, then replayed after the policy
/// withholds it, gets the step's current refusal, -32003, as SUB.4 pins it
/// for unregistered backends: a replayed key's holder held access before, so
/// "forbidden" tells it nothing new, and no retained result is served.
#[test]
fn a_replay_past_revocation_on_a_registered_backend_keeps_its_refusal() {
    let (registry, _calls) = counted_backend("beta");
    let meta = MetaMcp::new(registry).with_code_mode(true);
    let retry = RetryFields {
        idempotency_key: Some("replayed".into()),
        ..RetryFields::default()
    };
    let args = json!({"chain": [
        {"tool": "beta:other", "arguments": {}},
        {"tool": "beta:read", "arguments": {}}
    ]});
    let admit = |caller: &MetaMcpCallerContext<'_>, id| {
        meta.admit_meta_sync_for_test(
            AdmissionOwner::for_test(caller.owner_principal()),
            caller,
            "gateway_execute",
            &args,
            Some("legacy:session"),
            &RequestId::Number(id),
        )
    };
    let allowed = owned(&retry, &AllowAll);
    let Ok(super::SyncAdmission::Owned(owner)) = admit(&allowed, 1) else {
        panic!("premise: the first allowed call owns the key");
    };
    owner.mark_dispatched();
    // The first run dispatched both steps (#3872 FIX 1: only a dispatched
    // step's replay meets its refusal).
    owner.note_step(("beta", "other"));
    owner.note_step(("beta", "read"));
    owner.complete_secured(&crate::protocol::JsonRpcResponse::success(
        RequestId::Number(1),
        json!({"retained": "yes"}),
    ));
    let denied = DenyOne { tool: "read" };
    let revoked = owned(&retry, &denied);
    match admit(&revoked, 2) {
        Err(crate::Error::Forbidden { code, .. }) => assert_eq!(code, -32003),
        Err(other) => panic!("the replay past revocation lost SUB.4's answer: {other}"),
        Ok(_) => panic!("a retained result was served past the revocation"),
    }
}

/// A keyed `gateway_execute` of `[beta:other]` admitted and completed, then
/// the same key reused with `[beta:other, beta:read]` judged by `authorizer`:
/// the reuse's answer (a key mismatch: other arguments under a used key).
fn reuse_with_another_step(authorizer: &(dyn ToolAuthorizer + Sync)) -> String {
    let (registry, _calls) = counted_backend("beta");
    let meta = MetaMcp::new(registry).with_code_mode(true);
    let retry = RetryFields {
        idempotency_key: Some("reused".into()),
        ..RetryFields::default()
    };
    let admit = |caller: &MetaMcpCallerContext<'_>, args: &serde_json::Value, id| {
        meta.admit_meta_sync_for_test(
            AdmissionOwner::for_test(caller.owner_principal()),
            caller,
            "gateway_execute",
            args,
            Some("legacy:session"),
            &RequestId::Number(id),
        )
    };
    let first = json!({"chain": [{"tool": "beta:other", "arguments": {}}]});
    let Ok(super::SyncAdmission::Owned(owner)) = admit(&owned(&retry, &AllowAll), &first, 1) else {
        panic!("premise: the first call owns the key");
    };
    owner.mark_dispatched();
    owner.complete_secured(&crate::protocol::JsonRpcResponse::success(
        RequestId::Number(1),
        json!({"retained": "yes"}),
    ));
    let second = json!({"chain": [
        {"tool": "beta:other", "arguments": {}},
        {"tool": "beta:read", "arguments": {}}
    ]});
    match admit(&owned(&retry, authorizer), &second, 2) {
        Err(error) => format!("{error:?}"),
        Ok(_) => panic!("premise: a used key with other arguments is refused"),
    }
}

/// #3872 product review (oracle 1): a used key reused with other arguments is
/// a mismatch, not a replay. Its holder never held the new step, so a step
/// the caller cannot see answers as a missing one does (the key mismatch),
/// never its own refusal; otherwise any caller could probe names with keys.
#[test]
fn a_key_reused_with_a_withheld_step_answers_as_with_a_missing_one() {
    let withheld = reuse_with_another_step(&DenyOne { tool: "read" });
    let missing = reuse_with_another_step(&AllowAll);
    assert_eq!(withheld, missing, "key reuse: withheld vs missing step");
}

/// #3872 review (FIX 1, condition 2): a sync result stored before the step
/// list existed still decodes, with no list, and its replay keeps today's
/// refusal of a now-hidden step (fail closed). A listed run meets the refusal
/// only where it dispatched the step.
#[test]
fn a_stored_result_without_a_step_list_keeps_the_refusal() {
    use super::stored::{dispatched_steps, replay_meets_refusal};
    let hidden = vec![("beta".to_string(), "read".to_string())];
    let older = serde_json::to_vec(&json!({
        "response": {"jsonrpc": "2.0", "id": null, "result": {"retained": "yes"}},
        "chain": "not_eligible"
    }))
    .expect("serializes");
    assert_eq!(
        dispatched_steps(&older),
        None,
        "an older record has no list"
    );
    assert!(
        replay_meets_refusal(dispatched_steps(&older).as_deref(), &hidden),
        "an older record keeps the refusal"
    );
    let other = vec![("beta".to_string(), "other".to_string())];
    assert!(
        !replay_meets_refusal(Some(other.as_slice()), &hidden),
        "a run that never dispatched the hidden step replays its answer"
    );
    assert!(
        replay_meets_refusal(Some(hidden.as_slice()), &hidden),
        "a run that dispatched the hidden step meets its refusal"
    );
}
