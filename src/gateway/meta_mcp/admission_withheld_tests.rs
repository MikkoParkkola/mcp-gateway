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

/// Two keyed `gateway_execute` calls of `[beta:read, beta:other]`, the first
/// holding the key while the second asks: the second call's answer.
fn second_while_in_flight(authorizer: &(dyn ToolAuthorizer + Sync)) -> String {
    let (registry, _calls) = counted_backend("beta");
    let meta = MetaMcp::new(registry).with_code_mode(true);
    let retry = RetryFields {
        idempotency_key: Some("in-flight".into()),
        ..RetryFields::default()
    };
    let caller = owned(&retry, authorizer);
    let args = json!({"chain": [
        {"tool": "beta:other", "arguments": {}},
        {"tool": "beta:read", "arguments": {}}
    ]});
    let admit = |id| {
        meta.admit_meta_sync_for_test(
            AdmissionOwner::for_test(caller.owner_principal()),
            &caller,
            "gateway_execute",
            &args,
            Some("legacy:session"),
            &RequestId::Number(id),
        )
    };
    let held = admit(1);
    assert!(
        matches!(held, Ok(super::SyncAdmission::Owned(_))),
        "premise: the first call owns the key"
    );
    let second = admit(2).err().map(|error| error.to_string());
    drop(held);
    second.expect("premise: a key in flight refuses the second call")
}

/// Ruling A, addition 2: with the key in flight, a plan whose last step the
/// policy withholds gets exactly the answer the plan whose last step it
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
