// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8356: the reason the caller verdict records when the caller's own
//! catalogue withholds a tool.

use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::slot_verdict_fixture::{
    BACKEND, BINDING, CallerSlot, Surfaced, TOOL, Warmth, per_user, valid,
};
use crate::gateway::meta_mcp::visible::{
    Visibility, Withholding, memo::recorded_visibility, memo::with_visibility_memo,
};

/// M1: a tool blocked for its description is recorded as a descriptor
/// withholding, not as an invalid schema. The block lands after step 0 (the
/// caller's own fill can block a name), so the slot judgement is what
/// records it. Both answer -32601; the reason is what the log carries. RED
/// before the fix: every withheld slot entry is recorded as `Schema`.
#[tokio::test]
async fn m1_a_descriptor_block_in_the_callers_slot_is_recorded_as_descriptor() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Warm,
        crate::config::InputSchemaEnforcement::Closed,
        Surfaced::Yes,
    );
    let backend = fx
        .meta
        .backends
        .for_test()
        .get(BACKEND)
        .expect("the backend");
    backend.block_tool_for_test(TOOL);
    let alpha = crate::gateway::meta_mcp::catalogue_per_caller_tests::identity("alpha");
    let caller = crate::gateway::meta_mcp::identified_caller(&alpha);
    let recorded = with_visibility_memo(async {
        let _ = fx
            .meta
            .judge_caller_slot(
                (BACKEND, TOOL),
                &backend,
                Some(BINDING),
                crate::transport::LentCredential::default(),
                MetaMcp::proof_of(&caller),
            )
            .await;
        recorded_visibility(BACKEND, TOOL)
    })
    .await;
    assert_eq!(
        recorded,
        Some(Visibility::Withheld(Withholding::Descriptor)),
        "M1: a descriptor block was recorded as {recorded:?}"
    );
}

/// A memo recording [`TOOL`] on [`BACKEND`] as withheld, and alpha's caller
/// context carrying a signing context that already prepared that target:
/// what a signed stdio call looks like after its route stage. Signing ran the
/// invocation policy before the route stage recorded the verdict
/// (`stdio_dispatch.rs`: signing prepare precedes the route stage), so the
/// layers that skip the policy for a prepared target are the ones under test.
async fn with_prepared_withheld<R>(
    fx: &crate::gateway::meta_mcp::slot_verdict_fixture::PerUser,
    run: impl AsyncFnOnce(&crate::gateway::meta_mcp::MetaMcpCallerContext<'_>) -> R,
) -> R {
    let alpha = crate::gateway::meta_mcp::catalogue_per_caller_tests::identity("alpha");
    let signing = crate::gateway::meta_mcp::signing::SigningInvocationContext::prepared_for_test(
        BACKEND, TOOL,
    );
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        signing: Some(&signing),
        ..crate::gateway::meta_mcp::identified_caller(&alpha)
    };
    let _ = &fx.meta;
    with_visibility_memo(async {
        crate::gateway::meta_mcp::visible::memo::record_visibility(
            BACKEND,
            TOOL,
            Visibility::Withheld(Withholding::Schema),
        );
        run(&caller).await
    })
    .await
}

fn invoke_args() -> serde_json::Value {
    serde_json::json!({"server": BACKEND, "tool": TOOL, "arguments": {"q": "x"}})
}

fn is_absent<T>(answer: &crate::Result<T>) -> bool {
    matches!(answer, Err(e) if e.to_string()
        == crate::gateway::meta_mcp::visible::absent::absent_name(TOOL).to_string())
}

/// R1-signed, idempotent replay half: a signed call whose target signing
/// already prepared skips the invocation policy at dispatch
/// (`check_or_stamp`). A name the caller verdict withheld still answers as
/// absent there, ahead of the idempotent replay that follows it. RED before
/// the fix: the prepared branch only stamps, so the replay can serve a stored
/// result for a withheld name.
#[tokio::test]
async fn r1_signed_dispatch_of_a_withheld_name_answers_absent() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Warm,
        crate::config::InputSchemaEnforcement::Closed,
        Surfaced::No,
    );
    let answer = with_prepared_withheld(&fx, async |caller| {
        fx.meta
            .check_or_stamp(&invoke_args(), None, caller, (BACKEND, TOOL))
    })
    .await;
    assert!(
        is_absent(&answer),
        "R1-signed: a prepared dispatch of a withheld name passed: {answer:?}"
    );
}

/// R1-signed, retained-result half: execution admission skips the target's
/// invocation policy for a prepared signed call, then may serve a retained
/// result. A name the caller verdict withheld answers as absent first. RED
/// before the fix: admission admits it.
#[tokio::test]
async fn r1_signed_admission_of_a_withheld_name_answers_absent() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Warm,
        crate::config::InputSchemaEnforcement::Closed,
        Surfaced::No,
    );
    let answer = with_prepared_withheld(&fx, async |caller| {
        fx.meta
            .admit_meta_sync_for_test(
                crate::gateway::meta_mcp::AdmissionOwner::for_test(caller.owner_principal()),
                caller,
                "gateway_invoke",
                &invoke_args(),
                None,
                &crate::protocol::RequestId::Number(1),
            )
            .map(|_| ())
    })
    .await;
    assert!(
        is_absent(&answer),
        "R1-signed: admission of a withheld name passed: {answer:?}"
    );
}

/// M2 (the memo invariant): `caller_verdict` answers `Absent` exactly when it
/// leaves `Withheld` in the request's memo, on every branch a row can reach
/// in-process (the caller's slot offers, withholds or lacks the tool; no
/// principal on a required backend). The call path relies on it twice: the
/// dispatch branches on the verdict, and `refuse_withheld` reads the memo as
/// a backstop. If the two ever disagree, this fails first.
#[tokio::test]
async fn m2_absent_is_returned_exactly_when_the_memo_records_withheld() {
    use crate::gateway::meta_mcp::invoke::{CallerVerdict, TargetNaming};
    for slot in [CallerSlot::Valid, CallerSlot::Invalid, CallerSlot::Lacks] {
        let fx = per_user(
            slot,
            &valid(),
            Warmth::Warm,
            crate::config::InputSchemaEnforcement::Closed,
            Surfaced::Yes,
        );
        let alpha = crate::gateway::meta_mcp::catalogue_per_caller_tests::identity("alpha");
        let caller = crate::gateway::meta_mcp::identified_caller(&alpha);
        let (verdict, recorded) = with_visibility_memo(async {
            let verdict = fx
                .meta
                .caller_verdict(
                    (BACKEND, TOOL),
                    &caller,
                    None,
                    TargetNaming::SurfacedName,
                    None,
                )
                .await
                .expect("the verdict resolves")
                .0;
            (verdict, recorded_visibility(BACKEND, TOOL))
        })
        .await;
        assert_eq!(
            matches!(verdict, CallerVerdict::Absent),
            matches!(recorded, Some(Visibility::Withheld(_))),
            "M2 {slot:?}: verdict {verdict:?} vs memo {recorded:?}"
        );
        assert_eq!(
            matches!(verdict, CallerVerdict::Absent),
            !matches!(slot, CallerSlot::Valid),
            "M2 premise {slot:?}: {verdict:?}"
        );
    }
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Warm,
        crate::config::InputSchemaEnforcement::Closed,
        Surfaced::Yes,
    );
    let anonymous = crate::gateway::meta_mcp::anonymous_caller();
    let (verdict, recorded) = with_visibility_memo(async {
        let verdict = fx
            .meta
            .caller_verdict(
                (BACKEND, TOOL),
                &anonymous,
                None,
                TargetNaming::SurfacedName,
                None,
            )
            .await
            .expect("the verdict resolves")
            .0;
        (verdict, recorded_visibility(BACKEND, TOOL))
    })
    .await;
    assert!(
        matches!(verdict, CallerVerdict::Absent)
            && matches!(recorded, Some(Visibility::Withheld(_))),
        "M2 no principal: verdict {verdict:?} vs memo {recorded:?}"
    );
}
