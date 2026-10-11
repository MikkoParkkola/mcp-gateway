// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8356: the reason the caller verdict records when the caller's own
//! catalogue withholds a tool.

use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::slot_verdict_fixture::{
    BACKEND, BINDING, CallerSlot, Surfaced, TOOL, Warmth, per_user, valid,
};
use crate::gateway::meta_mcp::visible::{
    Visibility, Withholding, recorded_visibility, with_visibility_memo,
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
    let backend = fx.meta.backends.get(BACKEND).expect("the backend");
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
                &[],
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
