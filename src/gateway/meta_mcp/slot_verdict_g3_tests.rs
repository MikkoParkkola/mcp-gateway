// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8356 test plan r3 (final), group 3, meta-layer rows that compile on the
//! parent of the caller-verdict commits: F3 (red) and I6, I7 (the index).
//! Every test name starts with `g3_`.

use serde_json::{Value, json};

use super::catalogue_per_caller_tests::identity;
use super::identified_caller;
use super::slot_verdict_fixture::{
    BACKEND, BINDING, CallerSlot, Surfaced, TOOL, Warmth, call_as_alpha, indexed_binding_for,
    invalid, per_user, valid, warm_by_listing,
};
use crate::backend::PoolKey;
use crate::config::InputSchemaEnforcement;

const CLOSED: InputSchemaEnforcement = InputSchemaEnforcement::Closed;

/// A one-step `gateway_execute` chain naming [`TOOL`] on `BACKEND`, as alpha.
async fn step_as_alpha(meta: &super::MetaMcp) -> Value {
    let step = format!("{BACKEND}:{TOOL}");
    call_as_alpha(
        meta,
        "gateway_execute",
        json!({"chain": [{"tool": step, "arguments": {"q": "x"}}]}),
    )
    .await
}

/// F3 (the step flip guard): a chain step is judged by the caller's slot, not
/// the shared one, in both directions. Shared Invalid with caller Valid
/// dispatches; shared Valid with caller Invalid answers -32601 and does not.
/// Red on the parent: the shared Invalid withholds the first step.
#[tokio::test]
async fn g3_f3_step_flip_guard() {
    let fx = per_user(
        CallerSlot::Valid,
        &invalid(),
        Warmth::Warm,
        CLOSED,
        Surfaced::No,
    );
    let answer = step_as_alpha(&fx.meta).await;
    assert_eq!(
        fx.caller.calls() + fx.shared.calls(),
        1,
        "F3: a step valid in the caller's slot (invalid in the shared one) did not dispatch: {answer}"
    );

    let fx = per_user(
        CallerSlot::Invalid,
        &valid(),
        Warmth::Warm,
        CLOSED,
        Surfaced::No,
    );
    let answer = step_as_alpha(&fx.meta).await;
    assert_eq!(
        fx.caller.calls() + fx.shared.calls(),
        0,
        "F3: a step invalid in the caller's slot (valid in the shared one) dispatched: {answer}"
    );
    assert_eq!(
        answer.pointer("/error/code"),
        Some(&json!(-32601)),
        "F3: the reverse step is not answered -32601: {answer}"
    );
}

/// The slot a subject's binding names on [`BACKEND`].
fn slot_of(subject: &str) -> PoolKey {
    PoolKey::PerUser {
        binding: format!("{subject}@ledger"),
    }
}

/// alpha lists as `subject` (a fill of that subject's own slot, and its index
/// entry), returning whether the listing answered.
async fn list_as(meta: &super::MetaMcp, subject: &str) -> bool {
    let who = identity(subject);
    meta.list_tools(&json!({"server": BACKEND}), None, &identified_caller(&who))
        .await
        .is_ok()
}

/// I6 (guard): the index is bounded by the pool's admission. 64 principals are
/// admitted and indexed; the 65th is refused a slot and gets no entry.
#[tokio::test]
async fn g3_i6_index_bounded_by_admission() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    let backend = fx.meta.backends.get(BACKEND).expect("the backend");
    // alpha already holds one slot (the fixture opened it); 63 more fill the pool.
    let others: Vec<String> = (1..64).map(|i| format!("p{i}")).collect();
    for subject in &others {
        super::slot_verdict_fixture::add_caller(&fx.meta, subject, &valid());
    }
    warm_by_listing(&fx.meta).await;
    for subject in &others {
        assert!(
            list_as(&fx.meta, subject).await,
            "premise: {subject} listing"
        );
    }
    assert_eq!(
        backend.populated_per_user_bindings_for_test().len(),
        64,
        "premise: 64 principals are admitted and filled"
    );
    assert_eq!(
        backend.indexed_bindings_for_test().len(),
        64,
        "premise: 64 principals are indexed"
    );

    let refused = list_as(&fx.meta, "p64").await;
    assert!(
        !backend.pool_has_slot_for_test(&slot_of("p64")),
        "I6: the 65th principal was admitted a slot (listing answered: {refused})"
    );
    assert_eq!(
        indexed_binding_for(&fx.meta, "p64"),
        None,
        "I6: the 65th principal got an index entry"
    );
    assert!(
        backend.indexed_bindings_for_test().len() <= 64,
        "I6: the index outgrew the pool: {:?}",
        backend.indexed_bindings_for_test()
    );
}

/// I7 (guard): reading the index is free of side effects. `caller_slot_binding_for` on
/// a principal with no slot opens no pool entry, mints nothing, fills nothing.
#[tokio::test]
async fn g3_i7_index_read_has_no_side_effects() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    let backend = fx.meta.backends.get(BACKEND).expect("the backend");
    let (mints, lists) = (fx.mints(), fx.caller.lists() + fx.shared.lists());
    let populated = backend.populated_per_user_bindings_for_test();
    let slots = backend.pool_len_for_test();
    assert!(
        !backend.pool_has_slot_for_test(&slot_of("beta")),
        "premise: beta already holds a slot"
    );

    assert_eq!(indexed_binding_for(&fx.meta, "beta"), None, "a cold key");
    assert_eq!(
        indexed_binding_for(&fx.meta, "alpha"),
        None,
        "alpha, unfilled"
    );

    assert!(
        !backend.pool_has_slot_for_test(&slot_of("beta")),
        "I7: the read opened a slot for a cold key"
    );
    assert_eq!(fx.mints(), mints, "I7: the read minted a credential");
    assert_eq!(
        fx.caller.lists() + fx.shared.lists(),
        lists,
        "I7: the read filled a slot"
    );
    assert_eq!(
        backend.populated_per_user_bindings_for_test(),
        populated,
        "I7: the read populated a slot"
    );
    assert_eq!(
        backend.pool_len_for_test(),
        slots,
        "I7: the read opened a pool entry under some key"
    );
    assert!(
        backend.pool_has_slot_for_test(&PoolKey::PerUser {
            binding: BINDING.to_string()
        }),
        "premise: alpha's fixture slot is still there"
    );
}
