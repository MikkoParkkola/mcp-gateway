// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8498.VISIBLE.1b: a memo read looks its entry up by the caller's own
//! strings, so it allocates no key. Before, every read built an owned
//! `(String, String)` or `(String, DescriptorId)` key: two allocations per
//! read on every tools/call that consults the memo.

use super::{
    AccountOutcome, DescriptorId, VISIBILITY_MEMO, Visibility, VisibilityMemo, account_outcome,
    account_slot, target_key,
};
use crate::gateway::alloc_meter::measure;

/// A memo with one visibility entry and one account outcome recorded.
fn memo(account: &DescriptorId) -> VisibilityMemo {
    let memo = VisibilityMemo::default();
    memo.visibility
        .set(target_key("alpha", "read"), Visibility::Visible);
    memo.offer_pending
        .set(account_slot("alpha", account), AccountOutcome::Live);
    memo
}

#[test]
fn a_memo_read_allocates_no_key() {
    let account = DescriptorId("acct-1".to_owned());
    VISIBILITY_MEMO.sync_scope(memo(&account), || {
        let (seen, measured) =
            measure(|| VISIBILITY_MEMO.with(|memo| memo.recorded("alpha", "read")));
        assert_eq!(
            seen,
            Some(Visibility::Visible),
            "premise: the entry is read"
        );
        assert_eq!(
            measured.calls, 0,
            "a visibility read allocated: {measured:?}"
        );
        let (outcome, measured) = measure(|| account_outcome("alpha", &account));
        assert_eq!(
            outcome,
            Some(AccountOutcome::Live),
            "premise: the outcome is read"
        );
        assert_eq!(
            measured.calls, 0,
            "an account-outcome read allocated: {measured:?}"
        );
    });
}

use super::{Pair, slot, target};

// The rows below read the `Copy`-valued maps (`denial_code: i32` and
// `offer_pending: AccountOutcome`), so the value a read hands back is
// copied or moved, never cloned: no value clone sits inside the measured
// window to exclude or account for, and any allocation counted is the
// lookup's own.

/// A memo with one denial code and one account outcome recorded.
fn stocked(account: &DescriptorId) -> VisibilityMemo {
    let memo = VisibilityMemo::default();
    memo.denial_code
        .set(target_key("alpha", "read"), (-32003, None));
    memo.offer_pending
        .set(account_slot("alpha", account), AccountOutcome::Live);
    memo
}

#[test]
fn a_memo_with_allocates_no_key() {
    let account = DescriptorId("acct-1".to_owned());
    let memo = stocked(&account);
    let (code, measured) = measure(|| {
        memo.denial_code
            .with(&target("alpha", "read") as &(dyn Pair + '_), |(code, _)| {
                *code
            })
    });
    assert_eq!(code, Some(-32003), "premise: the entry is read in place");
    assert_eq!(
        measured.calls, 0,
        "a target-keyed `with` allocated: {measured:?}"
    );
    let (outcome, measured) = measure(|| {
        memo.offer_pending
            .with(&slot("alpha", &account) as &(dyn Pair + '_), |outcome| {
                *outcome
            })
    });
    assert_eq!(
        outcome,
        Some(AccountOutcome::Live),
        "premise: the outcome is read in place"
    );
    assert_eq!(
        measured.calls, 0,
        "an account-slot `with` allocated: {measured:?}"
    );
}

#[test]
fn a_memo_contains_allocates_no_key() {
    let account = DescriptorId("acct-1".to_owned());
    let memo = stocked(&account);
    let (held, measured) = measure(|| {
        memo.denial_code
            .contains(&target("alpha", "read") as &(dyn Pair + '_))
    });
    assert!(held, "premise: the entry is held");
    assert_eq!(
        measured.calls, 0,
        "a target-keyed `contains` allocated: {measured:?}"
    );
    let (held, measured) = measure(|| {
        memo.offer_pending
            .contains(&slot("alpha", &account) as &(dyn Pair + '_))
    });
    assert!(held, "premise: the outcome is held");
    assert_eq!(
        measured.calls, 0,
        "an account-slot `contains` allocated: {measured:?}"
    );
}

#[test]
fn a_memo_take_allocates_no_key() {
    let account = DescriptorId("acct-1".to_owned());
    let memo = stocked(&account);
    let (code, measured) = measure(|| {
        memo.denial_code
            .take(&target("alpha", "read") as &(dyn Pair + '_))
    });
    assert_eq!(
        code.map(|(code, _)| code),
        Some(-32003),
        "premise: the entry is taken"
    );
    assert_eq!(
        measured.calls, 0,
        "a target-keyed `take` allocated: {measured:?}"
    );
    let (outcome, measured) = measure(|| {
        memo.offer_pending
            .take(&slot("alpha", &account) as &(dyn Pair + '_))
    });
    assert_eq!(
        outcome,
        Some(AccountOutcome::Live),
        "premise: the outcome is taken"
    );
    assert_eq!(
        measured.calls, 0,
        "an account-slot `take` allocated: {measured:?}"
    );
}
