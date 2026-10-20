// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8498.VISIBLE.1b: a memo read looks its entry up by the caller's own
//! strings, so it allocates no key. Before, every read built an owned
//! `(String, String)` or `(String, AccountKey)` key: two allocations per
//! read on every tools/call that consults the memo.

use super::{
    AccountKey, AccountOutcome, VISIBILITY_MEMO, Visibility, VisibilityMemo, account_outcome,
    account_slot, target_key,
};
use crate::gateway::alloc_meter::measure;

/// A memo with one visibility entry and one account outcome recorded.
fn memo(account: &AccountKey) -> VisibilityMemo {
    let memo = VisibilityMemo::default();
    memo.visibility
        .set(target_key("alpha", "read"), Visibility::Visible);
    memo.offer_pending
        .set(account_slot("alpha", account), AccountOutcome::Live);
    memo
}

#[test]
fn a_memo_read_allocates_no_key() {
    let account = AccountKey("acct-1".to_owned());
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
