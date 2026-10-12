// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stored read's account memo slots (MIK-8392): the binding the
//! pre-pass's view read gave each account, and the live call's refusal kept
//! for an account that can never bind.

use super::{AccountKey, VISIBILITY_MEMO};

/// Keep the binding the pre-pass's view read gave `(server, account)`.
pub(crate) fn record_account_binding(server: &str, account: &AccountKey, binding: &str) {
    let _ = VISIBILITY_MEMO.try_with(|memo| {
        memo.account_binding
            .lock()
            .insert((server.to_owned(), account.clone()), binding.to_owned());
    });
}

/// The binding the pre-pass's view read gave `(server, account)`, if any.
pub(crate) fn account_binding(server: &str, account: &AccountKey) -> Option<String> {
    VISIBILITY_MEMO
        .try_with(|memo| {
            memo.account_binding
                .lock()
                .get(&(server.to_owned(), account.clone()))
                .cloned()
        })
        .ok()
        .flatten()
}

/// Keep the live call's refusal for `(server, account)` in the open request;
/// outside one it is dropped.
pub(crate) fn record_account_refusal(server: &str, account: &AccountKey, refusal: crate::Error) {
    let _ = VISIBILITY_MEMO.try_with(|memo| {
        memo.account_refusal
            .lock()
            .insert((server.to_owned(), account.clone()), refusal);
    });
}

/// Take the refusal kept for `(server, account)`, if any.
pub(crate) fn take_account_refusal(server: &str, account: &AccountKey) -> Option<crate::Error> {
    VISIBILITY_MEMO
        .try_with(|memo| {
            memo.account_refusal
                .lock()
                .remove(&(server.to_owned(), account.clone()))
        })
        .ok()
        .flatten()
}
