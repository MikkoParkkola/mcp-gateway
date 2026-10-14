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

/// Keep this request's transient busy custody for `(server, tool)`, with
/// the busy reason; outside a request nothing is kept.
pub(crate) fn record_account_transient(server: &str, tool: &str, reason: String) {
    let _ = VISIBILITY_MEMO.try_with(|memo| {
        memo.account_transient
            .lock()
            .insert((server.to_owned(), tool.to_owned()), reason);
    });
}

/// The transient kept for `(server, tool)`, without consuming it.
pub(crate) fn account_transient(server: &str, tool: &str) -> Option<String> {
    VISIBILITY_MEMO
        .try_with(|memo| {
            memo.account_transient
                .lock()
                .get(&(server.to_owned(), tool.to_owned()))
                .cloned()
        })
        .ok()
        .flatten()
}

/// Take any one transient this request holds, consuming it: the task
/// intake trigger, which answers for the whole call.
pub(crate) fn take_any_account_transient() -> Option<String> {
    VISIBILITY_MEMO
        .try_with(|memo| {
            let mut held = memo.account_transient.lock();
            let first = held.keys().next().cloned()?;
            held.remove(&first)
        })
        .ok()
        .flatten()
}

/// Take the transient kept for `(server, tool)`, consuming it once.
pub(crate) fn take_account_transient(server: &str, tool: &str) -> Option<String> {
    VISIBILITY_MEMO
        .try_with(|memo| {
            memo.account_transient
                .lock()
                .remove(&(server.to_owned(), tool.to_owned()))
        })
        .ok()
        .flatten()
}

/// Keep the route verdict's resolution error for `(server, tool)` in the
/// open request; outside one it is dropped.
pub(crate) fn record_resolution_error(server: &str, tool: &str, error: crate::Error) {
    let _ = VISIBILITY_MEMO.try_with(|memo| {
        memo.resolution_error
            .lock()
            .insert((server.to_owned(), tool.to_owned()), error);
    });
}

/// Whether a resolution error is kept for `(server, tool)`, without
/// consuming it: a repeated verdict reads it as a memo hit (G1a twin).
pub(crate) fn has_resolution_error(server: &str, tool: &str) -> bool {
    VISIBILITY_MEMO
        .try_with(|memo| {
            memo.resolution_error
                .lock()
                .contains_key(&(server.to_owned(), tool.to_owned()))
        })
        .unwrap_or(false)
}

/// Take the resolution error kept for `(server, tool)`, consuming it once.
pub(crate) fn take_resolution_error(server: &str, tool: &str) -> Option<crate::Error> {
    VISIBILITY_MEMO
        .try_with(|memo| {
            memo.resolution_error
                .lock()
                .remove(&(server.to_owned(), tool.to_owned()))
        })
        .ok()
        .flatten()
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
