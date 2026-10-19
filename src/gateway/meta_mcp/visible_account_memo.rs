// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stored read's account memo slots (MIK-8392): the binding the
//! pre-pass's view read gave each account, and the live call's refusal kept
//! for an account that can never bind.

use super::{AccountKey, account_slot, in_memo, target_key};

/// Keep the binding the pre-pass's view read gave `(server, account)`.
pub(crate) fn record_account_binding(server: &str, account: &AccountKey, binding: &str) {
    in_memo(|memo| {
        memo.account_binding
            .set(account_slot(server, account), binding.to_owned());
    });
}

/// The binding the pre-pass's view read gave `(server, account)`, if any.
pub(crate) fn account_binding(server: &str, account: &AccountKey) -> Option<String> {
    in_memo(|memo| memo.account_binding.get(&account_slot(server, account))).flatten()
}

/// Keep the live call's refusal for `(server, account)` in the open request;
/// outside one it is dropped.
pub(crate) fn record_account_refusal(server: &str, account: &AccountKey, refusal: crate::Error) {
    in_memo(|memo| {
        memo.account_refusal
            .set(account_slot(server, account), refusal);
    });
}

/// Keep this request's transient busy custody for `(server, tool)`, with
/// the busy reason; outside a request nothing is kept.
pub(crate) fn record_account_transient(server: &str, tool: &str, reason: String) {
    in_memo(|memo| memo.account_transient.set(target_key(server, tool), reason));
}

/// The transient kept for `(server, tool)`, without consuming it.
pub(crate) fn account_transient(server: &str, tool: &str) -> Option<String> {
    in_memo(|memo| memo.account_transient.get(&target_key(server, tool))).flatten()
}

/// Take any one transient this request holds, consuming it: the task
/// intake trigger, which answers for the whole call.
pub(crate) fn take_any_account_transient() -> Option<String> {
    in_memo(|memo| memo.account_transient.take_first_where(|_| true)).flatten()
}

/// Take any one sealed-transient resolution error this request holds (a
/// busy custody at the route stage's mint, MIK-8428 Case B), consuming it:
/// the task intake trigger beside [`take_any_account_transient`]. Any other
/// carried error is left for its own dispatch.
pub(crate) fn take_any_transient_resolution_error() -> Option<crate::Error> {
    in_memo(|memo| {
        memo.resolution_error.take_first_where(|error| {
            crate::personal_accounts::refusal::transient_data(error).is_some()
        })
    })
    .flatten()
}

/// Take the transient kept for `(server, tool)`, consuming it once.
pub(crate) fn take_account_transient(server: &str, tool: &str) -> Option<String> {
    in_memo(|memo| memo.account_transient.take(&target_key(server, tool))).flatten()
}

/// Keep the route verdict's resolution error for `(server, tool)` in the
/// open request; outside one it is dropped.
pub(crate) fn record_resolution_error(server: &str, tool: &str, error: crate::Error) {
    in_memo(|memo| memo.resolution_error.set(target_key(server, tool), error));
}

/// Whether a resolution error is kept for `(server, tool)`, without
/// consuming it: a repeated verdict reads it as a memo hit (G1a twin).
pub(crate) fn has_resolution_error(server: &str, tool: &str) -> bool {
    in_memo(|memo| memo.resolution_error.contains(&target_key(server, tool))).unwrap_or(false)
}

/// Take the resolution error kept for `(server, tool)`, consuming it once.
pub(crate) fn take_resolution_error(server: &str, tool: &str) -> Option<crate::Error> {
    in_memo(|memo| memo.resolution_error.take(&target_key(server, tool))).flatten()
}

/// Take the refusal kept for `(server, account)`, if any.
pub(crate) fn take_account_refusal(server: &str, account: &AccountKey) -> Option<crate::Error> {
    in_memo(|memo| memo.account_refusal.take(&account_slot(server, account))).flatten()
}

#[cfg(test)]
#[path = "visible_account_memo_tests.rs"]
mod tests;
