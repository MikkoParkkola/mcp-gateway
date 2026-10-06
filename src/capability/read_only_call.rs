// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A call made on the promise that it changes nothing (an events watch poll,
//! MIK-7720). The executor refuses a capability that is not read-only by the
//! definition it is about to run, so a reload between the caller's own check
//! and the call cannot turn the call into a mutation.

use super::CapabilityDefinition;

tokio::task_local! {
    /// Set while a read-only call dispatches: whether it also expects a
    /// capability that needs no credential (a shared watch poll).
    static READ_ONLY_CALL: bool;
}

/// Run `call` as a read-only call that also expects, when
/// `credential_free`, a capability needing no credential: a shared poll
/// must never run under one sharer's credential.
pub(crate) async fn read_only_call_as<F: std::future::Future>(
    credential_free: bool,
    call: F,
) -> F::Output {
    READ_ONLY_CALL.scope(credential_free, call).await
}

/// Inside a read-only call, refuse `capability` unless it is read-only and,
/// when the call expects it, needs no credential.
pub(super) fn refuse_unless_read_only(capability: &CapabilityDefinition) -> crate::Result<()> {
    let Ok(credential_free) = READ_ONLY_CALL.try_with(|free| *free) else {
        return Ok(());
    };
    let auth = &capability.auth;
    let refusal = if !capability.metadata.read_only {
        "is not read-only"
    } else if credential_free && (auth.account.is_some() || auth.required || !auth.key.is_empty()) {
        "needs a credential"
    } else {
        return Ok(());
    };
    Err(crate::Error::Config(format!(
        "{} {refusal}, so a read-only call refuses it",
        capability.name
    )))
}

#[cfg(test)]
#[path = "read_only_call_tests.rs"]
mod tests;
