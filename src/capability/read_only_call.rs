// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A call made on the promise that it changes nothing (an events watch poll,
//! MIK-7720). The executor refuses a capability that is not read-only by the
//! definition it is about to run, so a reload between the caller's own check
//! and the call cannot turn the call into a mutation.

use super::CapabilityDefinition;

tokio::task_local! {
    /// Set while a read-only call dispatches.
    static READ_ONLY_CALL: ();
}

/// Run `call` as a read-only call.
#[allow(dead_code, reason = "red: the watch poll uses it next")]
pub(crate) async fn read_only_call<F: std::future::Future>(call: F) -> F::Output {
    READ_ONLY_CALL.scope((), call).await
}

/// Inside a read-only call, refuse `capability` unless it is read-only.
#[allow(dead_code, reason = "red: the executor calls it next")]
pub(super) fn refuse_unless_read_only(capability: &CapabilityDefinition) -> crate::Result<()> {
    if READ_ONLY_CALL.try_with(|()| ()).is_ok() && !capability.metadata.read_only {
        return Err(crate::Error::Config(format!(
            "{} is not read-only, so a read-only call refuses it",
            capability.name
        )));
    }
    Ok(())
}

#[cfg(test)]
#[path = "read_only_call_tests.rs"]
mod tests;
