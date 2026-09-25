// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D1-f: what a failed append does, and the degraded state it leaves.

use super::TransparencyLogger;
use crate::security::audit::AuditFailurePolicy;

impl TransparencyLogger {
    /// Set what a failed append does (D1-f). The server picks `FailClosed`
    /// when auth is on.
    #[must_use]
    pub fn with_failure_policy(mut self, policy: AuditFailurePolicy) -> Self {
        self.failure_policy = policy;
        self
    }

    /// What a failed append does.
    #[must_use]
    pub fn failure_policy(&self) -> AuditFailurePolicy {
        self.failure_policy
    }

    /// Whether an append has failed under `FailClosed` and none has succeeded since.
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        self.degraded.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Appends that failed since the logger opened.
    #[must_use]
    pub fn append_failures(&self) -> u64 {
        self.append_failures
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Make every append fail until cleared.
    #[cfg(test)]
    pub(crate) fn set_append_failure_for_test(&self, on: bool) {
        self.fail_appends
            .store(on, std::sync::atomic::Ordering::Release);
    }
}
