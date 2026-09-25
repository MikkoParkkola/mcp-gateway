// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D1-f: what a failed append does, and the degraded state it leaves.

use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::TransparencyLogger;
use crate::security::audit::{AuditEnvelope, AuditFailurePolicy};

/// The `type` of the record a degraded logger appends to test its storage.
/// Chain consumers filter on it; no writer can supply `type` itself.
pub const AUDIT_PROBE_TYPE: &str = "audit_probe";

/// Bound on a probe append, so a stalled filesystem answers 503 instead of
/// hanging the call or the readiness check (Revision 3).
pub const AUDIT_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

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
        self.degraded.load(Ordering::Acquire)
    }

    /// Appends that failed since the logger opened.
    #[must_use]
    pub fn append_failures(&self) -> u64 {
        self.append_failures.load(Ordering::Acquire)
    }

    /// Make every append fail until cleared.
    #[cfg(test)]
    pub(crate) fn set_append_failure_for_test(&self, on: bool) {
        self.fail_appends.store(on, Ordering::Release);
    }

    /// Count a failed append, and under `FailClosed` mark the logger degraded;
    /// a successful append clears it. Called on every append.
    pub(super) fn record_append(&self, ok: bool) {
        if ok {
            if self.degraded.swap(false, Ordering::AcqRel) {
                telemetry_metrics::gauge!("mcp_audit_degraded").set(0.0);
                tracing::info!("audit log appends again; calls are admitted");
            }
            return;
        }
        self.append_failures.fetch_add(1, Ordering::AcqRel);
        telemetry_metrics::counter!("mcp_audit_append_failures_total").increment(1);
        if self.failure_policy == AuditFailurePolicy::FailClosed
            && !self.degraded.swap(true, Ordering::AcqRel)
        {
            telemetry_metrics::gauge!("mcp_audit_degraded").set(1.0);
            tracing::error!("audit log append failed; refusing calls until an append succeeds");
        }
    }

    /// Append one `audit_probe` record. Success clears the degraded state.
    ///
    /// # Errors
    ///
    /// Returns the append's I/O error.
    pub fn probe(&self) -> io::Result<()> {
        let mut fields = serde_json::Map::new();
        fields.insert("type".into(), AUDIT_PROBE_TYPE.into());
        fields.insert("timestamp".into(), chrono::Utc::now().to_rfc3339().into());
        self.append_core(fields, &AuditEnvelope::gateway(), false)
            .map(|_| ())
    }

    /// Admit a call. A healthy logger admits at once; a degraded one first
    /// tries a probe append, bounded by [`AUDIT_PROBE_TIMEOUT`].
    ///
    /// # Errors
    ///
    /// [`crate::Error::AuditUnavailable`] when degraded and the probe fails or
    /// times out.
    pub async fn admit(self: &Arc<Self>) -> crate::Result<()> {
        if !self.is_degraded() {
            return Ok(());
        }
        let logger = Arc::clone(self);
        let probe = tokio::task::spawn_blocking(move || logger.probe());
        match tokio::time::timeout(AUDIT_PROBE_TIMEOUT, probe).await {
            Ok(Ok(Ok(()))) => Ok(()),
            _ => Err(crate::Error::AuditUnavailable),
        }
    }
}
