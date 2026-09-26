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

/// Causes a failed append is reported under: the `cause` label of
/// `mcp_audit_append_failures_total` and the `/readyz` body. A full volume is
/// the one an operator most needs named (the log has no rotation yet).
const FAILURE_CAUSES: [&str; 5] = [
    "storage_full",
    "permission_denied",
    "read_only_filesystem",
    "not_found",
    "io_error",
];

fn failure_cause(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::StorageFull => FAILURE_CAUSES[0],
        io::ErrorKind::PermissionDenied => FAILURE_CAUSES[1],
        io::ErrorKind::ReadOnlyFilesystem => FAILURE_CAUSES[2],
        io::ErrorKind::NotFound => FAILURE_CAUSES[3],
        _ => FAILURE_CAUSES[4],
    }
}

/// Index of `cause` in [`FAILURE_CAUSES`].
fn cause_index(cause: &str) -> usize {
    FAILURE_CAUSES.iter().position(|c| *c == cause).unwrap_or(4)
}

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
    /// a successful append clears it. Called on every append with its error,
    /// if any, so the cause (a full disk above all) is named in the log line,
    /// the counter's `cause` label and `/readyz`.
    pub(super) fn record_append(&self, failure: Option<&io::Error>) {
        let Some(error) = failure else {
            if self.degraded.swap(false, Ordering::AcqRel) {
                telemetry_metrics::gauge!("mcp_audit_degraded").set(0.0);
                tracing::info!("audit log appends again; calls are admitted");
            }
            return;
        };
        let cause = failure_cause(error.kind());
        self.last_failure_cause
            .store(cause_index(cause), Ordering::Release);
        self.append_failures.fetch_add(1, Ordering::AcqRel);
        telemetry_metrics::counter!("mcp_audit_append_failures_total", "cause" => cause)
            .increment(1);
        if self.failure_policy == AuditFailurePolicy::FailClosed
            && !self.degraded.swap(true, Ordering::AcqRel)
        {
            telemetry_metrics::gauge!("mcp_audit_degraded").set(1.0);
            tracing::error!(
                cause,
                %error,
                "audit log append failed; refusing calls until an append succeeds"
            );
        }
    }

    /// The cause of the most recent failed append, such as `storage_full`.
    #[must_use]
    pub fn last_failure_cause(&self) -> Option<&'static str> {
        FAILURE_CAUSES
            .get(self.last_failure_cause.load(Ordering::Acquire))
            .copied()
    }

    /// Append one `audit_probe` record. Success clears the degraded state.
    ///
    /// # Errors
    ///
    /// Returns the append's I/O error.
    pub fn probe(&self) -> io::Result<()> {
        #[cfg(test)]
        self.hooks
            .probes
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
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
        let fail_closed = self.failure_policy == AuditFailurePolicy::FailClosed;
        // F20: a stalled fail-closed log refuses at once, with no probe and
        // no thread; a best-effort one keeps serving, as D1 left it.
        if self.is_stalled() {
            return if fail_closed {
                Err(crate::Error::AuditUnavailable)
            } else {
                Ok(())
            };
        }
        if !self.is_degraded() {
            return Ok(());
        }
        // The probe takes the same single permit, so a stall parks no second
        // thread; no permit within the probe bound is a 503.
        let probe = self.append_bounded(TransparencyLogger::probe);
        match tokio::time::timeout(AUDIT_PROBE_TIMEOUT, probe).await {
            Ok(Ok(())) => Ok(()),
            _ => Err(crate::Error::AuditUnavailable),
        }
    }
}

#[cfg(test)]
mod cause_tests {
    use super::{cause_index, failure_cause};

    /// A full volume is named as such, the cause an operator must act on.
    #[test]
    fn a_full_disk_is_reported_as_storage_full() {
        let cause = failure_cause(std::io::ErrorKind::StorageFull);
        assert_eq!(cause, "storage_full");
        assert_eq!(cause_index(cause), 0);
        assert_eq!(failure_cause(std::io::ErrorKind::Other), "io_error");
    }
}
