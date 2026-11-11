// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The key server's one way into the audit log: a safe `token.issued` row,
//! appended through the bounded synced path, with how far the append got
//! reported raw so the caller applies its failure policy.
//!
//! Kept in the logger module because only here is [`Dispatch`] visible: the
//! public `append_bounded` wrapper folds "never started" and "not confirmed"
//! into one I/O error, and the policy table needs them apart. It does not
//! call `append_admin_action`, which overwrites the row's `event`.

use std::io;
use std::sync::Arc;

use super::TransparencyLogger;
use super::bounded::Dispatch;
use crate::security::audit::AuditEnvelope;

/// The only event this path writes.
pub(crate) const ISSUED_EVENT: &str = "token.issued";

/// How an issuance row's append came out. Every arm but `Confirmed` means
/// "the row is not known to be on disk"; `Failed` and `Unconfirmed` may
/// still leave bytes behind (a rollback can fail, a timed-out write can land
/// late).
#[derive(Debug)]
pub(crate) enum IssuanceWrite {
    /// The row was written and synced.
    Confirmed,
    /// No append ran: the event was not an issuance row, admission refused,
    /// or the log was stalled or its permit was not taken.
    NotAttempted(io::Error),
    /// The append ran to its end and failed.
    Failed(io::Error),
    /// The append was dispatched and its end is not confirmed.
    Unconfirmed(io::Error),
}

impl IssuanceWrite {
    /// The fixed label for logs and counters; never the error text.
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::NotAttempted(_) => "not_attempted",
            Self::Failed(_) => "failed",
            Self::Unconfirmed(_) => "unconfirmed",
        }
    }
}

impl TransparencyLogger {
    /// Append one `token.issued` row, stamped with its time, through the
    /// bounded synced path. The future is never wrapped in an outer timeout:
    /// dropping it would skip the stall bookkeeping.
    pub(crate) async fn append_issuance_row(
        self: &Arc<Self>,
        mut fields: serde_json::Map<String, serde_json::Value>,
        envelope: AuditEnvelope,
    ) -> IssuanceWrite {
        if fields.get("event").and_then(serde_json::Value::as_str) != Some(ISSUED_EVENT) {
            return IssuanceWrite::NotAttempted(io::Error::other("not an issuance row"));
        }
        if self.admit().await.is_err() {
            return IssuanceWrite::NotAttempted(io::Error::other("audit admission refused"));
        }
        crate::clock::stamp_audit_row(&mut fields);
        let dispatched = self
            .dispatch_bounded(None, move |log| log.append_event_synced(fields, &envelope))
            .await;
        match dispatched {
            Dispatch::Joined(Ok(_)) => IssuanceWrite::Confirmed,
            Dispatch::Joined(Err(error)) => IssuanceWrite::Failed(error),
            Dispatch::NotStarted(error) => IssuanceWrite::NotAttempted(error),
            Dispatch::Unconfirmed(error) => IssuanceWrite::Unconfirmed(error),
        }
    }
}
