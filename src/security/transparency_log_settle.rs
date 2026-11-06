// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Settle: append one journaled config-write record on the live logger,
//! under its own lease and lock, synced, and only into the log the journal
//! is bound to. Settle never decides an outcome: it records the payload it
//! is given, unchanged. Records carry no paths, values, secrets or error
//! text; the payload types below hold none.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the config writer calls settle in the next step")
)]

use std::io;

use serde::Serialize;
use serde_json::{Map, Value};

use super::TransparencyLogger;
use super::identity::LogId;

/// The kind of config write an intent names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IntentKind {
    Save,
    Adopt,
    Restore,
    Backend,
}

/// The role a settled record plays; it names the record's event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    /// The writer's intent, by kind.
    Intent(IntentKind),
    /// A recovery attempt's intent.
    RecoveryIntent,
    /// A terminal outcome.
    Outcome,
    /// A terminal abandonment.
    Abandoned,
    /// A deferral, not terminal.
    Deferred,
    /// Delivery stopped by the operator, not terminal.
    DeliveryStopped,
}

impl Role {
    /// The record's event name.
    pub(crate) const fn event(self) -> &'static str {
        match self {
            Self::Intent(IntentKind::Save) => "config_save_intent",
            Self::Intent(IntentKind::Adopt) => "config_adopt_intent",
            Self::Intent(IntentKind::Restore) => "config_restore_intent",
            Self::Intent(IntentKind::Backend) => "config_backend_intent",
            Self::RecoveryIntent => "config_recovery_intent",
            Self::Outcome => "config_write_outcome",
            Self::Abandoned => "config_write_abandoned",
            Self::Deferred => "config_write_deferred",
            Self::DeliveryStopped => "config_write_delivery_stopped",
        }
    }
}

/// Why a write ended as it did: a closed set, never error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Reason {
    Committed,
    RolledBack,
    KeptNew,
    NothingPending,
    DeletedDuringCompute,
    ComputeRefused,
    SecretsRefused,
    WriterDied,
    Panicked,
    OperatorAbandoned,
    RenamedNotDurable,
    LeftToRecovery,
}

/// Which recovery attempt settled a write: its token and the counter its
/// intent was delivered at. The one wire form, frozen with the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SettledBy {
    pub(crate) token: String,
    pub(crate) intent_counter: u64,
}

/// A settled record: the log it went into and its counter there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Appended {
    pub(crate) id: LogId,
    pub(crate) counter: u64,
}

/// Why nothing was settled.
#[derive(Debug)]
pub(crate) enum Unsettled {
    /// The live logger holds another log than the journal is bound to.
    OtherLog,
    /// The append failed; nothing is claimed.
    Refused(io::Error),
}

/// Test seams (V.1): settle refuses before its append, or after it.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailSettle {
    BeforeAppend,
    AfterAppend,
}

impl TransparencyLogger {
    /// Append `payload` as the `role` record of `token`, synced, into the log
    /// bound by `binding`. Not built yet: refuses everything.
    ///
    /// # Errors
    ///
    /// Always [`Unsettled::Refused`] for now.
    pub(crate) fn settle(
        &self,
        _binding: &LogId,
        _token: &str,
        _role: Role,
        _payload: Map<String, Value>,
    ) -> Result<Appended, Unsettled> {
        Err(Unsettled::Refused(io::ErrorKind::Unsupported.into()))
    }
}

#[cfg(test)]
impl TransparencyLogger {
    /// Arm a one-shot settle refusal.
    pub(crate) fn arm_settle_fault(&self, fault: FailSettle) {
        *self.hooks.settle_fault.lock().unwrap() = Some(fault);
    }

    /// The V.1 `Bind(OtherLog)` seam: the logger presents `id` as its own.
    pub(crate) fn present_log_id_for_test(&self, id: LogId) {
        self.inner.lock().unwrap().log_id = id;
    }
}
