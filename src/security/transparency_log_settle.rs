// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Settle: append one journaled config-write record on the live logger,
//! under its own lease and lock, synced, and only into the log the journal
//! is bound to. Settle never decides an outcome: it records the payload it
//! is given, unchanged. Records carry no paths, values, secrets or error
//! text; the payload types below hold none.
#![expect(
    dead_code,
    reason = "the config writer, the next step, builds the intent roles and reasons"
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

/// The settle events no caller may append. The intent events are not here
/// yet: today's writer still appends them itself, and they are reserved when
/// it moves to settle.
pub(crate) const RESERVED_EVENTS: [&str; 4] = [
    Role::Outcome.event(),
    Role::Abandoned.event(),
    Role::Deferred.event(),
    Role::DeliveryStopped.event(),
];

impl TransparencyLogger {
    /// [`Self::settle_now`] for an async caller. Not bounded yet: it runs the
    /// synchronous core in place, with no F20 permit.
    ///
    /// # Errors
    ///
    /// As [`Self::settle_now`].
    pub(crate) async fn settle(
        self: &std::sync::Arc<Self>,
        binding: &LogId,
        token: &str,
        role: Role,
        payload: Map<String, Value>,
    ) -> Result<Appended, Unsettled> {
        self.settle_now(binding, token, role, payload)
    }

    /// Append `payload` as the `role` record of `token`, synced, into the log
    /// the journal bound as `binding`, under this logger's lease and lock.
    /// The payload is written as given; settle adds only `event` and `token`.
    ///
    /// # Errors
    ///
    /// [`Unsettled::OtherLog`] when this logger holds another log, checked
    /// after the tail is re-read (a rebuild can adopt another log), and
    /// [`Unsettled::Refused`] when the payload names a field settle or the
    /// chain owns, or the append fails: nothing is claimed either way.
    fn settle_now(
        &self,
        binding: &LogId,
        token: &str,
        role: Role,
        payload: Map<String, Value>,
    ) -> Result<Appended, Unsettled> {
        let fields = settle_fields(token, role, payload).map_err(Unsettled::Refused)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| Unsettled::Refused(io::Error::other("transparency log mutex poisoned")))?;
        self.refresh(&mut inner, true).map_err(Unsettled::Refused)?;
        if self.presented_id(&inner.log_id) != *binding {
            return Err(Unsettled::OtherLog);
        }
        #[cfg(test)]
        self.settle_fault_at(FailSettle::BeforeAppend)?;
        let written = self.append_refreshed(&mut inner, fields, true);
        // As every append: a failure counts toward the log's health, except
        // an oversized record, which is refused for that call only.
        if !written.as_ref().is_err_and(super::rotation::is_oversized) {
            self.record_append(written.as_ref().err());
        }
        written.map_err(Unsettled::Refused)?;
        #[cfg(test)]
        self.settle_fault_at(FailSettle::AfterAppend)?;
        Ok(Appended {
            id: inner.log_id.clone(),
            counter: inner.counter,
        })
    }
}

impl TransparencyLogger {
    /// The id settle checks the binding against: the one the refresh left.
    #[cfg(not(test))]
    #[allow(clippy::unused_self)]
    fn presented_id(&self, held: &LogId) -> LogId {
        held.clone()
    }

    /// As in production, unless the `Bind(OtherLog)` seam presents another.
    #[cfg(test)]
    fn presented_id(&self, held: &LogId) -> LogId {
        let presented = self.hooks.presented_id.lock().unwrap().clone();
        presented.unwrap_or_else(|| held.clone())
    }
}

/// The record settle writes: the payload as given, plus its role's event and
/// the token. A payload naming either, or a chain, envelope or segment field,
/// is refused rather than overwritten.
fn settle_fields(
    token: &str,
    role: Role,
    payload: Map<String, Value>,
) -> io::Result<Map<String, Value>> {
    TransparencyLogger::reject_reserved_fields(&payload)?;
    if let Some(key) = ["event", "token"]
        .into_iter()
        .find(|k| payload.contains_key(*k))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("settle: the payload names '{key}', which settle writes"),
        ));
    }
    let mut fields = payload;
    fields.insert("event".into(), role.event().into());
    fields.insert("token".into(), token.into());
    crate::security::audit::AuditEnvelope::gateway().write_into(&mut fields);
    Ok(fields)
}

#[cfg(test)]
impl TransparencyLogger {
    /// Arm a one-shot settle refusal.
    pub(crate) fn arm_settle_fault(&self, fault: FailSettle) {
        *self.hooks.settle_fault.lock().unwrap() = Some(fault);
    }

    /// Refuse here if `at` is armed, once.
    fn settle_fault_at(&self, at: FailSettle) -> Result<(), Unsettled> {
        let mut armed = self.hooks.settle_fault.lock().unwrap();
        if *armed == Some(at) {
            *armed = None;
            return Err(Unsettled::Refused(io::Error::other(
                "injected settle refusal",
            )));
        }
        Ok(())
    }

    /// The V.1 `Bind(OtherLog)` seam: settle sees `id` as the logger's own,
    /// after its refresh (which would otherwise restore the id on disk).
    pub(crate) fn present_log_id_for_test(&self, id: LogId) {
        *self.hooks.presented_id.lock().unwrap() = Some(id);
    }
}
