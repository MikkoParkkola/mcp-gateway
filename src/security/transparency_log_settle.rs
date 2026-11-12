// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Settle: append one journaled config-write record on the live logger,
//! under its own lease and lock, synced, and only into the log the journal
//! is bound to. Settle never decides an outcome: it records the payload it
//! is given, unchanged. Settle checks only the fields it and the chain own;
//! keeping paths, values, secrets and error text out of a payload is its
//! producer's (the journal's) job.
#![expect(
    dead_code,
    reason = "the config writer, the next step, builds the intent roles and reasons"
)]

use std::io;

use serde::Deserialize;
use serde::Serialize;
use serde_json::{Map, Value};

use super::TransparencyLogger;
use super::bounded::Dispatch;
use super::identity::LogId;

/// The kind of config write an intent names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IntentKind {
    Save,
    Adopt,
    Restore,
    Backend,
    KeyCreate,
}

/// The role a settled record plays; it names the record's event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    /// Every role, so a reader can name a record's role by its event.
    pub(crate) const ALL: [Self; 10] = [
        Self::Intent(IntentKind::Save),
        Self::Intent(IntentKind::Adopt),
        Self::Intent(IntentKind::Restore),
        Self::Intent(IntentKind::Backend),
        Self::Intent(IntentKind::KeyCreate),
        Self::RecoveryIntent,
        Self::Outcome,
        Self::Abandoned,
        Self::Deferred,
        Self::DeliveryStopped,
    ];

    /// The role whose event is `event`, if any.
    pub(crate) fn from_event(event: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.event() == event)
    }

    /// The record's event name.
    pub(crate) const fn event(self) -> &'static str {
        match self {
            Self::Intent(IntentKind::Save) => "config_save_intent",
            Self::Intent(IntentKind::Adopt) => "config_adopt_intent",
            Self::Intent(IntentKind::Restore) => "config_restore_intent",
            Self::Intent(IntentKind::Backend) => "config_backend_intent",
            Self::Intent(IntentKind::KeyCreate) => "config_key_create_intent",
            Self::RecoveryIntent => "config_recovery_intent",
            Self::Outcome => "config_write_outcome",
            Self::Abandoned => "config_write_abandoned",
            Self::Deferred => "config_write_deferred",
            Self::DeliveryStopped => "config_write_delivery_stopped",
        }
    }
}

/// Why a write ended as it did: a closed set, never error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    Abandoned,
    Moved,
    Refused,
    RenamedNotDurable,
    LeftToRecovery,
}

#[cfg(test)]
impl Reason {
    pub(crate) fn from_journal(bytes: &[u8]) -> Result<Self, InvalidReason> {
        serde_json::from_slice(bytes).map_err(|_| InvalidReason)
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvalidReason;

/// Actor metadata frozen beside caller payload bytes by journal owners.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Attribution {
    pub(crate) actor: crate::security::audit::AuditWho,
}

/// Which recovery attempt settled a write: its token and the counter its
/// intent was delivered at. The one wire form, frozen with the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SettledBy {
    // ci-allow-secret-debug: a write token is an opaque id naming one config-write attempt in the journal and the log, written to the log itself; it grants nothing.
    pub(crate) token: String,
    pub(crate) intent_counter: u64,
}

/// A settled record: the log it went into and its counter there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Appended {
    pub(crate) id: LogId,
    pub(crate) counter: u64,
}

/// Why a settle did not report `Appended`.
#[derive(Debug)]
pub(crate) enum Unsettled {
    /// The live logger holds another log than the journal is bound to;
    /// nothing was appended.
    OtherLog,
    /// A payload the rules refuse; nothing was appended, and a retry with
    /// the same payload cannot succeed.
    Invalid(InvalidPayload),
    /// Nothing was appended, and nothing can land later; retryable.
    Refused(io::Error),
    /// The write was dispatched and its completion is not confirmed: it may
    /// still land. Retryable; the reader collapses a repeat.
    Unconfirmed(io::Error),
}

/// Which rule refused a payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InvalidPayload {
    /// `kind` is absent or null.
    KindMissing,
    /// `kind` is not a string.
    KindNotString,
    /// `kind` lacks the settle prefix, or names nothing after it.
    KindNotPrefixed,
    /// A field the chain, the envelope, a segment or settle itself owns.
    ReservedField,
    /// The record is over the record cap.
    Oversized,
    /// A field the role's row (step 3 §2) requires, types or forbids.
    Field(FieldFault),
}

/// One break of a role's field row: which field, and how. Never its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FieldFault {
    pub(crate) field: &'static str,
    pub(crate) problem: FieldProblem,
}

/// How a field breaks its row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FieldProblem {
    /// Required and absent.
    Missing,
    /// Present with the wrong type, or an empty string where one is required.
    Mistyped,
    /// Present where the role forbids it.
    Forbidden,
}

/// Check `fields` (a whole record, or a payload with `event` and `token`
/// set) against `role`'s row of step 3 §2. Settle and verify both call it.
pub(crate) fn role_fields(role: Role, fields: &Map<String, Value>) -> Result<(), FieldFault> {
    use FieldProblem::{Forbidden, Missing, Mistyped};
    let fault = |field: &'static str, problem| Err(FieldFault { field, problem });
    text_field(fields, "token", "token")?;
    match (role, fields.get("intent_counter")) {
        (Role::Intent(_) | Role::RecoveryIntent, Some(_)) => fault("intent_counter", Forbidden)?,
        (Role::Outcome | Role::Deferred | Role::DeliveryStopped, None) => {
            fault("intent_counter", Missing)?;
        }
        (_, Some(v)) if v.as_u64().is_none() => fault("intent_counter", Mistyped)?,
        _ => {}
    }
    // settled_by belongs to an outcome alone (II.3): any other role,
    // recovery intents included, carrying it is refused.
    match (role, fields.get("settled_by")) {
        (_, None) => {}
        (Role::Outcome, Some(Value::Object(by))) => settled_by_fields(by)?,
        (Role::Outcome, Some(_)) => fault("settled_by", Mistyped)?,
        (_, Some(_)) => fault("settled_by", Forbidden)?,
    }
    match (role, fields.get("root")) {
        (Role::RecoveryIntent, Some(Value::Bool(true))) => {
            if fields.contains_key("settles") {
                fault("settles", Forbidden)?;
            }
        }
        (Role::RecoveryIntent, None) => text_field(fields, "settles", "settles")?,
        (Role::RecoveryIntent, Some(_)) => fault("root", Mistyped)?,
        (_, Some(_)) => fault("root", Forbidden)?,
        (_, None) => {}
    }
    Ok(())
}

/// An outcome's `settled_by`: a non-empty `token` and a u64 `intent_counter`.
fn settled_by_fields(by: &Map<String, Value>) -> Result<(), FieldFault> {
    text_field(by, "token", "settled_by.token")?;
    let problem = match by.get("intent_counter") {
        None => FieldProblem::Missing,
        Some(v) if v.as_u64().is_none() => FieldProblem::Mistyped,
        Some(_) => return Ok(()),
    };
    Err(FieldFault {
        field: "settled_by.intent_counter",
        problem,
    })
}

/// `map[key]` must be a non-empty string; a fault names it `field`.
fn text_field(map: &Map<String, Value>, key: &str, field: &'static str) -> Result<(), FieldFault> {
    let problem = match map.get(key) {
        None => FieldProblem::Missing,
        Some(Value::String(s)) if !s.is_empty() => return Ok(()),
        Some(_) => FieldProblem::Mistyped,
    };
    Err(FieldFault { field, problem })
}

/// The caller's part of a record: every chain, envelope and segment field,
/// `timestamp` and `clock_invalid` removed; `event`, `token` and the role
/// kept. Two repeats of one settle are equal exactly when their views are.
pub(crate) fn caller_view(record: &Map<String, Value>) -> Map<String, Value> {
    let mut view = record.clone();
    for name in TransparencyLogger::reserved_field_names().chain(["timestamp", "clock_invalid"]) {
        view.remove(name);
    }
    view
}

/// Test seams (V.1): settle refuses before its append, or after it, or its
/// task panics once it has started.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailSettle {
    BeforeAppend,
    AfterAppend,
    PanicInTask,
}

/// The kind prefix of every settle record (delta S2'): no other append may
/// write a kind that starts with it, so a reader of a plain kind never sees
/// a settle record.
pub(crate) const KIND_PREFIX: &str = "settle.";

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
    /// Append `payload` as the `role` record of `token`, synced, into the log
    /// the journal bound as `binding`, under this logger's lease and lock and
    /// the F20 bound: it answers within twice [`super::bounded::AUDIT_APPEND_TIMEOUT`].
    /// The payload is written as given; settle adds only `event` (from `role`)
    /// and `token`. Two settles of one payload, token and role write equal
    /// records but for the envelope and chain fields.
    ///
    /// # Errors
    ///
    /// [`Unsettled::Invalid`] for a payload the rules refuse,
    /// [`Unsettled::Refused`] when nothing was written and nothing can land
    /// (the permit was not taken, or the task failed before its first byte),
    /// [`Unsettled::OtherLog`] when this logger holds another log, and
    /// [`Unsettled::Unconfirmed`] once a write was dispatched and is not
    /// confirmed: it may still land.
    pub(crate) async fn settle(
        self: &std::sync::Arc<Self>,
        binding: &LogId,
        token: &str,
        role: Role,
        payload: Map<String, Value>,
    ) -> Result<Appended, Unsettled> {
        let fields = settle_fields(token, role, payload).map_err(Unsettled::Invalid)?;
        let binding = binding.clone();
        match self
            .dispatch_bounded(None, move |l| l.settle_now(&binding, fields))
            .await
        {
            Dispatch::NotStarted(e) => Err(Unsettled::Refused(e)),
            Dispatch::Joined(settled) => settled,
            Dispatch::Unconfirmed(e) => Err(Unsettled::Unconfirmed(e)),
        }
    }

    /// The synchronous core, on the blocking task under the permit: re-read
    /// the tail, check the binding after that (a rebuild can adopt another
    /// log), then write `fields` synced.
    fn settle_now(
        &self,
        binding: &LogId,
        fields: Map<String, Value>,
    ) -> Result<Appended, Unsettled> {
        #[cfg(test)]
        self.settle_task_started();
        // Before the first byte: a failure here is Refused, and counted.
        let refused = |e: io::Error| {
            self.record_append(Some(&e));
            Unsettled::Refused(e)
        };
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| refused(io::Error::other("transparency log mutex poisoned")))?;
        self.refresh(&mut inner, true).map_err(refused)?;
        if self.presented_id(&inner.log_id) != *binding {
            return Err(Unsettled::OtherLog);
        }
        #[cfg(test)]
        if self.settle_fault_at(FailSettle::BeforeAppend) {
            return Err(Unsettled::Refused(io::Error::other(
                "injected settle refusal",
            )));
        }
        // Once the write begins, a failure may have left bytes, or a sync
        // unproven: Unconfirmed, whatever the cut-back did.
        match self.append_refreshed(&mut inner, fields, true, Some(binding)) {
            Err(e) if super::rotation::is_oversized(&e) => {
                return Err(Unsettled::Invalid(InvalidPayload::Oversized));
            }
            Err(e) => {
                self.record_append(Some(&e));
                return Err(Unsettled::Unconfirmed(e));
            }
            Ok(_) => self.record_append(None),
        }
        #[cfg(test)]
        if self.settle_fault_at(FailSettle::AfterAppend) {
            return Err(Unsettled::Unconfirmed(io::Error::other(
                "injected settle failure",
            )));
        }
        Ok(Appended {
            id: inner.log_id.clone(),
            counter: inner.counter,
        })
    }
}

impl TransparencyLogger {
    /// The log's id after a refresh from the file on disk. A log replaced
    /// behind this handle is adopted by the refresh, which the cached
    /// [`Self::log_id`] cannot see.
    pub(crate) fn refreshed_log_id(&self) -> io::Result<LogId> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("transparency log mutex poisoned"))?;
        self.refresh(&mut inner, true)?;
        Ok(inner.log_id.clone())
    }

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

/// The record settle writes: the payload as given, plus `event` (from the
/// role) and `token`. A payload naming either, or a chain, envelope or
/// segment field, or a `kind` outside [`KIND_PREFIX`], is refused rather
/// than rewritten.
fn settle_fields(
    token: &str,
    role: Role,
    payload: Map<String, Value>,
) -> Result<Map<String, Value>, InvalidPayload> {
    let owned = ["event", "token"]
        .into_iter()
        .any(|k| payload.contains_key(k));
    if owned || TransparencyLogger::reject_reserved_fields(&payload).is_err() {
        return Err(InvalidPayload::ReservedField);
    }
    match payload.get("kind") {
        None | Some(Value::Null) => return Err(InvalidPayload::KindMissing),
        Some(Value::String(kind)) => {
            let named = kind
                .strip_prefix(KIND_PREFIX)
                .is_some_and(|rest| !rest.is_empty());
            if !named {
                return Err(InvalidPayload::KindNotPrefixed);
            }
        }
        Some(_) => return Err(InvalidPayload::KindNotString),
    }
    let mut fields = payload;
    fields.insert("event".into(), role.event().into());
    fields.insert("token".into(), token.into());
    crate::security::audit::AuditEnvelope::gateway().write_into(&mut fields);
    role_fields(role, &fields).map_err(InvalidPayload::Field)?;
    Ok(fields)
}

#[cfg(test)]
impl TransparencyLogger {
    /// Arm a one-shot settle refusal.
    pub(crate) fn arm_settle_fault(&self, fault: FailSettle) {
        *self.hooks.settle_fault.lock().unwrap() = Some(fault);
    }

    /// Whether `at` was armed; disarms it.
    fn settle_fault_at(&self, at: FailSettle) -> bool {
        let mut armed = self.hooks.settle_fault.lock().unwrap();
        let fired = *armed == Some(at);
        if fired {
            *armed = None;
        }
        fired
    }

    /// The task's start: wait at an armed start gate, or panic when armed.
    fn settle_task_started(&self) {
        let gate = self.hooks.settle_start.lock().unwrap().take();
        if let Some(gate) = gate {
            gate.hold();
        }
        assert!(
            !self.settle_fault_at(FailSettle::PanicInTask),
            "injected settle task panic"
        );
    }

    /// Hold settle's blocking task before it starts any work: a task queued
    /// but not started.
    pub(crate) fn hold_settle_task_for_test(&self) -> super::rotation::StallRelease {
        let gate = std::sync::Arc::new(super::rotation::StallGate::default());
        *self.hooks.settle_start.lock().unwrap() = Some(std::sync::Arc::clone(&gate));
        super::rotation::StallRelease(gate)
    }

    /// The V.1 `Bind(OtherLog)` seam: settle sees `id` as the logger's own,
    /// after its refresh (which would otherwise restore the id on disk).
    pub(crate) fn present_log_id_for_test(&self, id: LogId) {
        *self.hooks.presented_id.lock().unwrap() = Some(id);
    }
}

#[cfg(test)]
impl TransparencyLogger {
    pub(crate) async fn settle_attributed(
        self: &std::sync::Arc<Self>,
        binding: &LogId,
        token: &str,
        role: Role,
        payload: Map<String, Value>,
        actor: crate::security::audit::AuditWho,
    ) -> Result<Appended, Unsettled> {
        let mut fields = settle_fields(token, role, payload).map_err(Unsettled::Invalid)?;
        crate::security::audit::AuditEnvelope::ok(actor).write_into(&mut fields);
        let binding = binding.clone();
        match self
            .dispatch_bounded(None, move |log| log.settle_now(&binding, fields))
            .await
        {
            Dispatch::NotStarted(error) => Err(Unsettled::Refused(error)),
            Dispatch::Joined(settled) => settled,
            Dispatch::Unconfirmed(error) => Err(Unsettled::Unconfirmed(error)),
        }
    }
}
