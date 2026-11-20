// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a grant decision record is and how it reaches the log: the note a
//! check takes, which notes become records, and the bounded write, on the
//! caller's task or a spawned one when a slot drops.

use std::sync::Arc;
use std::time::Instant;

use serde_json::{Map, Value};

use crate::identity_grants::IdentityGrantAuditEvent;
use crate::security::TransparencyLogger;
use crate::security::audit::{AuditEnvelope, AuditOutcome, AuditWho};

#[cfg(test)]
use super::seams;
use super::{
    DECISION_KIND, LEDGER_WAIT, RecordedSet, RepeatMark, RetryCell, Slot, WITHHELD_RECORD_FAILED,
    marker, open_slot_recorded,
};

/// One grant decision noted inside a slot, keyed by the check's own inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::gateway::meta_mcp) struct GrantNote {
    /// The backend the check was asked about.
    pub(in crate::gateway::meta_mcp) server: String,
    /// The tool the check was asked about.
    pub(in crate::gateway::meta_mcp) tool: String,
    /// `trace::current()` when the note was taken; `None` outside an invocation.
    pub(in crate::gateway::meta_mcp) trace_id: Option<String>,
    /// Whether the grant allowed the call.
    pub(in crate::gateway::meta_mcp) allowed: bool,
    /// The record's domain fields, projected: the subject without its label.
    pub(in crate::gateway::meta_mcp) fields: Map<String, Value>,
    /// The evaluated subject id, for the envelope's `who`.
    pub(in crate::gateway::meta_mcp) subject: Option<String>,
    /// Set on a finished task's re-check: how a repeat is recognised.
    pub(in crate::gateway::meta_mcp) repeat: Option<RepeatMark>,
    /// Whether [`DELIVERY`] was set when the note was taken.
    pub(in crate::gateway::meta_mcp) delivery: bool,
    /// The open slot's recorded set; empty for a note taken outside a slot.
    pub(in crate::gateway::meta_mcp) recorded: RecordedSet,
    /// The retry a withheld call routed to, when taken inside one.
    pub(in crate::gateway::meta_mcp) retry: Option<RetryCell>,
}

impl GrantNote {
    /// Project `event` into a note. The subject keeps `authority` and
    /// `subject` only: its label is an email and never reaches the log.
    pub(super) fn project(server: &str, tool: &str, event: &IdentityGrantAuditEvent) -> Self {
        let mut fields = Map::new();
        fields.insert("kind".into(), DECISION_KIND.into());
        fields.insert("server".into(), server.into());
        fields.insert("timestamp".into(), event.timestamp.to_rfc3339().into());
        fields.insert(
            "reason".into(),
            serde_json::to_value(&event.reason).unwrap_or_default(),
        );
        fields.insert("capability".into(), event.capability.clone().into());
        fields.insert(
            "scope".into(),
            serde_json::to_value(&event.scope).unwrap_or_default(),
        );
        if let Some(tool) = &event.tool {
            fields.insert("tool".into(), tool.clone().into());
        }
        if let Some(grant_id) = &event.grant_id {
            fields.insert("grant_id".into(), grant_id.clone().into());
        }
        if let Some(agent_id) = &event.agent_id {
            fields.insert("agent_id".into(), agent_id.clone().into());
        }
        if let Some(subject) = &event.subject {
            fields.insert(
                "subject".into(),
                serde_json::json!({ "authority": subject.authority(), "subject": subject.subject() }),
            );
        }
        Self {
            server: server.to_string(),
            tool: tool.to_string(),
            trace_id: crate::gateway::trace::current(),
            allowed: event.allowed,
            fields,
            subject: event.subject.as_ref().map(|s| s.subject().to_owned()),
            repeat: None,
            delivery: marker::delivery_scoped(),
            recorded: open_slot_recorded().unwrap_or_default(),
            retry: marker::current_retry(),
        }
    }

    /// Whether the call this note is about has an invocation record of its
    /// own, as the log holds it now: a delivery re-check's call has the
    /// original request's, any other call has one once its trace id landed.
    fn invocation_recorded(&self) -> bool {
        self.delivery
            || self
                .trace_id
                .as_deref()
                .is_some_and(|trace| self.recorded.contains(trace))
            || self
                .retry
                .as_ref()
                .and_then(RetryCell::id)
                .is_some_and(|trace| self.recorded.contains(trace))
    }

    /// Every recorded field but the timestamp, and the outcome.
    pub(super) fn fingerprint(&self) -> String {
        let mut fields = self.fields.clone();
        fields.remove("timestamp");
        format!("{}|{}", self.allowed, Value::Object(fields))
    }

    fn envelope(&self) -> AuditEnvelope {
        let mut who = AuditWho::from_subject(self.subject.as_deref().unwrap_or("anonymous"));
        // `who` names the same (authority, subject) pair the domain
        // `subject` field records, not the subject alone.
        who.authority = self
            .fields
            .get("subject")
            .and_then(|subject| subject["authority"].as_str())
            .map(str::to_string);
        AuditEnvelope {
            trace_id: self.trace_id.clone(),
            otel_trace_id: None,
            outcome: if self.allowed {
                AuditOutcome::Ok
            } else {
                AuditOutcome::Denied(-32004)
            },
            who,
        }
    }
}

/// The notes that become records: every traced note, and the last untraced
/// note of a `(server, tool)` with no traced note.
pub(in crate::gateway::meta_mcp) fn select_records(notes: &[GrantNote]) -> Vec<&GrantNote> {
    let same = |a: &GrantNote, b: &GrantNote| a.server == b.server && a.tool == b.tool;
    notes
        .iter()
        .enumerate()
        .filter(|&(i, note)| {
            note.trace_id.is_some()
                || (!notes.iter().any(|n| same(n, note) && n.trace_id.is_some())
                    && !notes[i + 1..].iter().any(|n| same(n, note)))
        })
        .map(|(_, note)| note)
        .collect()
}

/// Owns a slot's notes: whatever is still pending when it drops (a cancelled
/// call) is written on a spawned task through the bounded append.
pub(super) struct SlotGuard {
    pub(super) slot: Arc<Slot>,
    pub(super) logger: Arc<TransparencyLogger>,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        // invariant: nothing panics while holding the slot lock, so it is never poisoned.
        let pending = std::mem::take(&mut *self.slot.notes.lock().expect("grant slot lock"));
        // invariant: nothing panics while holding the slot lock, so it is never poisoned.
        let best_effort =
            std::mem::take(&mut *self.slot.best_effort.lock().expect("grant slot lock"));
        if !pending.is_empty() || !best_effort.is_empty() {
            spawn_write(&self.logger, pending, best_effort);
        }
    }
}

/// Write `notes`, then `best_effort` notes, on one spawned task, bounded;
/// never on the caller's thread. A failed best-effort write only warns.
pub(super) fn spawn_write(
    logger: &Arc<TransparencyLogger>,
    notes: Vec<GrantNote>,
    best_effort: Vec<GrantNote>,
) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        tracing::error!(
            count = notes.len() + best_effort.len(),
            "grant decision records lost: no runtime to write them"
        );
        return;
    };
    let logger = Arc::clone(logger);
    #[cfg(test)]
    let in_flight = seams::write_spawned(&logger);
    handle.spawn(async move {
        // Off the count when the task ends, panics or is cancelled.
        #[cfg(test)]
        let _in_flight = in_flight;
        if !notes.is_empty()
            && let Err(error) = write_records(&logger, &notes).await
        {
            tracing::error!(%error, "grant decision records could not be written");
        }
        if !best_effort.is_empty() {
            #[cfg(test)]
            seams::at_best_effort_start().await;
            let server = best_effort.first().map(|note| note.server.clone());
            if let Err(error) = write_records(&logger, &best_effort).await {
                tracing::warn!(server = server.as_deref(), %error, "{WITHHELD_RECORD_FAILED}");
            }
        }
    });
}

/// Append one record per selected note, bounded (F20). Every record is
/// attempted; the first failure is reported after the batch.
pub(super) async fn write_records(
    logger: &Arc<TransparencyLogger>,
    notes: &[GrantNote],
) -> std::io::Result<()> {
    #[cfg(test)]
    seams::at_write_start().await;
    let mut first_failure = None;
    for note in select_records(notes) {
        // Held across the append: check, write and remember are one step.
        // The wait and the append share one deadline, so a queue of re-checks
        // behind slow writes fails like a slow append does (F20).
        let started = tokio::time::Instant::now();
        let deadline = LEDGER_WAIT;
        let mut ledger = None;
        if let Some(mark) = &note.repeat {
            let Ok(guard) = tokio::time::timeout(deadline, mark.store.0.lock()).await else {
                first_failure.get_or_insert(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "grant decision record timed out waiting for its repeat check",
                ));
                continue;
            };
            ledger = Some(guard);
        }
        let now = Instant::now();
        if let (Some(mark), Some(ledger)) = (&note.repeat, &ledger)
            && ledger.is_repeat(&mark.key, &mark.decision, now)
        {
            continue;
        }
        let (mut fields, envelope) = (note.fields.clone(), note.envelope());
        let judge = note.clone();
        // Only a re-check shares its wait with the append; any other record
        // keeps the log's own bounds unchanged.
        let cap = note
            .repeat
            .as_ref()
            .map(|_| deadline.saturating_sub(started.elapsed()));
        #[cfg(test)]
        if seams::fail_this_append(note) {
            first_failure.get_or_insert(std::io::Error::other("injected append failure"));
            continue;
        }
        let written = logger
            .append_bounded_within(cap, move |log| {
                // Read here, in the append op: appends are serialized, so every
                // earlier invocation append has finished and recorded itself.
                let recorded = judge.invocation_recorded();
                fields.insert("invocation_recorded".into(), recorded.into());
                log.append_event(fields, &envelope).map(|_| ())
            })
            .await;
        match written {
            // Remembered only once written: a failed write suppresses nothing.
            Ok(()) => {
                if let (Some(mark), Some(ledger)) = (&note.repeat, ledger.as_mut()) {
                    ledger.remember(mark.key.clone(), mark.decision.clone(), now);
                }
            }
            Err(error) => {
                first_failure.get_or_insert(error);
            }
        }
    }
    first_failure.map_or(Ok(()), Err)
}
