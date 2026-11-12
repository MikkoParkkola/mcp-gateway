// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Finish observations are emitted only after real operations, never by stubs.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::JournalV2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Event {
    OriginalUnlinked,
    JournalUnlinked,
    DirectorySynced,
    BStarted,
    BInvalid,
    IntentAppended,
    FlagSynced,
    RestoreVerified,
    ForwardVerified,
    BeforeAttemptPersist,
    AttemptPersisted,
    BeforeDecisionSync,
    DecisionPersisted,
    DecisionComputed,
    DecisionProposed,
    OutcomeAppended,
    DeferredFlagged,
    #[cfg(unix)]
    AfterTornWrite,
    RepairPaused,
}

#[derive(Default)]
struct Trace {
    events: Vec<Event>,
    tokens: BTreeSet<String>,
}

static EVENTS: Mutex<Option<HashMap<PathBuf, Trace>>> = Mutex::new(None);

pub(super) struct Watching(PathBuf);

pub(super) fn watch(target: &Path) -> Watching {
    EVENTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get_or_insert_with(HashMap::new)
        .insert(target.to_path_buf(), Trace::default());
    Watching(target.to_path_buf())
}

pub(super) fn note(target: &Path, event: Event) {
    if let Some(events) = EVENTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_mut()
        .and_then(|events| events.get_mut(target))
    {
        events.events.push(event);
    }
}

pub(super) fn events(target: &Path) -> Vec<Event> {
    EVENTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .and_then(|events| events.get(target).map(|trace| trace.events.clone()))
        .unwrap_or_default()
}

impl Drop for Watching {
    fn drop(&mut self) {
        if let Some(events) = EVENTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
        {
            events.remove(&self.0);
        }
    }
}

/// Capture tokens from the proposed in-memory owner before any journal write.
/// This inventory is independent of whatever survives in the journal or log.
pub(super) fn plan_tokens(target: &Path, state: &JournalV2) {
    if let Some(trace) = EVENTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_mut()
        .and_then(|events| events.get_mut(target))
    {
        for owner in state.writer.iter().chain(&state.attempts) {
            trace.tokens.insert(owner.intent_id.0.clone());
        }
    }
}

pub(super) fn tokens(target: &Path) -> Vec<String> {
    EVENTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .and_then(|events| {
            events
                .get(target)
                .map(|trace| trace.tokens.iter().cloned().collect())
        })
        .unwrap_or_default()
}

/// Call at entry to decision computation, before consulting recovery inputs.
/// The future repair implementation must call this even if it recomputes an
/// equal decision. Neither fixtures nor the current stubs manufacture the event.
pub(super) fn decision_computing(target: &Path) {
    note(target, Event::DecisionComputed);
}
