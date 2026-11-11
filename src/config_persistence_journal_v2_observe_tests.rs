// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Finish observations are emitted only after real operations, never by stubs.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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
    AttemptPersisted,
    DecisionPersisted,
    OutcomeAppended,
    DeferredFlagged,
    AfterTornWrite,
    RepairPaused,
}

static EVENTS: Mutex<Option<HashMap<PathBuf, Vec<Event>>>> = Mutex::new(None);

pub(super) struct Watching(PathBuf);

pub(super) fn watch(target: &Path) -> Watching {
    EVENTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get_or_insert_with(HashMap::new)
        .insert(target.to_path_buf(), Vec::new());
    Watching(target.to_path_buf())
}

pub(super) fn note(target: &Path, event: Event) {
    if let Some(events) = EVENTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_mut()
        .and_then(|events| events.get_mut(target))
    {
        events.push(event);
    }
}

pub(super) fn events(target: &Path) -> Vec<Event> {
    EVENTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .and_then(|events| events.get(target).cloned())
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
