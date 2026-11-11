// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Fault registration is separate from firing at a real operation boundary.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use super::super::observe::{self, Event};
use super::super::{JournalError, JournalV2};
use crate::config_persistence::crash_fs::{self, Mode};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum At {
    AttemptPersisted,
    IntentAppended,
    BeforeDecisionSync,
    DecisionPersisted,
    OutcomeAppended,
    DeferredFlagged,
    AfterTornWrite,
    RepairPaused,
}

#[derive(Clone)]
pub(super) enum Fault {
    Kill(At),
    Cut(At, Mode),
    Fail(At),
    Pause(Arc<Pause>),
}

struct Entry {
    fault: Fault,
    fired: usize,
}

static FAULTS: Mutex<Option<HashMap<PathBuf, Entry>>> = Mutex::new(None);

pub(super) struct Armed(PathBuf);

pub(super) fn arm(path: &Path, fault: Fault) -> Armed {
    FAULTS
        .lock()
        .expect("fault registry")
        .get_or_insert_with(HashMap::new)
        .insert(path.to_path_buf(), Entry { fault, fired: 0 });
    Armed(path.to_path_buf())
}

pub(super) fn fired(path: &Path) -> usize {
    FAULTS
        .lock()
        .expect("fault registry")
        .as_ref()
        .and_then(|entries| entries.get(path))
        .map_or(0, |entry| entry.fired)
}

/// Called by real implementation boundaries; neither arming nor a stub calls it.
pub(super) fn hit(path: &Path, at: At) -> Result<(), JournalError> {
    let fault = {
        let mut entries = FAULTS.lock().expect("fault registry");
        let Some(entry) = entries.as_mut().and_then(|entries| entries.get_mut(path)) else {
            return Ok(());
        };
        let matches = match &entry.fault {
            Fault::Kill(want) | Fault::Cut(want, _) | Fault::Fail(want) => *want == at,
            Fault::Pause(_) => at == At::RepairPaused,
        };
        if !matches || entry.fired != 0 {
            return Ok(());
        }
        entry.fired += 1;
        entry.fault.clone()
    };
    observe::note(path, event(at));
    match fault {
        Fault::Kill(_) => {
            let captured = serde_json::to_vec(&capture(path)).expect("pre-kill inventory");
            std::fs::write(path.with_extension("s6a2-seam"), captured).expect("crash seam witness");
            std::process::abort();
        }
        Fault::Cut(_, mode) => {
            let captured = capture(path);
            crash_fs::cut(path.parent().expect("target directory"), mode);
            std::panic::resume_unwind(Box::new(captured))
        }
        Fault::Fail(_) => Err(JournalError::Persist),
        Fault::Pause(pause) => {
            pause.enter();
            Ok(())
        }
    }
}

pub(super) fn event(at: At) -> Event {
    match at {
        At::AttemptPersisted => Event::AttemptPersisted,
        At::IntentAppended => Event::IntentAppended,
        At::BeforeDecisionSync => Event::BeforeDecisionSync,
        At::DecisionPersisted => Event::DecisionPersisted,
        At::OutcomeAppended => Event::OutcomeAppended,
        At::DeferredFlagged => Event::DeferredFlagged,
        At::AfterTornWrite => Event::AfterTornWrite,
        At::RepairPaused => Event::RepairPaused,
    }
}

impl Drop for Armed {
    fn drop(&mut self) {
        if let Some(entry) = FAULTS
            .lock()
            .expect("fault registry")
            .as_mut()
            .and_then(|entries| entries.remove(&self.0))
            && let Fault::Pause(pause) = entry.fault
        {
            pause.release();
        }
    }
}

#[derive(Default)]
pub(super) struct Pause {
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}

impl Pause {
    fn enter(&self) {
        let mut state = self.state.lock().expect("pause");
        state.0 = true;
        self.changed.notify_all();
        while !state.1 {
            state = self.changed.wait(state).expect("pause");
        }
    }

    pub(super) fn entered(&self) -> bool {
        let (state, _) = self
            .changed
            .wait_timeout_while(
                self.state.lock().expect("pause"),
                Duration::from_secs(2),
                |state| !state.0,
            )
            .expect("pause deadline");
        state.0
    }

    pub(super) fn release(&self) {
        self.state.lock().expect("pause").1 = true;
        self.changed.notify_all();
    }
}

/// Inject only after the atomic replacement and before the real directory sync.
pub(crate) fn before_decision_sync(path: &Path, state: &JournalV2) -> Result<(), JournalError> {
    decision_boundary(path, state, At::BeforeDecisionSync)
}

/// D3 is reached only after the replacement's directory sync succeeds.
pub(crate) fn after_decision_sync(path: &Path, state: &JournalV2) -> Result<(), JournalError> {
    decision_boundary(path, state, At::DecisionPersisted)
}

fn decision_boundary(path: &Path, state: &JournalV2, at: At) -> Result<(), JournalError> {
    let decided = state.writer.as_ref().is_none_or(|w| w.decision.is_some())
        && state.attempts.iter().all(|a| a.decision.is_some());
    if decided && (state.writer.is_some() || !state.attempts.is_empty()) {
        hit(path, at)?;
    }
    Ok(())
}

/// Pre-cut evidence travels outside the projected filesystem state.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct Captured {
    pub(super) tokens: Vec<String>,
    pub(super) computations: usize,
}

fn capture(path: &Path) -> Captured {
    Captured {
        tokens: observe::tokens(path),
        computations: observe::events(path)
            .iter()
            .filter(|event| **event == Event::DecisionComputed)
            .count(),
    }
}
