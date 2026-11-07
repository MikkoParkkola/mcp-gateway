// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The byte writer's test-only step record, keyed by target.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

type Hook = Arc<dyn Fn() + Send + Sync>;

static EVENTS: Mutex<Vec<(PathBuf, &'static str)>> = Mutex::new(Vec::new());
static HOOKS: Mutex<Vec<(PathBuf, &'static str, Hook)>> = Mutex::new(Vec::new());

/// Records `event` and runs the hooks registered for it, on the writer's
/// own thread.
pub(super) fn record(target: &Path, event: &'static str) {
    EVENTS
        .lock()
        .expect("order")
        .push((target.to_path_buf(), event));
    let due: Vec<Hook> = HOOKS
        .lock()
        .expect("hooks")
        .iter()
        .filter(|(p, e, _)| p == target && *e == event)
        .map(|(_, _, hook)| Arc::clone(hook))
        .collect();
    for hook in due {
        hook();
    }
}

/// Runs `hook` when the writer records `event` for `target`, until the
/// target's events are taken.
#[cfg(feature = "webui")]
pub(crate) fn on(target: &Path, event: &'static str, hook: Hook) {
    HOOKS
        .lock()
        .expect("hooks")
        .push((target.to_path_buf(), event, hook));
}

/// The events recorded for `target`, in order, cleared with its hooks.
#[cfg(feature = "webui")]
pub(crate) fn take(target: &Path) -> Vec<&'static str> {
    HOOKS.lock().expect("hooks").retain(|(p, _, _)| p != target);
    let mut all = EVENTS.lock().expect("order");
    let mine = all
        .iter()
        .filter(|(p, _)| p == target)
        .map(|(_, e)| *e)
        .collect();
    all.retain(|(p, _)| p != target);
    mine
}
