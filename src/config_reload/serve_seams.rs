// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only stops on a served start, keyed by the config path the startup gate checked: a row
//! arms one, and the serve load or the construction runs it when it reaches that point. Each call
//! site is gated `#[cfg(test)]`; nothing here exists in a product build.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

/// Where a served start can stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Point {
    /// The startup gate has checked the config; the config is not loaded yet.
    AfterPrepare,
    /// Construction has opened the serving log; the startup session is not finished yet.
    AfterServingOpen,
}

type Action = Arc<dyn Fn() + Send + Sync>;

static ARMED: Mutex<Option<HashMap<(PathBuf, Point), Action>>> = Mutex::new(None);

/// Disarms its stop when dropped.
pub(crate) struct Armed(PathBuf, Point);

impl Drop for Armed {
    fn drop(&mut self) {
        if let Some(armed) = ARMED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
        {
            armed.remove(&(self.0.clone(), self.1));
        }
    }
}

/// Run `action` when a served start for `config` reaches `point`.
pub(crate) fn arm(config: &Path, point: Point, action: impl Fn() + Send + Sync + 'static) -> Armed {
    ARMED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get_or_insert_with(HashMap::new)
        .insert((config.to_path_buf(), point), Arc::new(action));
    Armed(config.to_path_buf(), point)
}

/// Called at the point itself; runs the armed action, if any, outside the registry lock.
pub(crate) fn reached(config: &Path, point: Point) {
    let action = ARMED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .and_then(|armed| armed.get(&(config.to_path_buf(), point)).cloned());
    if let Some(action) = action {
        action();
    }
}
