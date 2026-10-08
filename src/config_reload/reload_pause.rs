// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only pause point inside a reload (MIK-8042 R6).
//!
//! A test arms a pause for one config path; the next reload of that path
//! signals `reached` once it has written and is about to read the file back,
//! then waits for `release`. That holds a writer inside its critical section
//! for exactly as long as the test needs to start a contender, with no
//! sleeps.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};

use tokio::sync::Notify;

/// One armed pause.
#[derive(Default)]
pub(crate) struct Pause {
    /// Notified when a reload reaches the pause point.
    pub(crate) reached: Notify,
    /// Notify to let the paused reload continue.
    pub(crate) release: Notify,
}

static PAUSES: LazyLock<Mutex<HashMap<PathBuf, Arc<Pause>>>> = LazyLock::new(Default::default);

/// Arm a one-shot pause for the next reload of `path`.
pub(crate) fn arm(path: &Path) -> Arc<Pause> {
    let pause = Arc::new(Pause::default());
    PAUSES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(path.to_path_buf(), Arc::clone(&pause));
    pause
}

/// Called at the start of a reload: waits there if a pause is armed for
/// `path`, and disarms it.
pub(crate) async fn pause_here(path: &Path) {
    let pause = PAUSES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(path);
    if let Some(pause) = pause {
        pause.reached.notify_one();
        pause.release.notified().await;
    }
}
