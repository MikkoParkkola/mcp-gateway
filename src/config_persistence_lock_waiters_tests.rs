// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Existing lock-waiter observations, compiled only for tests.

use std::path::{Path, PathBuf};

/// How many callers have found `lock` held and are waiting on it: the seam a
/// test uses to know its racers reached the lock. Red-first stub.
#[cfg(all(test, feature = "webui"))]
pub(crate) fn waiters_for_test(lock: &Path) -> usize {
    waiters()
        .lock()
        .map_or(0, |w| w.get(lock).copied().unwrap_or(0))
}

/// Process-wide, not per thread: the racers a test counts run on workers.
#[cfg(test)]
fn waiters() -> &'static std::sync::Mutex<std::collections::HashMap<PathBuf, usize>> {
    static WAITERS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<PathBuf, usize>>,
    > = std::sync::OnceLock::new();
    WAITERS.get_or_init(Default::default)
}

/// Counts one waiter on its lock while it lives, from the first time the
/// lock is found held.
#[cfg(test)]
#[derive(Default)]
pub(super) struct Waiting(Option<PathBuf>);

#[cfg(test)]
impl Waiting {
    pub(super) fn start(&mut self, lock: &Path) {
        if self.0.is_none() {
            if let Ok(mut w) = waiters().lock() {
                *w.entry(lock.to_path_buf()).or_insert(0) += 1;
            }
            self.0 = Some(lock.to_path_buf());
        }
    }
}

#[cfg(test)]
impl Drop for Waiting {
    fn drop(&mut self) {
        if let Some(lock) = &self.0
            && let Ok(mut w) = waiters().lock()
            && let Some(n) = w.get_mut(lock)
        {
            *n = n.saturating_sub(1);
        }
    }
}
