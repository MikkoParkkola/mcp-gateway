// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Load-time log lines that must not repeat on every reload (#1286).
//!
//! A failed reload is retried every poll, and every retry loads and
//! validates the config again, so a line logged per load would repeat every
//! 2 seconds for as long as the config stays broken.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};

use super::Evaluated;

/// Whether the port-0 warning has been logged in this process.
pub(super) static PORT_ZERO_WARNED: AtomicBool = AtomicBool::new(false);

/// Warn that port 0 asks the OS for an ephemeral port, once per `warned`.
/// The bound port only changes on a restart, so once per process is enough.
pub(super) fn warn_port_zero(port: u16, warned: &AtomicBool) {
    if port == 0 && !warned.swap(true, Ordering::Relaxed) {
        tracing::warn!("Server port is 0; OS will assign an ephemeral port");
    }
}

/// Whether `key` is logged for the first time in this process. For advisory
/// warnings about config content: the same config re-read on every retried
/// reload stays quiet, and a changed config (a new key) warns again.
// ponytail: one process-wide set, grows only with distinct advisories in the
// configs this process loaded; bound it if configs are generated per request.
pub(crate) fn first_time(key: &str) -> bool {
    static LOGGED: std::sync::Mutex<Option<HashSet<String>>> = std::sync::Mutex::new(None);
    let mut logged = LOGGED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    logged
        .get_or_insert_with(HashSet::new)
        .insert(key.to_owned())
}

impl Evaluated {
    /// Log the resolved env files once, at startup. Each file's own load line
    /// is DEBUG, because reloads repeat it.
    pub(super) fn log_env_files(&self) {
        if !self.env_paths.as_paths().is_empty() {
            tracing::info!(env_files = ?self.env_paths.as_paths(), "Env files resolved");
        }
    }
}

#[cfg(test)]
#[path = "log_once_tests.rs"]
mod tests;
