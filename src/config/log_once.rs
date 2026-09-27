// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Load-time log lines that must not repeat on every reload (#1286).
//!
//! A failed reload is retried every poll, and every retry loads and
//! validates the config again, so a line logged per load would repeat every
//! 2 seconds for as long as the config stays broken.

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
