// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Session lifecycle callbacks for per-session state cleanup.
//!
//! Features like cost governance, firewall anomaly detection, tool profiles,
//! and semantic search feedback maintain per-session state in `DashMap`s.
//! This module provides a central registry so all such state is cleaned up
//! when a session disconnects.

use std::sync::Arc;

use parking_lot::RwLock;
use tracing::debug;

type CleanupFn = Box<dyn Fn(&str) + Send + Sync>;

/// Registry of session disconnect callbacks.
///
/// Register cleanup handlers during gateway startup; they fire automatically
/// when a session transport closes (SSE disconnect or DELETE /mcp).
#[derive(Default)]
pub struct SessionLifecycle {
    callbacks: RwLock<Vec<(String, Arc<CleanupFn>)>>,
}

impl SessionLifecycle {
    /// Create a new empty lifecycle registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a named cleanup callback.
    ///
    /// The callback receives the session ID string when a session disconnects.
    /// Name is used for debug logging only.
    pub fn register(&self, name: impl Into<String>, callback: impl Fn(&str) + Send + Sync + 'static) {
        self.callbacks
            .write()
            .push((name.into(), Arc::new(Box::new(callback))));
    }

    /// Fire all registered callbacks for the given session ID.
    ///
    /// Called by the notification multiplexer when a session is reaped
    /// or by the DELETE /mcp handler.
    pub fn on_disconnect(&self, session_id: &str) {
        let cbs = self.callbacks.read();
        if cbs.is_empty() {
            return;
        }
        debug!(session_id, callbacks = cbs.len(), "Session disconnect cleanup");
        for (name, cb) in cbs.iter() {
            cb(session_id);
            debug!(session_id, handler = %name, "Cleanup handler executed");
        }
    }

    /// Number of registered callbacks (for diagnostics).
    pub fn handler_count(&self) -> usize {
        self.callbacks.read().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_callback_fires_on_disconnect() {
        let lifecycle = SessionLifecycle::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);
        lifecycle.register("test", move |_sid| {
            c.fetch_add(1, Ordering::SeqCst);
        });

        lifecycle.on_disconnect("session-123");
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        // Multiple disconnects increment
        lifecycle.on_disconnect("session-456");
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_multiple_callbacks() {
        let lifecycle = SessionLifecycle::new();
        let counter = Arc::new(AtomicUsize::new(0));

        for i in 0..3 {
            let c = Arc::clone(&counter);
            lifecycle.register(format!("handler-{i}"), move |_sid| {
                c.fetch_add(1, Ordering::SeqCst);
            });
        }

        lifecycle.on_disconnect("sess-1");
        assert_eq!(counter.load(Ordering::SeqCst), 3);
        assert_eq!(lifecycle.handler_count(), 3);
    }

    #[test]
    fn test_receives_correct_session_id() {
        let lifecycle = SessionLifecycle::new();
        let captured = Arc::new(RwLock::new(String::new()));
        let c = Arc::clone(&captured);
        lifecycle.register("id-check", move |sid| {
            *c.write() = sid.to_string();
        });

        lifecycle.on_disconnect("abc-def-123");
        assert_eq!(*captured.read(), "abc-def-123");
    }

    #[test]
    fn test_empty_lifecycle_is_noop() {
        let lifecycle = SessionLifecycle::new();
        lifecycle.on_disconnect("no-handlers"); // should not panic
        assert_eq!(lifecycle.handler_count(), 0);
    }
}
