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
    /// Keys awaiting reclamation, and the deadline each is reclaimed at.
    ///
    /// MCP 2026-07-28 removed protocol sessions, so `on_disconnect` has nothing
    /// left to fire on: there is no session to DELETE, and the stream whose
    /// close drove the other trigger is replaced by `subscriptions/listen`.
    /// Every handler registered here would simply never run, and everything it
    /// reclaimed would leak — in silence, because nothing errors when a
    /// callback is not called.
    ///
    /// So the trigger becomes a deadline. The handlers are unchanged; what
    /// changes is that something still fires them.
    tracked: RwLock<std::collections::HashMap<String, u64>>,
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
    ///
    /// **Precondition (D5):** `reap` is unconditional — it fires a handler even
    /// while a request for the same key is in flight, because no lock protects
    /// a key between `track` and its deadline. A registered handler may
    /// therefore only reclaim state whose loss is indistinguishable from an
    /// eviction the caller's own bookkeeping already tolerates (a cache entry,
    /// a `DashMap` slot rebuilt on next use) — never state a live request
    /// depends on to complete correctly.
    pub fn register(
        &self,
        name: impl Into<String>,
        callback: impl Fn(&str) + Send + Sync + 'static,
    ) {
        self.callbacks
            .write()
            .push((name.into(), Arc::new(Box::new(callback))));
    }

    /// Fire all registered callbacks for the given session ID.
    ///
    /// Called by the notification multiplexer when a session is reaped
    /// or by the DELETE /mcp handler.
    pub fn on_disconnect(&self, session_id: &str) {
        // Whatever brought us here, this key is done: drop its deadline so a
        // later reap cannot fire the handlers for it a second time.
        self.untrack(session_id);
        self.fire_cleanup(session_id);
    }

    /// Run the cleanup handlers for a key whose deadline is already gone.
    ///
    /// Separate from [`Self::on_disconnect`] because reaping has **already**
    /// removed the key. Removing it a second time cannot remove the entry
    /// reaping took — that one is gone — so the only thing a second removal can
    /// delete is a deadline some other caller re-registered in between, taking
    /// a live caller's state with it.
    ///
    /// **Residual, stated rather than implied**: a key re-tracked between
    /// reaping's removal and this call still has its handlers fired, because
    /// nothing holds the two together. Closing that needs the ownership model
    /// this module does not yet have — it is not reached from production at all
    /// (MIK-7291), and the fix belongs with the decision to wire it.
    fn fire_cleanup(&self, session_id: &str) {
        let cbs = self.callbacks.read();
        if cbs.is_empty() {
            return;
        }
        debug!(
            session_id,
            callbacks = cbs.len(),
            "Session disconnect cleanup"
        );
        for (name, cb) in cbs.iter() {
            cb(session_id);
            debug!(session_id, handler = %name, "Cleanup handler executed");
        }
    }

    /// Note that `key` is reclaimable once `expires_at` has passed.
    ///
    /// The key is whatever the caller is identified by — a principal after the
    /// migration, a session before it. The handlers do not care which; they
    /// care that something eventually names the key again.
    /// One deadline per key, replaced rather than accumulated. Appending a
    /// second deadline for a key already tracked kept the older one, so a
    /// refreshed caller was reclaimed on its previous deadline while still
    /// live — and the handlers, which free things, ran twice for one key.
    pub fn track(&self, key: impl Into<String>, expires_at: u64) {
        self.tracked.write().insert(key.into(), expires_at);
    }

    /// Stop tracking a key that has already been reclaimed.
    ///
    /// Without this a disconnect leaves the deadline behind, and the next reap
    /// fires the handlers again for a key that is already gone.
    pub fn untrack(&self, key: &str) {
        self.tracked.write().remove(key);
    }

    /// Reclaim every tracked key whose deadline has passed, and report how
    /// many were reclaimed.
    ///
    /// Each key fires the handlers exactly once and is then forgotten: these
    /// callbacks free things, and a handler that runs twice for one key is its
    /// own defect. The count is the keys removed, not the keys examined, so a
    /// caller logging a sweep can tell an idle sweep from a busy one.
    pub fn reap(&self, now: u64) -> usize {
        let expired: Vec<String> = {
            let mut tracked = self.tracked.write();
            let expired: Vec<String> = tracked
                .iter()
                .filter(|(_, expires_at)| now > **expires_at)
                .map(|(key, _)| key.clone())
                .collect();
            for key in &expired {
                tracked.remove(key);
            }
            expired
        };
        let reclaimed = expired.len();
        for key in expired {
            // Already removed above. `on_disconnect` would remove it again, and
            // a second removal can only take an entry someone re-registered.
            self.fire_cleanup(&key);
        }
        reclaimed
    }

    /// How many keys are awaiting reclamation.
    pub fn tracked_count(&self) -> usize {
        self.tracked.read().len()
    }

    /// Number of registered callbacks (for diagnostics).
    pub fn handler_count(&self) -> usize {
        self.callbacks.read().len()
    }
}

/// Idle deadline written by a tracking write site: `now + IDLE_TTL`.
///
/// 300s, matching the shipped `PER_USER_IDLE_TTL`
/// (`gateway/server/mod.rs`). A STATED ASSUMPTION (MIK-7215 CONTROL.4,
/// team-lead ruling 2026-09-07/R3): no cadence knob is added beside it —
/// reaping rides the host loop's own `session_reaper_interval`, so a second
/// interval constant here would have no reader.
pub const IDLE_TTL: u64 = 300;

/// Build the one production `SessionLifecycle` and register its one real
/// consumer today, `Firewall::on_session_end`.
///
/// The single named function startup and tests both call (MIK-7215
/// CONTROL.4 D8): a test that registers its own handler instead of calling
/// this would prove a fixture, not the wiring. `firewall` is `None` when the
/// firewall is disabled or the feature build has none configured — the
/// lifecycle is still created (the host reaper always runs), it simply has
/// nothing to fire.
///
/// The callback captures `firewall` as `Weak`: the handle this function
/// returns is stored on `AppState` beside `firewall` itself, and a strong
/// `Arc` inside the callback would close a reference cycle through the state
/// that owns both.
#[cfg(feature = "firewall")]
pub fn wire_session_lifecycle(
    firewall: Option<&Arc<crate::security::firewall::Firewall>>,
) -> Arc<SessionLifecycle> {
    let lifecycle = Arc::new(SessionLifecycle::new());
    if let Some(fw) = firewall {
        let weak = Arc::downgrade(fw);
        lifecycle.register("firewall_anomaly_cleanup", move |session_id| {
            if let Some(fw) = weak.upgrade() {
                fw.on_session_end(session_id);
            }
        });
    }
    lifecycle
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn a_refreshed_key_keeps_only_its_latest_deadline() {
        // Tracking the same key twice used to keep both deadlines. The older
        // one then reclaimed a caller that was still live, and the handlers —
        // which free things — ran twice for one key.
        let lifecycle = SessionLifecycle::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&fired);
        lifecycle.register("test", move |_key| {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        lifecycle.track("caller-a", 100);
        lifecycle.track("caller-a", 200);
        assert_eq!(
            lifecycle.tracked_count(),
            1,
            "one key must hold one deadline, not one per refresh"
        );

        lifecycle.reap(150);
        assert_eq!(
            fired.load(Ordering::SeqCst),
            0,
            "a refreshed caller must not be reclaimed on its previous deadline"
        );
        assert_eq!(lifecycle.tracked_count(), 1, "and must still be tracked");

        lifecycle.reap(250);
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "past its real deadline it is reclaimed exactly once"
        );
    }

    #[test]
    fn a_disconnect_drops_the_deadline_so_reaping_cannot_repeat_it() {
        let lifecycle = SessionLifecycle::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&fired);
        lifecycle.register("test", move |_key| {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        lifecycle.track("caller-b", 100);
        lifecycle.on_disconnect("caller-b");
        assert_eq!(fired.load(Ordering::SeqCst), 1);

        lifecycle.reap(200);
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "a key already reclaimed must not be reclaimed again by a later reap"
        );
    }

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
