// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Session lifecycle callbacks for per-identity state cleanup.
//!
//! Features like cost governance, firewall anomaly detection, tool profiles,
//! and semantic search feedback maintain per-caller state in `DashMap`s that
//! nothing reclaims on its own. This type is the reusable registry for that:
//! register a cleanup callback, track a key with a deadline, and either an
//! explicit disconnect or a periodic reap fires the callback once.
//!
//! It is **not** a single app-wide instance — each owner that needs cleanup
//! holds and arms its own `SessionLifecycle`, the way [`Firewall`] does for
//! its anomaly detector (MIK-7215.CONTROL.4). Cost governance, tool
//! profiles, and semantic search do not have one wired yet; the type is
//! ready for them, the wiring is not done.
//!
//! [`Firewall`]: crate::security::firewall::Firewall

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    /// nothing holds the two together. Now that `Firewall` wires this
    /// (MIK-7215.CONTROL.4) the race IS reachable — a request that lands
    /// between `reap`'s removal and this fire re-tracks the key and then has
    /// its callback run anyway, wiping a live caller's anomaly baseline one
    /// call early. Accepted for now: the effect is one unscored call, not a
    /// correctness or security failure, and closing it needs the ownership
    /// model this module does not yet have.
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

    /// Reclaim every tracked key whose deadline has passed.
    ///
    /// Each key fires the handlers exactly once and is then forgotten: these
    /// callbacks free things, and a handler that runs twice for one key is its
    /// own defect.
    pub fn reap(&self, now: u64) {
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
        for key in expired {
            // Already removed above. `on_disconnect` would remove it again, and
            // a second removal can only take an entry someone re-registered.
            self.fire_cleanup(&key);
        }
    }

    /// How many keys are awaiting reclamation.
    pub fn tracked_count(&self) -> usize {
        self.tracked.read().len()
    }

    /// Number of registered callbacks (for diagnostics).
    pub fn handler_count(&self) -> usize {
        self.callbacks.read().len()
    }

    /// Track `key`, reclaimable `ttl` after now.
    ///
    /// Epoch math lives here, next to [`Self::reap`], rather than duplicated
    /// at each caller — the repo's convention of inlining
    /// `SystemTime::now().duration_since(UNIX_EPOCH)` per call site is fine
    /// when there is one call site; a lifecycle registry is exactly the
    /// place that should not be one of several.
    pub fn track_for(&self, key: impl Into<String>, ttl: Duration) {
        self.track(key, now_secs().saturating_add(ttl.as_secs()));
    }

    /// Reclaim every tracked key whose deadline has passed, as of now.
    ///
    /// Convenience over [`Self::reap`] for callers that always mean
    /// wall-clock now — a periodic reaper task, not a test proving a
    /// specific deadline.
    pub fn reap_now(&self) {
        self.reap(now_secs());
    }
}

/// Seconds since the Unix epoch, saturating rather than panicking on a clock
/// set before 1970 — a reclaim deadline that reads as "already due" is the
/// safe failure, an unwrap panic taking the process down is not.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
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

    #[test]
    fn track_for_expires_relative_to_now_not_to_zero() {
        // A ttl is a duration from now, not an absolute deadline — track_for
        // must add now_secs(), not just forward the ttl as the deadline.
        let lifecycle = SessionLifecycle::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&fired);
        lifecycle.register("test", move |_key| {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        lifecycle.track_for("caller", Duration::from_secs(3600));
        lifecycle.reap_now();
        assert_eq!(
            fired.load(Ordering::SeqCst),
            0,
            "an hour-long ttl tracked seconds ago must not be reclaimed by reap_now"
        );
        assert_eq!(lifecycle.tracked_count(), 1);
    }

    #[test]
    fn reap_now_reclaims_a_zero_ttl_key() {
        let lifecycle = SessionLifecycle::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&fired);
        lifecycle.register("test", move |_key| {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        lifecycle.track("caller", 0); // deadline in the deep past
        lifecycle.reap_now();
        assert_eq!(fired.load(Ordering::SeqCst), 1);
    }
}
