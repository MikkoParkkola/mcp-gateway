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
    /// Handlers for state keyed by a *session id*. They fire only when a
    /// session really ends ([`Self::on_disconnect`]), never from the idle
    /// deadline: a session quiet for [`IDLE_TTL`] is still a live session, and
    /// reclaiming its profile or workflow state would silently reset it.
    ended: RwLock<Vec<(String, Arc<CleanupFn>)>>,
    /// Ids whose session-end handlers fire a second time at the given Unix
    /// second. A call already in flight when its session ended can write state
    /// under the dead id after the first pass; the second pass, one
    /// [`END_GRACE`] later, takes what it left. Without it a client looping
    /// create, long call, DELETE grows the stores by one entry per round.
    ended_pending: RwLock<Vec<(String, u64)>>,
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

/// How long after a session ends its in-flight calls may still write state
/// under its id. Longer than the backend request timeout, so a call that began
/// before the end has finished by the second cleanup pass.
pub const END_GRACE: std::time::Duration = std::time::Duration::from_secs(120);

/// How long an identity's derived state outlives its last observed request.
///
/// The revision removed protocol sessions, so nothing signals a disconnect and
/// the only honest question left is "has this identity been quiet long enough".
/// Five minutes is the answer the reclaim-latency bound in the design is stated
/// against: a caller idle this long has its per-identity state reclaimed, and a
/// caller still working keeps pushing its deadline forward.
pub const IDLE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// Seconds since the Unix epoch, the unit every deadline in this module uses.
///
/// One helper so the seam between this module's `u64` seconds and callers that
/// think in `Instant` is crossed in exactly one place. A clock set backwards
/// delays a reclaim and one set forwards reclaims early; both touch derived
/// state only, which is why wall-clock is acceptable here and a monotonic
/// `Instant` — unloggable, unpersistable, uncomparable across a restart — is
/// not.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
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

    /// Register a handler for state keyed by a session id. It fires on a real
    /// session end only; see the `ended` field for why not on idle reclaim.
    pub fn register_session_end(
        &self,
        name: impl Into<String>,
        callback: impl Fn(&str) + Send + Sync + 'static,
    ) {
        self.ended
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
        self.fire_ended(session_id);
        self.ended_pending
            .write()
            .push((session_id.to_owned(), now_unix() + END_GRACE.as_secs()));
    }

    /// Run the session-end handlers for `session_id`.
    fn fire_ended(&self, session_id: &str) {
        for (name, cb) in self.ended.read().iter() {
            cb(session_id);
            debug!(
                session_id = %crate::gateway::session_id::session_fp(session_id),
                handler = %name,
                "Session-end handler executed"
            );
        }
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
        let fp = crate::gateway::session_id::session_fp(session_id);
        debug!(
            session_id = %fp,
            callbacks = cbs.len(),
            "Session disconnect cleanup"
        );
        for (name, cb) in cbs.iter() {
            cb(session_id);
            debug!(session_id = %fp, handler = %name, "Cleanup handler executed");
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
        // The second pass for sessions that ended a grace period ago.
        let due: Vec<String> = {
            let mut pending = self.ended_pending.write();
            let (due, later): (Vec<_>, Vec<_>) = pending.drain(..).partition(|(_, at)| now > *at);
            *pending = later;
            due.into_iter().map(|(id, _)| id).collect()
        };
        for id in due {
            self.fire_ended(&id);
        }
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

/// Register the firewall's per-identity cleanup with a lifecycle registry.
///
/// Held as a `Weak`, never an `Arc`: the registry outlives a request and would
/// otherwise keep the firewall — and every scanner and tracker it owns — alive
/// for the process lifetime. An upgrade that fails means the firewall is gone,
/// and so is the state this handler existed to reclaim.
///
/// Production code calls this at gateway startup. Tests call the same function,
/// because a test that registers its own handler proves only that a test can
/// register one.
#[cfg(feature = "firewall")]
pub fn wire_session_lifecycle(
    lifecycle: &Arc<SessionLifecycle>,
    firewall: &Arc<crate::security::firewall::Firewall>,
) {
    let firewall = Arc::downgrade(firewall);
    lifecycle.register("firewall-anomaly", move |key| {
        if let Some(firewall) = firewall.upgrade() {
            firewall.on_session_end(key);
        }
    });
}

/// Register the per-session stores `MetaMcp` owns with a lifecycle registry.
///
/// Held as a `Weak` for the reason [`wire_session_lifecycle`] gives. Without
/// this registration the profile, FSM state, cost, transition and promoted-tool
/// stores gain an entry per legacy session and never lose it (MIK-7215.CONTROL.5,
/// gap G2). Transition entries keyed on a caller key go on its idle deadline.
pub fn wire_meta_session_cleanup(
    lifecycle: &Arc<SessionLifecycle>,
    meta: &Arc<crate::gateway::meta_mcp::MetaMcp>,
) {
    let ended = Arc::downgrade(meta);
    lifecycle.register_session_end("meta-session-state", move |key| {
        if let Some(meta) = ended.upgrade() {
            meta.forget_session(key);
        }
    });
    // Hints key on the caller key, which never ends; its idle deadline does.
    let idle = Arc::downgrade(meta);
    lifecycle.register("meta-caller-hints", move |key| {
        if let Some(meta) = idle.upgrade() {
            meta.forget_caller(key);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn an_idle_deadline_does_not_fire_a_session_end_handler() {
        let lifecycle = SessionLifecycle::new();
        let ended = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&ended);
        lifecycle.register_session_end("ended", move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
        });
        lifecycle.track("quiet-session", 0);

        assert_eq!(lifecycle.reap(1), 1);
        assert_eq!(
            ended.load(Ordering::SeqCst),
            0,
            "a session that is only idle is still live"
        );

        lifecycle.on_disconnect("quiet-session");
        assert_eq!(ended.load(Ordering::SeqCst), 1, "a real end fires it once");
    }

    #[test]
    fn a_session_end_is_cleaned_a_second_time_after_the_grace_period() {
        let lifecycle = SessionLifecycle::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&fired);
        lifecycle.register_session_end("count", move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
        });

        lifecycle.on_disconnect("ended");
        assert_eq!(fired.load(Ordering::SeqCst), 1);

        // A call in flight at the end writes after the first pass.
        lifecycle.reap(now_unix());
        assert_eq!(fired.load(Ordering::SeqCst), 1, "not before the grace");

        lifecycle.reap(now_unix() + END_GRACE.as_secs() + 1);
        assert_eq!(fired.load(Ordering::SeqCst), 2, "the second pass");

        lifecycle.reap(now_unix() + 2 * END_GRACE.as_secs());
        assert_eq!(fired.load(Ordering::SeqCst), 2, "and only once");
    }

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
    fn a_renewal_during_the_reap_keeps_the_state_it_writes() {
        // MIK-7746: reaping removed the key, dropped the lock, then ran the
        // handlers. A caller renewing in that window wrote fresh state the
        // handler then wiped. The handler waits (bounded) for a renewal from
        // another thread; the renewal's write must outlive the handler.
        use std::sync::mpsc;
        use std::time::Duration;
        let lifecycle = Arc::new(SessionLifecycle::new());
        let store = Arc::new(parking_lot::Mutex::new(Vec::<&str>::new()));
        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let (renewed_tx, renewed_rx) = mpsc::channel::<()>();
        let wiped = Arc::clone(&store);
        let entered_tx = parking_lot::Mutex::new(Some(entered_tx));
        lifecycle.register("hints", move |_key| {
            if let Some(tx) = entered_tx.lock().take() {
                tx.send(()).unwrap();
                // Base: the renewal lands here. Fixed: it waits on the lock.
                let _ = renewed_rx.recv_timeout(Duration::from_millis(300));
            }
            wiped.lock().clear();
        });
        lifecycle.track("caller", 0);

        let renewer = std::thread::spawn({
            let (lifecycle, store) = (Arc::clone(&lifecycle), Arc::clone(&store));
            move || {
                entered_rx.recv().unwrap();
                lifecycle.track("caller", u64::MAX);
                store.lock().push("fresh");
                let _ = renewed_tx.send(());
            }
        });
        assert_eq!(lifecycle.reap(1), 1);
        renewer.join().unwrap();

        assert_eq!(
            *store.lock(),
            ["fresh"],
            "a caller renewed while its old deadline was reaped lost its fresh state"
        );
        assert_eq!(lifecycle.tracked_count(), 1, "and its new deadline stays");
    }
}
