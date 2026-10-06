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
    /// Keys a running task call is writing under, with how many such calls.
    /// A sweep passes them over: a caller whose task is still running is not
    /// idle, however long ago its last request was (MIK-7828.FIX.2).
    /// Lock order: `sweeping`, then `held`, then `tracked`; never the reverse.
    /// [`KeyHold`]'s drop takes `tracked` and then `held` one after the
    /// other, never both at once, so it is outside this order.
    held: parking_lot::Mutex<std::collections::HashMap<String, usize>>,
    /// Held by `reap` from choosing the expired keys until their handlers
    /// have run, and by `hold` while it registers. A hold cannot start between
    /// a key being chosen and its state being freed, so nothing a held call
    /// writes is freed by a sweep that chose the key before the hold.
    /// Handlers run under it and must not take a hold.
    sweeping: parking_lot::Mutex<()>,
}

/// A running call's claim on its caller key; see [`SessionLifecycle::hold`].
#[must_use = "the key is held only while this guard lives"]
pub(crate) struct KeyHold {
    lifecycle: Arc<SessionLifecycle>,
    key: String,
}

impl Drop for KeyHold {
    /// The call is over: it was the caller's latest activity, so the key's
    /// deadline runs one [`IDLE_TTL`] from now. Renewed BEFORE the hold is
    /// released, so a sweep in between finds a fresh deadline, never the
    /// expired one the hold was covering.
    fn drop(&mut self) {
        self.lifecycle
            .track(self.key.clone(), now_unix() + IDLE_TTL.as_secs());
        let mut held = self.lifecycle.held.lock();
        if let Some(count) = held.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                held.remove(&self.key);
            }
        }
    }
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
    /// **Residual, stated rather than implied**: `reap` skips a key re-tracked
    /// after it was chosen, but one re-tracked while its handlers are already
    /// running still loses that state, because [`Self::track`] does not wait
    /// for a sweep (it runs on every request). A key taken by [`Self::hold`] is not
    /// exposed to it: a hold waits for a running sweep to finish (`sweeping`).
    /// A plain [`Self::track`] still is, and the reaper does run in production.
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

    /// Keep `key` from being reclaimed until the returned guard drops, then
    /// renew its deadline. Taken around a task's backend call, which can run
    /// far past [`IDLE_TTL`] with no request from its caller in between. A
    /// key not yet tracked is tracked from the moment the guard drops.
    /// Registering waits for a sweep that is running its handlers, which is
    /// why handlers must stay in-memory and short.
    pub(crate) fn hold(self: &Arc<Self>, key: &str) -> KeyHold {
        let _sweeping = self.sweeping.lock();
        *self.held.lock().entry(key.to_owned()).or_default() += 1;
        KeyHold {
            lifecycle: Arc::clone(self),
            key: key.to_owned(),
        }
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
        // Until the handlers below have run: see `sweeping`.
        let _sweeping = self.sweeping.lock();
        let expired: Vec<String> = {
            let held = self.held.lock();
            let mut tracked = self.tracked.write();
            let expired: Vec<String> = tracked
                .iter()
                .filter(|(key, expires_at)| now > **expires_at && !held.contains_key(*key))
                .map(|(key, _)| key.clone())
                .collect();
            for key in &expired {
                tracked.remove(key);
            }
            expired
        };
        let mut reclaimed = 0;
        for key in expired {
            // Already removed above. `on_disconnect` would remove it again, and
            // a second removal can only take an entry someone re-registered.
            // A key a request re-tracked since it was chosen belongs to a live
            // caller again: its state stays, and its new deadline decides.
            if self.tracked.read().contains_key(&key) {
                continue;
            }
            self.fire_cleanup(&key);
            reclaimed += 1;
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

    /// MIK-7828.FIX.2: a held key survives a sweep past its deadline, stays
    /// held until its last holder lets go, and is then due one `IDLE_TTL`
    /// from that moment, not on the deadline it had before.
    #[test]
    fn a_held_key_is_reclaimed_only_an_idle_ttl_after_its_last_hold() {
        let lifecycle = Arc::new(SessionLifecycle::new());
        let fired = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&fired);
        lifecycle.register("count", move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
        });
        lifecycle.track("caller", 10);
        let first = lifecycle.hold("caller");
        let second = lifecycle.hold("caller");
        assert_eq!(lifecycle.reap(20), 0, "reclaimed while held");
        drop(first);
        assert_eq!(
            lifecycle.reap(20),
            0,
            "reclaimed while one call still holds it"
        );
        assert_eq!(
            lifecycle.reap(now_unix() + IDLE_TTL.as_secs() + 1),
            0,
            "the first release freed a key the second call still holds"
        );
        drop(second);
        let released = now_unix();
        assert_eq!(
            lifecycle.reap(20),
            0,
            "reclaimed on the deadline before the hold"
        );
        assert_eq!(
            lifecycle.reap(released + IDLE_TTL.as_secs() - 1),
            0,
            "reclaimed before an idle TTL had passed since the call ended"
        );
        assert_eq!(lifecycle.reap(now_unix() + IDLE_TTL.as_secs() + 1), 1);
        assert_eq!(fired.load(Ordering::SeqCst), 1);
    }

    /// A hold asked for while a sweep is freeing that key's state is granted
    /// only once the freeing is done, so the held call's writes come after it.
    /// The handler does not finish until it is told to, so a hold granted
    /// early is seen as early. A holder thread slower than the 500 ms wait
    /// can still hide a missing wait (never fail a correct one); the
    /// handler counts as finished only when told to, not on its timeout.
    #[test]
    fn a_hold_waits_for_a_sweep_already_freeing_its_key() {
        use std::sync::mpsc::{RecvTimeoutError, channel};
        use std::time::Duration;
        let lifecycle = Arc::new(SessionLifecycle::new());
        let freed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (started_tx, started_rx) = channel();
        let (go_tx, go_rx) = channel::<()>();
        let go_rx = parking_lot::Mutex::new(go_rx);
        let done = Arc::clone(&freed);
        lifecycle.register("slow", move |_| {
            started_tx.send(()).expect("test alive");
            if go_rx.lock().recv_timeout(Duration::from_secs(10)).is_ok() {
                done.store(true, Ordering::SeqCst);
            }
        });
        lifecycle.track("caller", 0);
        let sweeper = Arc::clone(&lifecycle);
        let sweep = std::thread::spawn(move || sweeper.reap(1));
        started_rx.recv().expect("the sweep chose the key");

        let (held_tx, held_rx) = channel();
        let (holder, seen) = (Arc::clone(&lifecycle), Arc::clone(&freed));
        let hold = std::thread::spawn(move || {
            let hold = holder.hold("caller");
            held_tx
                .send(seen.load(Ordering::SeqCst))
                .expect("test alive");
            drop(hold);
        });
        let freed_when_held = match held_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(freed_when_held) => freed_when_held,
            Err(RecvTimeoutError::Timeout) => {
                go_tx.send(()).expect("handler alive");
                held_rx.recv().expect("the hold is granted after the sweep")
            }
            Err(RecvTimeoutError::Disconnected) => panic!("the holder died"),
        };
        let _ = go_tx.send(());
        assert!(
            freed_when_held,
            "a hold was granted while a sweep was still freeing its key"
        );
        hold.join().expect("holder");
        assert_eq!(sweep.join().expect("sweep"), 1);
    }

    /// A key a request re-tracks after the sweep chose it is not reclaimed:
    /// the first handler to run re-tracks the other expired key.
    #[test]
    fn a_key_retracked_after_the_sweep_chose_it_keeps_its_state() {
        let lifecycle = Arc::new(SessionLifecycle::new());
        let fired = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let (seen, renew) = (Arc::clone(&fired), Arc::downgrade(&lifecycle));
        lifecycle.register("renews-the-other", move |key| {
            seen.lock().expect("seen").push(key.to_owned());
            let other = if key == "a" { "b" } else { "a" };
            if let Some(lifecycle) = renew.upgrade() {
                lifecycle.track(other, u64::MAX);
            }
        });
        lifecycle.track("a", 0);
        lifecycle.track("b", 0);
        assert_eq!(lifecycle.reap(1), 1, "both keys reclaimed: {fired:?}");
        assert_eq!(fired.lock().expect("seen").len(), 1);
        assert_eq!(lifecycle.tracked_count(), 1);
    }

    /// A caller that renews while its old deadline's handler is running and
    /// then writes fresh state keeps that state (MIK-7746). The handler waits
    /// up to 500 ms for the renewer to have written before it wipes. If a
    /// renewal can land during the handler, the write is wiped; if the renewal
    /// waits for the handler, the wait times out and the write comes after
    /// the wipe. A runner slower than the wait can hide the defect, never
    /// fail a correct registry.
    #[test]
    fn a_renewal_during_the_reap_keeps_the_state_it_writes() {
        use std::sync::mpsc::channel;
        use std::time::Duration;
        let lifecycle = Arc::new(SessionLifecycle::new());
        let store = Arc::new(parking_lot::Mutex::new(Vec::<&str>::new()));
        let (entered_tx, entered_rx) = channel::<()>();
        let (written_tx, written_rx) = channel::<()>();
        let written_rx = parking_lot::Mutex::new(written_rx);
        let wiped = Arc::clone(&store);
        lifecycle.register("hints", move |_key| {
            let _ = entered_tx.send(());
            let _ = written_rx.lock().recv_timeout(Duration::from_millis(500));
            wiped.lock().clear();
        });
        lifecycle.track("caller", 0);

        let renewer = std::thread::spawn({
            let (lifecycle, store) = (Arc::clone(&lifecycle), Arc::clone(&store));
            move || {
                entered_rx.recv().expect("the handler started");
                lifecycle.track("caller", u64::MAX);
                store.lock().push("fresh");
                let _ = written_tx.send(());
            }
        });
        assert_eq!(lifecycle.reap(1), 1);
        renewer.join().expect("renewer");

        assert_eq!(
            *store.lock(),
            ["fresh"],
            "a caller renewed while its old deadline was reaped lost its fresh state"
        );
        assert_eq!(lifecycle.tracked_count(), 1, "and its new deadline stays");
    }
}
