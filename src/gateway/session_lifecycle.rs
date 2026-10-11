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

mod session_hold;
pub(crate) use session_hold::SessionHold;

type CleanupFn = Box<dyn Fn(&str) + Send + Sync>;
/// Whether the multiplexer still has a session; see `SessionLifecycle::liveness`.
type LivenessFn = Box<dyn Fn(&str) -> bool + Send + Sync>;

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
    /// `None`: the end came on a clock before 1970 and is dated by the next
    /// readable reap (MIK-8202).
    ended_pending: RwLock<Vec<(String, Option<u64>)>>,
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
    ///
    /// `None` is a key whose latest activity came on a clock before 1970: it
    /// awaits renewal, and the next readable reap gives it a full
    /// [`IDLE_TTL`] before judging it (MIK-8202).
    tracked: RwLock<std::collections::HashMap<String, Option<u64>>>,
    /// Keys a running task call is writing under, with how many such calls.
    /// A sweep passes them over: a caller whose task is still running is not
    /// idle, however long ago its last request was (MIK-7828.FIX.2).
    /// Lock order: `held`, then `tracked`, then `callbacks`; never the
    /// reverse. `ended` and `ended_pending` are leaves, taken alone. `reap`
    /// holds `held` and `tracked` while it decides on one key, removes it and
    /// runs its handlers, so neither a hold nor a renewal can land between the
    /// decision and the freeing (MIK-7746). [`KeyHold`]'s drop takes `tracked`
    /// and then `held` one after the other, never both at once, so it is
    /// outside this order.
    held: parking_lot::Mutex<std::collections::HashMap<String, usize>>,
    /// Test seam: run by `reap` before each key's critical section, with no
    /// registry lock held, so a test can renew a key between the sweep's
    /// snapshot and its turn.
    #[cfg(test)]
    between_keys: parking_lot::Mutex<Option<Box<dyn FnMut() + Send>>>,
    /// Test seam: run inside `reap`'s pass that dates undated keys, under
    /// the `tracked` write lock, so a test can race a renewal against it.
    #[cfg(test)]
    dating_pass: parking_lot::Mutex<Option<Box<dyn FnMut() + Send>>>,
    /// Session ids a running call holds, and whether the session ended under
    /// them (MIK-7996, [`SessionHold`]). A leaf lock, never held with another.
    session_holds: parking_lot::Mutex<std::collections::HashMap<String, session_hold::Held>>,
    /// Whether the multiplexer still has a session, installed by the reaper
    /// that pairs the two. None: every id counts as live.
    liveness: std::sync::OnceLock<LivenessFn>,
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
        self.lifecycle.renew(self.key.clone());
        let mut held = self.lifecycle.held.lock();
        if let Some(count) = held.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                held.remove(&self.key);
            }
        }
    }
}

/// When the second cleanup pass runs after a session ends. A backstop only:
/// a call that writes after the end, however long it runs, holds the session
/// and reruns the end handlers itself when it finishes ([`SessionHold`]).
pub const END_GRACE: std::time::Duration = std::time::Duration::from_secs(120);

/// How long an identity's derived state outlives its last observed request.
///
/// The revision removed protocol sessions, so nothing signals a disconnect and
/// the only honest question left is "has this identity been quiet long enough".
/// Five minutes is the answer the reclaim-latency bound in the design is stated
/// against: a caller idle this long has its per-identity state reclaimed, and a
/// caller still working keeps pushing its deadline forward.
pub const IDLE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// Seconds since the Unix epoch, the unit every deadline in this module uses;
/// `None` on a clock before 1970 (MIK-8202).
///
/// One helper so the seam between this module's `u64` seconds and callers that
/// think in `Instant` is crossed in exactly one place. A clock set backwards
/// delays a reclaim and one set forwards reclaims early; both touch derived
/// state only, which is why wall-clock is acceptable here and a monotonic
/// `Instant` — unloggable, unpersistable, uncomparable across a restart — is
/// not.
pub fn now_unix() -> Option<u64> {
    crate::clock::unix_secs().ok()
}

/// The second-pass time of a session ending now, or `None` on a clock before
/// 1970: dated by the next readable reap.
fn grace_from_now() -> Option<u64> {
    now_unix().map(|now| now.saturating_add(END_GRACE.as_secs()))
}

impl SessionLifecycle {
    /// Create a new empty lifecycle registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a named cleanup callback.
    ///
    /// The callback receives the session ID string when a session disconnects.
    /// Name is used for debug logging only. A callback must not call any
    /// method of this registry, nor take a lock that a caller of one holds:
    /// it runs under the registry's locks, which are not reentrant.
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
    ///
    /// It runs more than once per id: at the end, when the last call still
    /// holding the session finishes ([`SessionHold`]), and at the grace pass,
    /// and a re-run can race the grace pass on another thread. A handler must
    /// therefore be idempotent and safe to run concurrently with itself. It
    /// must not block either: a re-run happens where the last call's hold
    /// drops, on whatever runtime thread that is.
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
    /// or by the DELETE /mcp handler. The cleanup handlers run even for a key
    /// the idle sweep already reclaimed, so they must be idempotent.
    pub fn on_disconnect(&self, session_id: &str) {
        // Whatever brought us here, this key is done: drop its deadline so a
        // later reap cannot fire the handlers for it a second time. The
        // handlers run under the lock that dropped it, so a renewal waits
        // for them and its writes outlive them (MIK-7746).
        {
            let mut tracked = self.tracked.write();
            tracked.remove(session_id);
            self.fire_cleanup(session_id);
        }
        self.fire_ended(session_id);
        self.ended_pending
            .write()
            .push((session_id.to_owned(), grace_from_now()));
    }

    /// Run the session-end handlers for `session_id`.
    fn fire_ended(&self, session_id: &str) {
        // Marked first, so a call still holding the session runs these
        // again after its last write (MIK-7996).
        self.mark_ended(session_id);
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
    /// a live caller's state with it. Both callers run it under the
    /// `tracked` write lock that removed the key, so a [`Self::track`] for it
    /// waits until the handlers are done.
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
    ///
    /// A caller renews BEFORE it writes state under the key: a renewal waits
    /// for a running cleanup of the key, so only a write that follows it is
    /// sure to outlive that cleanup (MIK-7746). Caller keys only: state keyed
    /// by a session id is freed by the session-end handlers, which a renewal
    /// does not order against.
    pub fn track(&self, key: impl Into<String>, expires_at: u64) {
        self.tracked.write().insert(key.into(), Some(expires_at));
    }

    /// Test seam: run `hook` inside the next reaps' dating pass.
    #[cfg(test)]
    pub(crate) fn on_dating_pass(&self, hook: impl FnMut() + Send + 'static) {
        *self.dating_pass.lock() = Some(Box::new(hook));
    }

    /// The caller's latest activity is now: `key` is reclaimable one
    /// [`IDLE_TTL`] from now. On a clock before 1970 the activity cannot be
    /// dated, so the key awaits renewal at the next readable reap instead of
    /// keeping an older deadline (MIK-8202).
    pub fn renew(&self, key: impl Into<String>) {
        let expires_at = now_unix().map(|now| now.saturating_add(IDLE_TTL.as_secs()));
        self.tracked.write().insert(key.into(), expires_at);
    }

    /// Keep `key` from being reclaimed until the returned guard drops, then
    /// renew its deadline. Taken around a task's backend call, which can run
    /// far past [`IDLE_TTL`] with no request from its caller in between. A
    /// key not yet tracked is tracked from the moment the guard drops.
    /// Registering waits while a sweep runs any key's handlers (`held` is
    /// taken across each key's section), which is why handlers must stay
    /// in-memory and short.
    pub(crate) fn hold(self: &Arc<Self>, key: &str) -> KeyHold {
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
    /// callbacks free things, and a cleanup handler that runs twice for one
    /// key is its own defect. (Session-end handlers are the exception: see
    /// [`Self::register_session_end`].) The count is the keys removed, not the keys examined, so a
    /// caller logging a sweep can tell an idle sweep from a busy one.
    pub fn reap(&self, now: u64) -> usize {
        // Undated keys and ends (activity on a clock before 1970) are dated
        // from this readable pass, before any of them is judged, and under
        // the locks a renewal takes, so a renewal racing the pass keeps its
        // own deadline (MIK-8202).
        {
            let mut tracked = self.tracked.write();
            #[cfg(test)]
            if let Some(hook) = self.dating_pass.lock().as_mut() {
                hook();
            }
            for deadline in tracked.values_mut().filter(|d| d.is_none()) {
                *deadline = Some(now.saturating_add(IDLE_TTL.as_secs()));
            }
        }
        // The second pass for sessions that ended a grace period ago.
        let due: Vec<String> = {
            let mut pending = self.ended_pending.write();
            for (_, at) in pending.iter_mut().filter(|(_, at)| at.is_none()) {
                *at = Some(now.saturating_add(END_GRACE.as_secs()));
            }
            let (due, later): (Vec<_>, Vec<_>) = pending
                .drain(..)
                .partition(|(_, at)| at.is_some_and(|at| now > at));
            *pending = later;
            due.into_iter().map(|(id, _)| id).collect()
        };
        for id in due {
            self.fire_ended(&id);
        }
        // Candidates only: each key is decided again under the locks that
        // free it, so a key renewed or held since this snapshot is skipped.
        let candidates: Vec<String> = {
            let held = self.held.lock();
            self.tracked
                .read()
                .iter()
                .filter(|(key, expires_at)| {
                    expires_at.is_some_and(|at| now > at) && !held.contains_key(*key)
                })
                .map(|(key, _)| key.clone())
                .collect()
        };
        let mut reclaimed = 0;
        for key in candidates {
            #[cfg(test)]
            if let Some(hook) = self.between_keys.lock().as_mut() {
                hook();
            }
            // One key at a time (MIK-7746): its handlers run under the locks
            // that decided and removed it, so a hold or a renewal for it waits
            // until they are done and whatever it writes next outlives them.
            // The sweep holds the locks one key at a time, so a renewal of
            // another key waits only while some key's handlers run.
            let held = self.held.lock();
            let mut tracked = self.tracked.write();
            let due = tracked.get(&key).is_some_and(|expires_at| {
                expires_at.is_some_and(|at| now > at) && !held.contains_key(&key)
            });
            if !due {
                continue;
            }
            tracked.remove(&key);
            // Removed here, not by `on_disconnect`: a second removal could
            // only take an entry someone re-registered.
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
    meta.attach_session_lifecycle(lifecycle);
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
#[path = "session_lifecycle_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "session_lifecycle_clock_tests.rs"]
mod clock_tests;
