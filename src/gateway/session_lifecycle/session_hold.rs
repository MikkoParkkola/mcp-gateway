// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A running call's claim on its session id (MIK-7996).
//!
//! The session-end handlers clear what a session wrote, but a call still
//! running when its session ends writes again afterwards. A [`SessionHold`]
//! lives as long as such a call. If the session ends while any hold on it is
//! alive, or had already ended when the hold was taken, the last hold to drop
//! runs the session-end handlers again, after the call's final write.
//!
//! The order that makes this race-free: an ender removes the session from the
//! multiplexer and then marks the holds; a holder inserts its hold and then
//! asks the multiplexer. Whichever comes second sees the other.

use std::sync::Arc;

use super::SessionLifecycle;

/// How many holds an id has, and whether its session ended under them.
#[derive(Default)]
pub(super) struct Held {
    holds: usize,
    ended: bool,
}

/// A running call's claim on its session id; see the module docs.
///
/// Released only by `Drop`, so completion, a dropped (cancelled) future, an
/// aborted task and an unwinding panic all release it. The release build
/// aborts on panic, which ends the process and its in-memory state with it.
#[must_use = "the session is held only while this guard lives"]
pub(crate) struct SessionHold {
    lifecycle: Arc<SessionLifecycle>,
    id: String,
}

impl SessionLifecycle {
    /// Hold `id` until the returned guard drops. Built right after the
    /// count goes up, so an unwind in the probe below still releases it.
    pub(crate) fn hold_session(self: &Arc<Self>, id: &str) -> SessionHold {
        self.session_holds
            .lock()
            .entry(id.to_owned())
            .or_default()
            .holds += 1;
        let hold = SessionHold {
            lifecycle: Arc::clone(self),
            id: id.to_owned(),
        };
        // Taken after the end: the session is already gone, so nothing will
        // mark this hold. It marks itself.
        if self.liveness.get().is_some_and(|live| !live(id)) {
            self.mark_ended(id);
        }
        hold
    }

    /// Install the answer to "does this session still exist", once. Without
    /// one every id counts as live and a hold is ended only by a real end.
    pub(crate) fn set_liveness(&self, live: impl Fn(&str) -> bool + Send + Sync + 'static) {
        if self.liveness.set(Box::new(live)).is_err() {
            tracing::debug!("session liveness probe already installed");
        }
    }

    /// Mark the holds on `id`, if any, as outliving its session.
    pub(super) fn mark_ended(&self, id: &str) {
        if let Some(held) = self.session_holds.lock().get_mut(id) {
            held.ended = true;
        }
    }

    /// How many ids are held.
    #[cfg(test)]
    pub(crate) fn held_session_count(&self) -> usize {
        self.session_holds.lock().len()
    }
}

impl Drop for SessionHold {
    /// The last hold on an ended session runs the end handlers again, with
    /// no lifecycle lock held, so everything the call wrote is taken.
    fn drop(&mut self) {
        let mut holds = self.lifecycle.session_holds.lock();
        debug_assert!(
            holds.get(&self.id).is_some_and(|held| held.holds >= 1),
            "a live hold always has its counted entry"
        );
        let Some(held) = holds.get_mut(&self.id) else {
            return;
        };
        held.holds -= 1;
        if held.holds > 0 {
            return;
        }
        let ended = held.ended;
        holds.remove(&self.id);
        drop(holds);
        if ended {
            self.lifecycle.fire_ended(&self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn counted(lifecycle: &SessionLifecycle) -> Arc<AtomicUsize> {
        let fired = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&fired);
        lifecycle.register_session_end("count", move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
        });
        fired
    }

    #[test]
    fn an_end_before_the_hold_is_seen_by_the_probe() {
        let lifecycle = Arc::new(SessionLifecycle::new());
        let fired = counted(&lifecycle);
        let live = Arc::new(AtomicBool::new(true));
        let probe = Arc::clone(&live);
        lifecycle.set_liveness(move |_| probe.load(Ordering::SeqCst));

        // Removed from the multiplexer, then ended: no hold to mark yet.
        live.store(false, Ordering::SeqCst);
        lifecycle.on_disconnect("s");
        let hold = lifecycle.hold_session("s");
        drop(hold);
        assert_eq!(fired.load(Ordering::SeqCst), 2, "the late hold re-ran it");
        assert_eq!(lifecycle.held_session_count(), 0);
    }

    #[test]
    fn an_end_between_the_insert_and_the_check_is_marked_either_way() {
        let lifecycle = Arc::new(SessionLifecycle::new());
        let fired = counted(&lifecycle);
        let live = Arc::new(AtomicBool::new(true));
        let probe = Arc::clone(&live);
        let ender = Arc::clone(&lifecycle);
        // The probe runs after the insert; the session ends inside it.
        lifecycle.set_liveness(move |id| {
            probe.store(false, Ordering::SeqCst);
            ender.on_disconnect(id);
            probe.load(Ordering::SeqCst)
        });
        drop(lifecycle.hold_session("s"));
        assert_eq!(
            fired.load(Ordering::SeqCst),
            2,
            "marked by the end and by the probe"
        );
        assert_eq!(lifecycle.held_session_count(), 0);
    }

    #[test]
    fn a_check_before_the_end_leaves_the_mark_to_the_ender() {
        let lifecycle = Arc::new(SessionLifecycle::new());
        let fired = counted(&lifecycle);
        lifecycle.set_liveness(|_| true);
        let hold = lifecycle.hold_session("s");
        lifecycle.on_disconnect("s");
        assert_eq!(fired.load(Ordering::SeqCst), 1);
        drop(hold);
        assert_eq!(
            fired.load(Ordering::SeqCst),
            2,
            "the ender's mark re-ran it"
        );
    }

    #[test]
    fn a_live_session_hold_runs_nothing() {
        let lifecycle = Arc::new(SessionLifecycle::new());
        let fired = counted(&lifecycle);
        lifecycle.set_liveness(|_| true);
        drop(lifecycle.hold_session("s"));
        drop(lifecycle.hold_session("s"));
        assert_eq!(fired.load(Ordering::SeqCst), 0);
        assert_eq!(lifecycle.held_session_count(), 0);
    }
}
