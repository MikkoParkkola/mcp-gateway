// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A gateway stop under one deadline: [`BackendRegistry::stop_all_by`] and
//! the stop deadline every backend the registry builds shares.

use std::sync::Arc;

use tracing::warn;

use super::{Backend, BackendRegistry};

impl BackendRegistry {
    /// The stop deadline this registry's backends share, for backends built
    /// outside it (the capability executor's MCP children).
    pub(crate) fn stop_deadline(&self) -> Arc<crate::transport::StopDeadline> {
        Arc::clone(&self.stop_deadline)
    }

    /// Hand every live tree to the reaper without waiting for lifecycle locks.
    pub(crate) fn hand_over_now(&self, budget: std::time::Duration) {
        for backend in self.latch_and_snapshot() {
            backend.hand_over_now(budget);
        }
    }

    /// [`Self::stop_all`], planned to end by `deadline`: the deadline is set
    /// first, so a stdio tree already in its exit waits is cut to it too, and
    /// each close plans its own waits to fit.
    ///
    /// However the stop ends (finished, timed out by the caller, or dropped),
    /// every backend's tree not yet handed to the reaper is then killed at
    /// once, so none is left running behind the parent. A tree already
    /// handed over is in the reaper's hands, cut to `deadline`.
    pub(crate) async fn stop_all_by(&self, deadline: tokio::time::Instant) {
        self.stop_deadline.move_earlier(deadline.into_std());
        if mutant!("s9507.h1", false, self.stop_deadline.is_hurried()) {
            self.hand_over_now(deadline.saturating_duration_since(tokio::time::Instant::now()));
        }
        // The backends to retire are the ones the stop latched and took, in
        // one hold: a reload registering after this is refused, never stopped
        // without being retired.
        let backends = self.latch_and_snapshot();
        let _sweep = RetireOnDrop(backends.clone());
        #[cfg(test)]
        seam::after_sweep();
        let stop = crate::transport::within_stop_deadline(deadline, Self::stop_each(backends));
        // Bounded by the deadline as a whole: a backend waiting on a restart's
        // lifecycle lock cannot outrun the stage. What it leaves running is
        // retired by `_sweep` when this returns.
        if tokio::time::timeout_at(deadline, stop).await.is_err() {
            warn!("backend stop did not finish by its deadline; retiring what is left");
        }
        // Trees handed over gracefully before this stop (an idle close, a
        // restart) are cut to `deadline` by the reaper; wait for their kills.
        self.stop_deadline.wait_handed(deadline).await;
        // The stop is over: from now on a handover (an idle release racing
        // this return) is killed on its first step, which runs on the
        // handing-over thread, so nothing is left in its waits behind the
        // parent. Then once more for any that slipped in before this moment.
        self.stop_deadline.move_earlier(std::time::Instant::now());
        self.stop_deadline.wait_handed(deadline).await;
    }
}

/// Retires each backend when dropped: the last word of a stop, whichever way
/// it ended (see [`BackendRegistry::stop_all_by`]).
struct RetireOnDrop(Vec<Arc<Backend>>);

impl Drop for RetireOnDrop {
    fn drop(&mut self) {
        for backend in &self.0 {
            backend.retire_now();
        }
    }
}

/// Test-only hook right after the stop takes the backends it will retire,
/// for the row that registers a backend in that window. Thread-local: its
/// rows run on the default current-thread runtime.
#[cfg(test)]
pub(in crate::backend) mod seam {
    use std::cell::RefCell;

    thread_local! {
        static AFTER_SWEEP: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    }

    /// Run `hook` once, the next time a stop on this thread has taken them.
    /// Unix-only, like the only row that arms it.
    #[cfg(unix)]
    pub(in crate::backend) fn after_sweep_runs(hook: impl FnOnce() + 'static) {
        AFTER_SWEEP.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    }

    pub(super) fn after_sweep() {
        if let Some(hook) = AFTER_SWEEP.with(|slot| slot.borrow_mut().take()) {
            hook();
        }
    }
}
