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
        let _sweep = RetireOnDrop(
            self.backends
                .iter()
                .map(|entry| Arc::clone(entry.value()))
                .collect(),
        );
        #[allow(
            clippy::disallowed_methods,
            reason = "Lifecycle: gateway startup, wiring or shutdown; no caller request"
        )]
        let stop = crate::transport::within_stop_deadline(deadline, self.stop_all());
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
