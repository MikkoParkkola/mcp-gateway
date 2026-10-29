// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shared watcher: one task per gateway, alive only while a stream is open.
//!
//! Status has no push source (the breaker and kill-switch hooks are single
//! listener and already taken), so every tick it recomputes the two status
//! views from backend state and the counter store, in memory, and publishes
//! them. Its state lives in the hub, so a restart never resets a generation.

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;

use super::super::status::{StatusView, status_body};
use crate::gateway::router::AppState;

/// Every change lands within 250 ms, well inside the 1 s the stream promises.
pub(super) const TICK: Duration = Duration::from_millis(250);

/// Spawn the watcher. It takes the hub's publish lock before anything else,
/// so it waits for any watcher still publishing.
pub(super) fn spawn(state: &Arc<AppState>) -> JoinHandle<()> {
    tokio::spawn(run(Arc::clone(state)))
}

/// Run until aborted (the last stream's guard aborts it).
async fn run(state: Arc<AppState>) {
    #[cfg(test)]
    state
        .dashboard_bootstrap
        .stream_hub()
        .probe()
        .watcher_started();
    let hub = state.dashboard_bootstrap.stream_hub();
    // Test signal: this watcher found the lock held and now queues behind it.
    #[cfg(test)]
    if hub.publish_lock().try_lock_owned().is_err() {
        hub.probe().lock_wait_begun();
    }
    let _publishing = hub.publish_lock().lock_owned().await;
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        #[cfg(test)]
        hub.probe().park_point().await;
        let reloaded = hub.reloaded(&state.live_config.generation());
        hub.observe(
            status_body(&state, StatusView::Full),
            status_body(&state, StatusView::CountsOnly),
            reloaded,
        );
    }
}
