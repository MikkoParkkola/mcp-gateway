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

use super::super::status::{StatusView, status_body};
use crate::config_reload::Generation;
use crate::gateway::router::AppState;

/// Every change lands within 250 ms, well inside the 1 s the stream promises.
pub(super) const TICK: Duration = Duration::from_millis(250);

/// Run until aborted (the last stream's guard aborts it).
pub(super) async fn run(state: Arc<AppState>) {
    let hub = state.dashboard_bootstrap.stream_hub();
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last: Option<Arc<Generation>> = None;
    loop {
        tick.tick().await;
        // A publish swaps the generation's `Arc`; holding the previous one
        // keeps its address from being reused, so pointer equality is exact.
        let now = state.live_config.generation();
        let reloaded = last.as_ref().is_some_and(|prev| !Arc::ptr_eq(prev, &now));
        last = Some(now);
        hub.observe(
            status_body(&state, StatusView::Full),
            status_body(&state, StatusView::CountsOnly),
            reloaded,
        );
    }
}
