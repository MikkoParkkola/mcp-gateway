// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reclaim abandoned continuations while the serving owner is alive.

use std::sync::{Arc, Weak};

use crate::protocol::continuation::ContinuationState;

pub(super) struct CleanupRuntime {
    pub(super) epoch: Arc<dyn Fn() -> u64 + Send + Sync>,
    #[cfg(test)]
    events: Option<tokio::sync::mpsc::UnboundedSender<CleanupEvent>>,
    #[cfg(test)]
    scans: Option<Arc<std::sync::atomic::AtomicU64>>,
}

#[cfg(test)]
impl CleanupRuntime {
    pub(super) fn with_events(
        epoch: Arc<dyn Fn() -> u64 + Send + Sync>,
        events: tokio::sync::mpsc::UnboundedSender<CleanupEvent>,
    ) -> Self {
        Self {
            epoch,
            events: Some(events),
            ..Self::default()
        }
    }

    pub(super) fn with_clock(epoch: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self {
        Self {
            epoch,
            ..Self::default()
        }
    }
}

impl Default for CleanupRuntime {
    fn default() -> Self {
        Self {
            epoch: Arc::new(crate::protocol::continuation::now_unix_secs),
            #[cfg(test)]
            events: None,
            #[cfg(test)]
            scans: None,
        }
    }
}

/// Start an abortable worker without retaining the gateway across idle waits.
pub(super) fn spawn_cleanup(
    state: Weak<ContinuationState>,
    runtime: CleanupRuntime,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Tokio's first tick is immediate. Scanning begins one period later.
        interval.tick().await;
        #[cfg(test)]
        if let Some(events) = &runtime.events {
            let _ = events.send(CleanupEvent::Ready);
        }
        loop {
            interval.tick().await;
            let Some(state) = state.upgrade() else {
                break;
            };
            let now = (runtime.epoch)();
            let removed = state.in_flight().reclaim_now(now).await;
            #[cfg(not(test))]
            let _ = removed;
            #[cfg(test)]
            {
                if let Some(scans) = &runtime.scans {
                    scans.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                if let Some(events) = &runtime.events {
                    let _ = events.send(CleanupEvent::Scanned { removed });
                }
            }
        }
    })
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(super) enum CleanupEvent {
    Ready,
    Scanned { removed: usize },
}

#[cfg(test)]
mod tests;
