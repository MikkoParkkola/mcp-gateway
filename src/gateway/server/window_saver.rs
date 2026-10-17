// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The HTTP `serve` side of the U1 v2 window (MIK-7211): open this
//! process's segment before serving, checkpoint it periodically, and seal it
//! on the shutdown broadcast.
//!
//! One sink mutex orders the open, every checkpoint and the final write, and
//! a closed sink writes nothing, so a late write can never reopen a sealed
//! segment. The seal itself is in memory (the registry lock), so refusals
//! start at the broadcast whatever the disk does. Every write runs on a
//! detached thread (MIK-8157), and the final one under a deadline.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tracing::warn;

use crate::clock::ClockBeforeEpoch;
use crate::config::ProtocolRevisionWindow;
use crate::protocol_revision_telemetry::window::{HttpSegmentSink, SegmentCounts};

/// How often an HTTP process rewrites its window segment.
pub(super) const WINDOW_SAVE_INTERVAL: Duration = Duration::from_secs(5);
/// How long `serve` waits for its segment to open before serving anyway.
///
/// A healthy open is one lock, one read and one fsynced rename on a local
/// disk, well under 100 ms; 2 s bounds a stalled mount at a cost no larger
/// than a restart already pays, far inside the 300 s restart budget.
pub(super) const WINDOW_OPEN_STARTUP_BOUND: Duration = Duration::from_secs(2);

/// The log line the measurement runbook greps for: any hit un-certifies.
const NOT_DURABLE: &str =
    "HTTP protocol-revision telemetry is not durable; do not start the measurement window";

/// Counts for a checkpoint (`false`) or for the seal (`true`), which sets
/// the serving gateway's flag in the same critical section.
pub(super) type CountsFn = Arc<dyn Fn(bool) -> SegmentCounts + Send + Sync>;

/// What a saver needs beyond its gateway. Tests shorten the bounds and
/// replace the clock; `run.rs` uses [`SaverSettings::production`].
#[derive(Clone)]
pub(super) struct SaverSettings {
    pub(super) every: Duration,
    pub(super) open_bound: Duration,
    pub(super) close_bound: Duration,
    pub(super) clock_ms: fn() -> Result<u64, ClockBeforeEpoch>,
}

impl SaverSettings {
    pub(super) fn production() -> Self {
        Self {
            every: WINDOW_SAVE_INTERVAL,
            open_bound: WINDOW_OPEN_STARTUP_BOUND,
            close_bound: super::persistence::SHUTDOWN_SAVES_TIMEOUT,
            clock_ms: crate::clock::unix_millis,
        }
    }
}

/// The production counts: this process's HTTP slice, sealing `seal`.
pub(super) fn global_counts(seal: Arc<AtomicBool>) -> CountsFn {
    Arc::new(move |sealing: bool| {
        crate::protocol_revision_telemetry::window::global_segment_counts(
            sealing.then_some(seal.as_ref()),
        )
    })
}

/// Open the segment (waiting at most `open_bound`), then keep it current
/// until `shutdown`, and seal it. `None` with `off`: nothing is recorded or
/// sealed, and shutdown serves as in 3.5.x. Await the handle after the
/// listener: it ends within `close_bound` of the broadcast.
pub(super) async fn start_window_saver(
    mode: ProtocolRevisionWindow,
    data_dir: PathBuf,
    listen: SocketAddr,
    counts: CountsFn,
    shutdown: tokio::sync::broadcast::Receiver<()>,
    settings: SaverSettings,
) -> Option<tokio::task::JoinHandle<()>> {
    // STUB(red): records nothing and seals nothing.
    let _ = (mode, data_dir, listen, counts, settings, NOT_DURABLE);
    let _: Option<Arc<Mutex<Option<HttpSegmentSink>>>> = None;
    let mut shutdown = shutdown;
    Some(tokio::spawn(async move {
        let _ = shutdown.recv().await;
        warn!("window saver stub stopped");
    }))
}

#[cfg(test)]
#[path = "window_saver_tests.rs"]
mod tests;
