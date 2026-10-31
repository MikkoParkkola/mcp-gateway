// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Design rows 11, 12, 13, 16, 18, 20 and the `off` arm: the saver's open,
//! checkpoints and seal. Counts come from a stub, so no row seals the
//! process-wide registry other tests count through. Stalls wait on the
//! write gate's signals and on the seal flag, never on a sleep. The runtime
//! has two workers: a row blocks one on a gate signal while the saver runs.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use super::*;
use crate::protocol_revision_telemetry::window;
use crate::protocol_revision_telemetry::window::stall_seam::{self, Role};
use crate::protocol_revision_telemetry::{Registry, Transport};

/// Bound on each wait for something that must happen (a setup watchdog).
const ARRIVAL: Duration = Duration::from_secs(30);
/// Scheduling allowance on top of a configured bound, for a loaded CI host.
const ALLOWANCE: Duration = Duration::from_secs(5);
/// The short close bound the deadline rows configure.
const CLOSE_BOUND: Duration = Duration::from_millis(300);

struct Rig {
    dir: tempfile::TempDir,
    seal: Arc<AtomicBool>,
    served: Arc<AtomicU64>,
    shutdown: tokio::sync::broadcast::Sender<()>,
}

impl Rig {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
            seal: Arc::new(AtomicBool::new(false)),
            served: Arc::new(AtomicU64::new(0)),
            shutdown: tokio::sync::broadcast::channel(1).0,
        }
    }

    fn window_path(&self) -> std::path::PathBuf {
        window::window_paths(self.dir.path()).0
    }

    /// Counts of `served` HTTP requests; sealing sets this rig's flag.
    fn counts(&self) -> CountsFn {
        let (seal, served) = (Arc::clone(&self.seal), Arc::clone(&self.served));
        Arc::new(move |sealing| {
            if sealing {
                seal.store(true, Ordering::SeqCst);
            }
            let mut registry = Registry::new();
            for _ in 0..served.load(Ordering::SeqCst) {
                registry.observe_request(Some("2025-11-25"), "claude", Transport::Http);
            }
            SegmentCounts {
                snapshot: registry.snapshot(),
                ..SegmentCounts::empty()
            }
        })
    }

    async fn start(
        &self,
        mode: ProtocolRevisionWindow,
        settings: SaverSettings,
    ) -> Option<tokio::task::JoinHandle<()>> {
        start_window_saver(
            mode,
            self.dir.path().to_path_buf(),
            "127.0.0.1:39401".parse().expect("address"),
            self.counts(),
            self.shutdown.subscribe(),
            settings,
        )
        .await
    }

    fn segments(&self) -> Vec<window::Segment> {
        window::load(self.dir.path()).map_or_else(|_| Vec::new(), |w| w.http_segments)
    }
}

/// Settings for a row that is not about the startup bound: the open gets
/// the whole watchdog, so `start` returns once it lands. A short bound here
/// made the open-before-serving row race a slow open (Windows CI, #3920).
fn settings(close_bound: Duration) -> SaverSettings {
    SaverSettings {
        every: Duration::from_secs(3600),
        open_bound: ARRIVAL,
        close_bound,
        clock_ms: crate::clock::unix_millis,
    }
}

/// Settings for a row that stalls the open on purpose and needs `start` to
/// give up on it: a short startup bound, as production's, but shorter.
fn stalled_open(close_bound: Duration) -> SaverSettings {
    SaverSettings {
        open_bound: Duration::from_millis(200),
        ..settings(close_bound)
    }
}

fn before_epoch() -> Result<u64, ClockBeforeEpoch> {
    Err(ClockBeforeEpoch)
}

async fn stop(rig: &Rig, saver: tokio::task::JoinHandle<()>) {
    rig.shutdown.send(()).expect("the saver subscribed");
    tokio::time::timeout(ARRIVAL, saver)
        .await
        .expect("the saver ends within its close bound")
        .expect("the saver does not panic");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_the_mode_off_nothing_is_recorded_or_sealed() {
    let rig = Rig::new();
    assert!(
        rig.start(ProtocolRevisionWindow::Off, settings(ARRIVAL))
            .await
            .is_none()
    );
    rig.shutdown.send(()).ok();
    assert!(!rig.seal.load(Ordering::SeqCst));
    assert!(!rig.dir.path().join("protocol-revision-telemetry").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_segment_is_open_before_serving_and_sealed_on_the_broadcast() {
    let rig = Rig::new();
    let saver = rig
        .start(ProtocolRevisionWindow::Record, settings(ARRIVAL))
        .await
        .expect("record");
    let segments = rig.segments();
    assert_eq!(
        segments.len(),
        1,
        "the segment must exist before serving starts"
    );
    assert!(!segments[0].closed_cleanly);
    rig.served.store(9, Ordering::SeqCst);
    stop(&rig, saver).await;
    let segment = rig.segments().remove(0);
    assert!(segment.closed_cleanly);
    assert_eq!(segment.snapshot.total, 9);
    assert!(segment.sealed_at_ms.is_some());
    assert!(rig.seal.load(Ordering::SeqCst));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_final_write_stalled_past_its_bound_leaves_the_segment_unclean() {
    // Row 11 arm 1, and row 12: refusals start at the broadcast regardless.
    let rig = Rig::new();
    let saver = rig
        .start(ProtocolRevisionWindow::Record, settings(CLOSE_BOUND))
        .await
        .expect("record");
    let (entered, release) = stall_seam::arm(&rig.window_path(), Role::Close);
    rig.served.store(4, Ordering::SeqCst);
    let broadcast = std::time::Instant::now();
    rig.shutdown.send(()).expect("subscribed");
    entered
        .recv_timeout(ARRIVAL)
        .expect("the final write starts");
    assert!(
        rig.seal.load(Ordering::SeqCst),
        "the seal waits for no write"
    );
    tokio::time::timeout(ARRIVAL, saver)
        .await
        .expect("bounded")
        .expect("no panic");
    // timing-oracle: vs CLOSE_BOUND (MIK-7211)
    assert!(
        broadcast.elapsed() < CLOSE_BOUND + ALLOWANCE,
        "the saver outlived its close bound: {:?}",
        broadcast.elapsed()
    );
    assert!(
        !rig.segments()[0].closed_cleanly,
        "an unlanded close reads clean"
    );
    drop(release);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_final_write_released_after_its_bound_lands_the_exact_sealed_counts() {
    // Row 11 arm 2: a late landing is correct data.
    let rig = Rig::new();
    let saver = rig
        .start(ProtocolRevisionWindow::Record, settings(CLOSE_BOUND))
        .await
        .expect("record");
    let (entered, release) = stall_seam::arm(&rig.window_path(), Role::Close);
    rig.served.store(4, Ordering::SeqCst);
    rig.shutdown.send(()).expect("subscribed");
    entered
        .recv_timeout(ARRIVAL)
        .expect("the final write starts");
    tokio::time::timeout(ARRIVAL, saver)
        .await
        .expect("bounded")
        .expect("no panic");
    rig.served.store(99, Ordering::SeqCst); // after the seal: never in the file
    release.send(()).expect("release");
    let landed = wait_for(|| rig.segments().first().is_some_and(|s| s.closed_cleanly));
    assert!(landed, "the released close never landed");
    assert_eq!(rig.segments()[0].snapshot.total, 4);
}

/// Reads before 1970 once (the saver's start-time read), then normally. Only
/// the row below uses it.
static START_CLOCK_READS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn clock_unreadable_at_start() -> Result<u64, ClockBeforeEpoch> {
    if START_CLOCK_READS.fetch_add(1, Ordering::SeqCst) == 0 {
        Err(ClockBeforeEpoch)
    } else {
        crate::clock::unix_millis()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_time_the_clock_could_not_read_is_never_written_as_zero() {
    // Row 13: with no start time there is no segment, even once the clock
    // reads again; a 0 start would look like a process from 1970.
    let rig = Rig::new();
    let recovering = SaverSettings {
        clock_ms: clock_unreadable_at_start,
        ..settings(ARRIVAL)
    };
    let saver = rig
        .start(ProtocolRevisionWindow::Record, recovering)
        .await
        .expect("record");
    rig.served.store(3, Ordering::SeqCst);
    stop(&rig, saver).await;
    let segments = rig.segments();
    assert!(
        segments.iter().all(|s| s.process_started_at_ms != 0),
        "a 0 start time was written: {segments:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_clock_before_1970_never_writes_a_zero_and_never_closes_clean() {
    // Row 13: with no readable clock there is no start time to record, so no
    // segment is written; the seal is still taken, so refusals still start.
    let rig = Rig::new();
    let clockless = SaverSettings {
        clock_ms: before_epoch,
        ..settings(ARRIVAL)
    };
    let saver = rig
        .start(ProtocolRevisionWindow::Record, clockless)
        .await
        .expect("record");
    stop(&rig, saver).await;
    assert!(rig.seal.load(Ordering::SeqCst), "a clock error still seals");
    let segments = rig.segments();
    assert!(
        segments
            .iter()
            .all(|s| !s.closed_cleanly && s.process_started_at_ms != 0),
        "{segments:?}"
    );
}

/// A clock that reads normally until its row breaks it. Only the row below
/// passes it to a saver, so no other row sees it break.
static SEAL_CLOCK_BROKEN: AtomicBool = AtomicBool::new(false);

fn clock_that_breaks() -> Result<u64, ClockBeforeEpoch> {
    if SEAL_CLOCK_BROKEN.load(Ordering::SeqCst) {
        Err(ClockBeforeEpoch)
    } else {
        crate::clock::unix_millis()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_clock_failing_at_the_seal_leaves_a_healthy_segment_unclean() {
    // Row 13, after a healthy open: no seal time can be written, so the
    // close never lands, and the seal still refuses later requests.
    let rig = Rig::new();
    let breaking = SaverSettings {
        clock_ms: clock_that_breaks,
        ..settings(ARRIVAL)
    };
    let saver = rig
        .start(ProtocolRevisionWindow::Record, breaking)
        .await
        .expect("record");
    assert_eq!(rig.segments().len(), 1, "the open used the healthy clock");
    SEAL_CLOCK_BROKEN.store(true, Ordering::SeqCst);
    stop(&rig, saver).await;
    SEAL_CLOCK_BROKEN.store(false, Ordering::SeqCst);
    assert!(rig.seal.load(Ordering::SeqCst), "a clock error still seals");
    let segment = rig.segments().remove(0);
    assert!(!segment.closed_cleanly, "{segment:?}");
    assert!(segment.sealed_at_ms.is_none());
}

fn wait_for(mut done: impl FnMut() -> bool) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < ARRIVAL {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

#[path = "window_saver_stall_tests.rs"]
mod stall;

#[path = "window_saver_lifetime_tests.rs"]
mod lifetime;
