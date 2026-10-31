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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tracing::warn;

use crate::clock::ClockBeforeEpoch;
use crate::config::ProtocolRevisionWindow;
use crate::protocol_revision_telemetry::window::{HttpSegmentSink, SegmentCounts, WriterIdentity};
#[cfg(test)]
use crate::protocol_revision_telemetry::window::{stall_seam, window_paths};

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

/// This process's segment, as every write of it finds it under the sink
/// mutex. `Sealed` is final: the seal sets it whatever it found, and no open
/// follows it, so a write that reaches the sink after the seal opens nothing.
#[derive(Default)]
enum SinkState {
    #[default]
    Unopened,
    Open(HttpSegmentSink),
    Sealed,
}

/// The sink every write of this process's segment takes in turn.
type Sink = Arc<Mutex<SinkState>>;

/// The saver's writer threads still running: counted before each spawn and
/// uncounted when it ends (or fails to start), so the shutdown can wait for
/// every write the saver began.
#[derive(Default)]
struct Writers {
    running: AtomicUsize,
    idle: tokio::sync::Notify,
    /// Test support: run once in `idle`, after the count is read and before
    /// the await, so a row can end the last writer exactly there.
    #[cfg(test)]
    between_read_and_await: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Test support: the next spawn fails as if the OS refused a thread.
    #[cfg(test)]
    fail_next_spawn: AtomicBool,
}

impl Writers {
    /// Run `work` on a writer thread named `name` that this count covers.
    fn spawn(
        self: &Arc<Self>,
        name: &str,
        work: impl FnOnce() + Send + 'static,
    ) -> std::io::Result<()> {
        self.running.fetch_add(1, Ordering::SeqCst);
        let writers = Arc::clone(self);
        let thread = move || {
            let _running = Running(writers);
            work();
        };
        #[cfg(test)]
        let spawned = if self.fail_next_spawn.swap(false, Ordering::SeqCst) {
            drop(thread);
            Err(std::io::Error::other("a forced spawn failure"))
        } else {
            std::thread::Builder::new()
                .name(name.to_owned())
                .spawn(thread)
        };
        #[cfg(not(test))]
        let spawned = std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(thread);
        if spawned.is_err() {
            // The closure never ran, so its guard never will: uncount once.
            self.finished();
        }
        spawned.map(drop)
    }

    fn finished(&self) {
        if self.running.fetch_sub(1, Ordering::SeqCst) == 1 {
            // `notify_waiters`, never `notify_one`: a `Notified` future
            // receives `notify_waiters` from the moment it is created, even
            // unpolled (tokio's `Notify::notified`), which is what lets
            // `idle` create it before reading the count. With `notify_one`
            // that holds only after `enable()`, and the last wakeup could be
            // lost.
            self.idle.notify_waiters();
        }
    }

    /// Resolves once no writer thread is running.
    async fn idle(&self) {
        loop {
            // Created before the count is read, so a last writer ending
            // between the read and the await still wakes this.
            let notified = self.idle.notified();
            if self.running.load(Ordering::SeqCst) == 0 {
                return;
            }
            #[cfg(test)]
            if let Some(hook) = self
                .between_read_and_await
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                hook();
            }
            notified.await;
        }
    }
}

/// Uncounts its writer when the writer's thread ends, by return or panic.
struct Running(Arc<Writers>);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.finished();
    }
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
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
    settings: SaverSettings,
) -> Option<tokio::task::JoinHandle<()>> {
    if mode == ProtocolRevisionWindow::Off {
        return None;
    }
    let sink: Sink = Arc::default();
    let writers = Arc::new(Writers::default());
    // No readable clock means no start time to record: no segment is
    // written (never a 0), but the seal below still refuses late requests.
    let identity = if let Ok(started_ms) = (settings.clock_ms)() {
        Some(WriterIdentity {
            listen: listen.to_string(),
            exe: std::env::current_exe()
                .map_or_else(|_| "unknown".to_string(), |path| path.display().to_string()),
            process_started_at_ms: started_ms,
        })
    } else {
        warn!(data_dir = %data_dir.display(), "{NOT_DURABLE} (clock before 1970)");
        None
    };
    if let Some(identity) = &identity {
        let opened = open_detached(&writers, &sink, &data_dir, identity, settings.clock_ms);
        match tokio::time::timeout(settings.open_bound, opened).await {
            Ok(Ok(true)) => {}
            Ok(_) => warn!(data_dir = %data_dir.display(), "{NOT_DURABLE}"),
            Err(_) => warn!(data_dir = %data_dir.display(), "{NOT_DURABLE} (open still running)"),
        }
    }
    Some(tokio::spawn(async move {
        let mut interval = tokio::time::interval(settings.every);
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Some(identity) = &identity {
                        checkpoint_detached(&writers, &sink, &data_dir, identity, &counts, settings.clock_ms);
                    }
                }
                _ = shutdown.recv() => break,
            }
        }
        // The seal, in memory and under the registry lock: refusals start
        // now, whatever the disk does next.
        let sealed_counts = counts(true);
        let sealed_at_ms = (settings.clock_ms)();
        let deadline = tokio::time::Instant::now() + settings.close_bound;
        #[cfg(test)]
        let seam_path = window_paths(&data_dir).0;
        #[cfg(test)]
        let drain_seam_path = seam_path.clone();
        let close: super::persistence::ShutdownSave = (
            "protocol-revision window seal",
            Box::new(move || {
                let seal = || {
                    let mut held = sink
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let found = std::mem::replace(&mut *held, SinkState::Sealed);
                    let (SinkState::Open(mut sink), Ok(sealed_at_ms)) = (found, sealed_at_ms)
                    else {
                        warn!("{NOT_DURABLE}: the window segment was not sealed");
                        return;
                    };
                    let now = sealed_at_ms / 1_000;
                    if let Err(error) = sink.close(&sealed_counts, now, sealed_at_ms) {
                        warn!(%error, "{NOT_DURABLE}: the window segment seal did not land");
                    }
                };
                seal();
                #[cfg(test)]
                stall_seam::pass(&seam_path, stall_seam::Role::Sealed);
            }),
        );
        super::persistence::run_shutdown_saves(deadline, vec![close]).await;
        #[cfg(test)]
        stall_seam::pass(&drain_seam_path, stall_seam::Role::Draining);
        // Every write this saver began ends before its handle resolves, within
        // the same bound as the seal. A disk stalled past it keeps its thread
        // detached (MIK-8157): shutdown is never held longer.
        if tokio::time::timeout_at(deadline, writers.idle())
            .await
            .is_err()
        {
            warn!("{NOT_DURABLE}: a window write is still running");
        }
    }))
}

/// Open the segment on a detached thread holding the sink mutex. Resolves to
/// whether it opened; a stalled open keeps the mutex until it finishes.
fn open_detached(
    writers: &Arc<Writers>,
    sink: &Sink,
    data_dir: &std::path::Path,
    identity: &WriterIdentity,
    clock_ms: fn() -> Result<u64, ClockBeforeEpoch>,
) -> impl std::future::Future<Output = Result<bool, tokio::sync::oneshot::error::RecvError>> {
    let (done, opened) = tokio::sync::oneshot::channel();
    let (sink, data_dir, identity) = (Arc::clone(sink), data_dir.to_path_buf(), identity.clone());
    let spawned = writers.spawn("protocol-revision window open", move || {
        let mut held = sink
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = done.send(open_into(&mut held, &data_dir, identity, clock_ms));
    });
    if let Err(error) = spawned {
        warn!(%error, "the window open could not start a thread");
    }
    opened
}

/// Open into `held` unless already open. `true` once a sink is held; never
/// after the seal.
fn open_into(
    held: &mut SinkState,
    data_dir: &std::path::Path,
    identity: WriterIdentity,
    clock_ms: fn() -> Result<u64, ClockBeforeEpoch>,
) -> bool {
    match held {
        SinkState::Open(_) => return true,
        SinkState::Sealed => return false,
        SinkState::Unopened => {}
    }
    let Ok(now_ms) = clock_ms() else {
        return false;
    };
    match HttpSegmentSink::open(data_dir, identity, now_ms / 1_000) {
        Ok(opened) => {
            *held = SinkState::Open(opened);
            true
        }
        Err(error) => {
            warn!(%error, data_dir = %data_dir.display(), "{NOT_DURABLE}");
            false
        }
    }
}

/// One periodic checkpoint on a detached thread. A tick that finds the sink
/// busy skips (`try_lock`); with no sink yet, it retries the open first.
/// Counts are cumulative from process start, so a skipped tick loses nothing.
fn checkpoint_detached(
    writers: &Arc<Writers>,
    sink: &Sink,
    data_dir: &std::path::Path,
    identity: &WriterIdentity,
    counts: &CountsFn,
    clock_ms: fn() -> Result<u64, ClockBeforeEpoch>,
) {
    let (sink, data_dir, identity) = (Arc::clone(sink), data_dir.to_path_buf(), identity.clone());
    let counts = Arc::clone(counts);
    let spawned = writers.spawn("protocol-revision window checkpoint", move || {
        #[cfg(test)]
        let seam_path = window_paths(&data_dir).0;
        #[cfg(test)]
        stall_seam::pass(&seam_path, stall_seam::Role::BeforeLock);
        let run = || {
            let mut held = match sink.try_lock() {
                Ok(held) => held,
                Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => return,
            };
            if !open_into(&mut held, &data_dir, identity, clock_ms) {
                return;
            }
            let (SinkState::Open(sink), Ok(now_ms)) = (&mut *held, clock_ms()) else {
                return;
            };
            if let Err(error) = sink.checkpoint(&counts(false), now_ms / 1_000) {
                warn!(%error, "failed to checkpoint the HTTP protocol-revision window segment");
            }
        };
        run();
        #[cfg(test)]
        stall_seam::pass(&seam_path, stall_seam::Role::CheckpointDone);
    });
    if let Err(error) = spawned {
        warn!(%error, "a window checkpoint could not start a thread; skipped");
    }
}

#[cfg(test)]
#[path = "window_saver_tests.rs"]
mod tests;
