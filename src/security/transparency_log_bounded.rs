// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F20: a bounded audit append for async callers.
//!
//! A blocked `write(2)` cannot be cancelled, and the thread doing it holds
//! the chain lock until the kernel returns. So the bound works around the
//! lock rather than through it: the append runs on the blocking pool, never
//! on a runtime worker; a one-permit semaphore keeps at most one blocking
//! thread parked on a stuck write; a timeout marks the log `stalled`, which
//! fail-closed callers then refuse at once; the stuck write clears it when
//! it finally returns (UPGRADING item 50).

use std::io;
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::TransparencyLogger;

/// Bound on waiting for the append permit, and, separately, on the write
/// itself. Above the 2 s probe bound because a normal append may include a
/// D6 rotation (fsyncs plus a 1 MiB reserve write).
pub(crate) const AUDIT_APPEND_TIMEOUT: Duration = Duration::from_secs(5);

/// Stall bookkeeping, a leaf lock never held across I/O.
#[derive(Default)]
pub(crate) struct StallState {
    next_gen: u64,
    in_flight: Option<u64>,
    stalled: bool,
}

/// Per-logger F20 state.
pub(crate) struct Bound {
    permit: Arc<tokio::sync::Semaphore>,
    state: std::sync::Mutex<StallState>,
    /// Blocking closures started, for the one-thread-parked rows.
    #[cfg(test)]
    pub(crate) closures_entered: std::sync::atomic::AtomicUsize,
    /// [`AUDIT_APPEND_TIMEOUT`]; tests shorten it.
    pub(crate) limit: std::sync::Mutex<Duration>,
    /// Runs once when a timeout is noticed, before the stall lock is taken.
    #[cfg(test)]
    pub(crate) before_mark: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Default for Bound {
    fn default() -> Self {
        Self {
            permit: Arc::new(tokio::sync::Semaphore::new(1)),
            state: std::sync::Mutex::new(StallState::default()),
            #[cfg(test)]
            closures_entered: std::sync::atomic::AtomicUsize::new(0),
            limit: std::sync::Mutex::new(AUDIT_APPEND_TIMEOUT),
            #[cfg(test)]
            before_mark: std::sync::Mutex::new(None),
        }
    }
}

fn timed_out() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "audit append timed out: the log is stalled",
    )
}

impl TransparencyLogger {
    fn append_timeout(&self) -> Duration {
        self.bound.limit.lock().map_or(AUDIT_APPEND_TIMEOUT, |l| *l)
    }

    /// Whether a timed-out append is still stuck in the kernel.
    #[must_use]
    pub(crate) fn is_stalled(&self) -> bool {
        self.bound.state.lock().is_ok_and(|s| s.stalled)
    }

    /// Run `op` (one append) on the blocking pool, bounded twice by
    /// [`AUDIT_APPEND_TIMEOUT`]: once waiting for the single permit, once
    /// for the write. While the log is stalled it refuses at once, with no
    /// wait and no thread.
    ///
    /// # Errors
    ///
    /// The append's own error, or `ErrorKind::TimedOut` when either bound
    /// expires (the log is then marked stalled).
    pub(crate) async fn append_bounded<T, F>(self: &Arc<Self>, op: F) -> io::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&TransparencyLogger) -> io::Result<T> + Send + 'static,
    {
        // RED: the append runs inline on the caller's worker, unbounded.
        if std::hint::black_box(true) {
            return op(self);
        }
        // While stalled every append is refused at once, with no wait and no
        // thread; a best-effort caller logs it and serves anyway.
        if self.is_stalled() {
            return Err(timed_out());
        }
        let limit = self.append_timeout();
        let permit = tokio::time::timeout(limit, Arc::clone(&self.bound.permit).acquire_owned())
            .await
            .map_err(|_| self.mark_stalled(None))?
            .map_err(|_| io::Error::other("audit append permit closed"))?;
        let generation = {
            let mut s = self
                .bound
                .state
                .lock()
                .map_err(|_| io::Error::other("stall lock"))?;
            s.next_gen += 1;
            s.in_flight = Some(s.next_gen);
            s.next_gen
        };
        let logger = Arc::clone(self);
        let task = tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            logger.bound.closures_entered.fetch_add(1, Ordering::AcqRel);
            let result = op(&logger);
            // Record first, then clear the stall, then free the permit, so a
            // caller that sees the log unstalled also sees this result.
            if let Ok(mut s) = logger.bound.state.lock()
                && s.in_flight == Some(generation)
            {
                s.in_flight = None;
                s.stalled = false;
            }
            drop(permit);
            result
        });
        match tokio::time::timeout(limit, task).await {
            Ok(Ok(result)) => result,
            Ok(Err(join)) => Err(io::Error::other(format!(
                "audit append task failed: {join}"
            ))),
            Err(_) => Err(self.mark_stalled(Some(generation))),
        }
    }

    /// Mark the log stalled, but only while `generation` is still in the
    /// kernel: a write that finished in the window since the timeout has
    /// already cleared `in_flight`, so the flag cannot stick (F20 r3).
    fn mark_stalled(&self, generation: Option<u64>) -> io::Error {
        #[cfg(test)]
        {
            let hook = self.bound.before_mark.lock().expect("hook lock").take();
            if let Some(f) = hook {
                f();
            }
        }
        telemetry_metrics::counter!("mcp_audit_append_timeouts_total").increment(1);
        if let Ok(mut s) = self.bound.state.lock() {
            let still_stuck = match generation {
                Some(g) => s.in_flight == Some(g),
                None => s.in_flight.is_some(),
            };
            if still_stuck {
                s.stalled = true;
            }
        }
        tracing::error!("audit append timed out; the audit log is stalled");
        timed_out()
    }
}

#[cfg(test)]
impl TransparencyLogger {
    /// Test seam for callers outside this module: bound every append at
    /// `limit`, and block the next write until the returned barrier is
    /// released (a write stuck in the kernel), for at most 3 s.
    pub(crate) fn stall_next_write_for_test(
        &self,
        limit: Duration,
    ) -> Arc<super::rotation::StallGate> {
        *self.bound.limit.lock().expect("limit lock") = limit;
        let b = Arc::new(super::rotation::StallGate::default());
        *self.hooks.stall.lock().expect("stall lock") = Some(Arc::clone(&b));
        b
    }

    /// Whether a write's generation is still in the kernel.
    pub(crate) fn write_in_flight_for_test(&self) -> bool {
        self.bound
            .state
            .lock()
            .expect("stall lock")
            .in_flight
            .is_some()
    }
}
