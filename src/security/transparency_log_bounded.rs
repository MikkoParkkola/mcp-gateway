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
    /// Appends refused at once because the log was stalled (D3-a).
    #[cfg(test)]
    pub(crate) refused_under_stall: std::sync::atomic::AtomicUsize,
    /// Appends that reached the permit wait (MIK-7912).
    #[cfg(test)]
    pub(crate) permit_waits: std::sync::atomic::AtomicUsize,
    /// Answers given because of a stall: a timed-out append, or a call or
    /// append refused while stalled (MIK-8171).
    #[cfg(test)]
    pub(crate) stall_answers: std::sync::atomic::AtomicUsize,
    /// D3-a R4: one-shot fault for the next append of this `kind`.
    #[cfg(test)]
    pub(crate) fail_next_kind: std::sync::Mutex<Option<String>>,
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
            #[cfg(test)]
            refused_under_stall: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            permit_waits: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            stall_answers: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            fail_next_kind: std::sync::Mutex::new(None),
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
        self.append_bounded_within(None, op).await
    }

    /// [`Self::append_bounded`] with an optional tighter `cap` on both bounds.
    /// The cap is one deadline shared by the permit wait and the write. A
    /// caller that wants a tighter bound passes it here rather than wrapping
    /// the future in its own timeout: dropping the future would skip the stall
    /// bookkeeping and the timeout metric (#2252).
    pub(crate) async fn append_bounded_within<T, F>(
        self: &Arc<Self>,
        cap: Option<Duration>,
        op: F,
    ) -> io::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&TransparencyLogger) -> io::Result<T> + Send + 'static,
    {
        // While stalled every append is refused at once, with no wait and no
        // thread; a best-effort caller logs it and serves anyway.
        if self.is_stalled() {
            #[cfg(test)]
            {
                self.bound
                    .refused_under_stall
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.bound
                    .stall_answers
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            return Err(timed_out());
        }
        let limit = cap.map_or(self.append_timeout(), |c| c.min(self.append_timeout()));
        let started = tokio::time::Instant::now();
        // The write this caller queues behind, if any: a permit wait that
        // times out marks the log stalled only if that same write is still in
        // the kernel, not a fresh one that took the permit at the boundary.
        let queued_behind = self.bound.state.lock().ok().and_then(|s| s.in_flight);
        #[cfg(test)]
        self.bound.permit_waits.fetch_add(1, Ordering::SeqCst);
        let permit = tokio::time::timeout(limit, Arc::clone(&self.bound.permit).acquire_owned())
            .await
            .map_err(|_| self.mark_stalled(queued_behind))?
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
        // A capped caller gets one deadline across the permit wait and the
        // write; an uncapped one keeps the two full bounds (F20).
        let write_limit = if cap.is_some() {
            limit.saturating_sub(started.elapsed())
        } else {
            limit
        };
        match tokio::time::timeout(write_limit, task).await {
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
        self.bound.stall_answers.fetch_add(1, Ordering::SeqCst);
        #[cfg(test)]
        {
            let hook = self.bound.before_mark.lock().expect("hook lock").take();
            if let Some(f) = hook {
                f();
            }
        }
        telemetry_metrics::counter!("mcp_audit_append_timeouts_total").increment(1);
        if let Ok(mut s) = self.bound.state.lock()
            && generation.is_some()
            && s.in_flight == generation
        {
            s.stalled = true;
            tracing::error!("audit append timed out; the audit log is stalled");
        }
        timed_out()
    }
}

#[cfg(test)]
impl TransparencyLogger {
    /// Test seam for callers outside this module: bound every append at
    /// `limit`, and block the next write until the returned barrier is
    /// released or dropped (a write stuck in the kernel).
    pub(crate) fn stall_next_write_for_test(
        &self,
        limit: Duration,
    ) -> super::rotation::StallRelease {
        *self.bound.limit.lock().expect("limit lock") = limit;
        let b = Arc::new(super::rotation::StallGate::default());
        *self.hooks.stall.lock().expect("stall lock") = Some(Arc::clone(&b));
        super::rotation::StallRelease(b)
    }

    /// On a stalled log, bound every append past the stall gate's hang
    /// guard. A call that queued on the permit would then outlast the held
    /// write, which clears the stall; one refused at once leaves it stalled.
    pub(crate) fn lift_append_bound_for_test(&self) {
        assert!(self.is_stalled(), "lift the bound only while stalled");
        *self.bound.limit.lock().expect("limit lock") = super::rotation::StallGate::DEADLINE * 2;
    }

    /// Answers given because of a stall so far (MIK-8171).
    pub(crate) fn stall_answers_for_test(&self) -> usize {
        self.bound.stall_answers.load(Ordering::SeqCst)
    }

    /// Appends that reached the permit wait: a test holding the permit with a
    /// stalled write sees a later append queue behind it (MIK-7912).
    pub(crate) fn permit_waits_for_test(&self) -> usize {
        self.bound.permit_waits.load(Ordering::SeqCst)
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

#[cfg(test)]
impl TransparencyLogger {
    /// Instance-local one-shot I/O fault for the next append whose `kind`
    /// field equals `kind`; other appends pass (D3-a R4).
    pub(crate) fn fail_next_append_of_kind_for_test(&self, kind: &str) {
        *self.bound.fail_next_kind.lock().expect("fault lock") = Some(kind.to_string());
    }

    /// Bounded appends refused at once because the log was stalled (D3-a):
    /// lets a cell prove a spawned write took the bounded path.
    pub(crate) fn refused_under_stall_for_test(&self) -> usize {
        self.bound.refused_under_stall.load(Ordering::SeqCst)
    }

    /// Whether an injected fault fails this append: the kind-scoped one-shot,
    /// the instance one-shot, or the persistent fault.
    pub(super) fn injected_fault(
        &self,
        fields: &serde_json::Map<String, serde_json::Value>,
    ) -> bool {
        // A record without a `kind` is named by its `event` (a `tenant_read`).
        let kind = fields
            .get("kind")
            .or_else(|| fields.get("event"))
            .and_then(serde_json::Value::as_str);
        let mut armed = self.bound.fail_next_kind.lock().expect("fault lock");
        let kind_hit = kind.is_some() && armed.as_deref() == kind && armed.take().is_some();
        drop(armed);
        kind_hit
            || self.fail_next_append.swap(false, Ordering::AcqRel)
            || self.fail_appends.load(Ordering::Acquire)
    }
}
