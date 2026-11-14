// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The stdio teardown after EOF, under one stated deadline (MIK-7685).
//!
//! `run_stdio_on` returns within `STDIO_DRAIN_TIMEOUT + STDIO_TEARDOWN_TIMEOUT`
//! of EOF, whatever a backend stop, the custody store, a task or a disk write
//! does. A step still running at the deadline is abandoned and logged by
//! name; a blocking write keeps its thread, and the process exits behind it.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;
use tracing::{debug, error, warn};

use super::{Gateway, StdioTelemetry, stdio_tasks, task_runtime, warmstart::WarmerGuard};

/// The teardown window after the stdio drain window.
pub(super) const STDIO_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// A fresh signal listener and orphan watch armed when the read loop exits.
/// Windows has no SIGTERM path here: a parent's stop is a job kill. If a
/// parent cannot close stdin, its single SIGTERM is consumed by the read
/// loop as the first signal; that case stays out of scope.
pub(super) struct Hurry {
    signal: std::pin::Pin<Box<dyn Future<Output = ()> + Send>>,
    ready: bool,
    cut: Option<Instant>,
    deadline: Arc<crate::transport::StopDeadline>,
}

impl Hurry {
    fn new(
        signal: impl Future<Output = ()> + Send + 'static,
        deadline: Arc<crate::transport::StopDeadline>,
    ) -> Self {
        let mut signal = Box::pin(signal);
        // Register the OS handlers now, before any drain or other await.
        let ready = futures::FutureExt::now_or_never(signal.as_mut()).is_some();
        Self {
            signal,
            ready,
            cut: None,
            deadline,
        }
    }

    async fn wait(&mut self) -> Instant {
        if !self.ready {
            self.signal.as_mut().await;
            self.ready = true;
        }
        *self
            .cut
            .get_or_insert_with(|| self.deadline.hurry(std::time::Instant::now()).into())
    }
}

fn parent_pid() -> i32 {
    #[cfg(unix)]
    return rustix::process::getppid().map_or(0, |pid| pid.as_raw_nonzero().get());
    #[cfg(not(unix))]
    0
}

/// A hurry flushes the reply drain only while that drain is still running: a
/// finished drain future is never polled again (a fused one would wait out the
/// whole cut for nothing).
pub(super) fn flush_pending(hurried: bool, drain_finished: bool) -> bool {
    hurried && !drain_finished
}

/// Run one teardown step under `deadline`. `None` when it did not finish:
/// the step is dropped, and the expiry logged by name.
pub(super) async fn bounded_step<F: Future>(
    deadline: Instant,
    step: &str,
    future: F,
) -> Option<F::Output> {
    let finished = tokio::time::timeout_at(deadline, future).await.ok();
    if finished.is_none() {
        // ERROR: an abandoned step may be a write that never landed.
        error!(
            step,
            "shutdown step did not finish within its deadline; abandoned"
        );
    }
    finished
}

/// Run a synchronous step (disk I/O) under `deadline`, on its own detached
/// thread rather than the blocking pool: the runtime's drop waits for every
/// blocking-pool task, so a stuck write there would still hold the process
/// open after `run_stdio_on` returned. A detached thread ends with the process.
pub(super) async fn bounded_blocking(
    deadline: Instant,
    step: &str,
    work: impl FnOnce() + Send + 'static,
) {
    let (done, finished) = tokio::sync::oneshot::channel();
    let spawned = std::thread::Builder::new()
        .name(format!("shutdown: {step}"))
        .spawn(move || {
            work();
            let _ = done.send(());
        });
    if let Err(error) = spawned {
        warn!(step, %error, "shutdown step could not start a thread; skipped");
        return;
    }
    bounded_step(deadline, step, finished).await;
}

/// The final cost snapshot, after the drain so the last calls' spend is in
/// it. The periodic saver is stopped first, so an older save cannot land
/// after; if it does not stop in time, it may still be writing, and the final
/// save is skipped rather than raced.
#[cfg(feature = "cost-governance")]
pub(super) async fn final_cost_save(
    deadline: Instant,
    saver: Option<super::AbortOnDrop>,
    enforcer: Arc<crate::cost_accounting::enforcer::BudgetEnforcer>,
    data_dir: std::path::PathBuf,
) {
    if let Some(saver) = saver
        && bounded_step(deadline, "cost saver stop", saver.stop())
            .await
            .is_none()
    {
        warn!("stdio: final cost snapshot skipped: the periodic saver is still running");
        return;
    }
    bounded_blocking(deadline, super::persistence::COST_SAVE_STEP, move || {
        super::persistence::save_costs(&enforcer, &data_dir);
    })
    .await;
}

/// Capture at startup, but poll only after the read loop ends. The future
/// belongs to Hurry, so teardown completion or cancellation drops the watch.
pub(super) fn orphan_watch(
    #[cfg(test)] injected: Option<Arc<dyn Fn() -> i32 + Send + Sync>>,
) -> impl Future<Output = ()> + Send + 'static {
    #[cfg(test)]
    let read = move || injected.as_ref().map_or_else(parent_pid, |read| read());
    #[cfg(not(test))]
    let read = parent_pid;
    let saved = read();
    async move {
        if !cfg!(unix) || saved <= 1 {
            std::future::pending::<()>().await;
        }
        let mut polls = tokio::time::interval(Duration::from_millis(50));
        loop {
            polls.tick().await;
            if read() != saved {
                return;
            }
        }
    }
}

impl Gateway {
    pub(super) fn stdio_hurry(
        &self,
        orphan: impl Future<Output = ()> + Send + 'static,
        eof_with_signal: bool,
    ) -> Hurry {
        let (signal_tx, _) = tokio::sync::broadcast::channel(1);
        #[cfg(test)]
        let signal = super::test_seams::shutdown_signal_or_trigger(
            signal_tx,
            self.test_seams.take_hurry_trigger(),
        );
        #[cfg(not(test))]
        let signal = super::support::shutdown_signal(signal_tx);
        let signal = async move {
            tokio::select! {
                biased;
                () = std::future::ready(()), if eof_with_signal => {},
                () = signal => {},
                () = orphan => {},
            }
        };
        Hurry::new(signal, self.backends.stop_deadline())
    }

    /// Save the protocol-revision window, waiting for a save already in
    /// flight. The final save at shutdown: after the saver's ticks stop, it
    /// takes the sink lock as soon as the last tick's write ends and saves
    /// what is left. Every save runs under this one lock, so no two overlap
    /// and no delta is counted twice (MIK-8364).
    pub(super) fn persist_stdio_protocol_telemetry(sink: &StdioTelemetry) {
        let mut sink = sink
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::persist_held(sink.as_mut());
    }

    /// The saver's tick: save the window unless a save is still in flight,
    /// in which case skip; the next tick carries this tick's delta, because a
    /// save advances its baseline only after a successful write (MIK-8364).
    pub(super) fn save_stdio_protocol_telemetry_unless_busy(sink: &StdioTelemetry) {
        match sink.try_lock() {
            Ok(mut held) => Self::persist_held(held.as_mut()),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                Self::persist_held(poisoned.into_inner().as_mut());
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                debug!("stdio protocol telemetry save skipped: the previous save has not finished");
            }
        }
    }

    fn persist_held(sink: Option<&mut crate::protocol_revision_telemetry::DurableTelemetrySink>) {
        if let Some(sink) = sink
            && let Err(error) = sink.persist_global()
        {
            warn!(
                %error,
                "failed to persist stdio protocol-revision telemetry; measurement window is incomplete"
            );
        }
    }

    /// The protocol telemetry save, on a detached thread under `deadline`.
    pub(super) async fn persist_stdio_telemetry_bounded(
        deadline: Instant,
        sink: &Arc<StdioTelemetry>,
    ) {
        let sink = Arc::clone(sink);
        bounded_blocking(deadline, "protocol telemetry save", move || {
            Self::persist_stdio_protocol_telemetry(&sink);
        })
        .await;
    }

    /// Preparations after the writer join, each step under `deadline`.
    async fn stdio_before_backends(
        &self,
        deadline: Instant,
        warm_start_tasks: WarmerGuard,
        task_store: Option<(
            Arc<stdio_tasks::StdioTasks>,
            crate::gateway::task_service::execution::ExpirySweep,
        )>,
    ) {
        #[cfg(test)]
        self.test_seams.stdio_before_backends_hold.pause().await;
        // Awaited, not left to the drop guard: an abort is asynchronous, so a
        // retry task mid-`ensure_started` would otherwise still be starting a
        // backend while `stop_all` drains it, delaying shutdown and logging
        // starts for a gateway that is on its way out. The guard remains the
        // backstop for every path that does not reach this line.
        bounded_step(deadline, "warm-start cancel", warm_start_tasks.cancel()).await;
        // Tasks before custody and backends: a worker's dispatch IS a backend call.
        if let Some((tasks, expiry)) = task_store {
            let timeout = self.config.server.shutdown_timeout;
            bounded_step(
                deadline,
                "task store shutdown",
                stdio_tasks::shutdown(
                    &tasks,
                    expiry,
                    task_runtime::ShutdownBudget::within(
                        deadline.saturating_duration_since(Instant::now()),
                        timeout,
                    ),
                ),
            )
            .await;
        }
        // Release the custody store before the backends go, bounded like the
        // HTTP stop: a release thread that cannot start leaks the store to exit
        // instead of parking its drop on the blocking pool. A cancelled or
        // failed serve detaches it through its serve guard instead.
        if let Some(Err(e)) = bounded_step(
            deadline,
            "account custody shutdown",
            self.shutdown_account_custody_by(deadline),
        )
        .await
        {
            warn!(error = %e, "Personal account custody shutdown failed");
        }
        // A cut custody step leaves the store in the handle: hand it to a
        // detached thread now, so the gateway's drop never releases it here.
        self.detach_custody_release();
    }

    /// A fresh signal cancels the remaining preparations, then cuts backend
    /// waits too if it arrives after those preparations have finished.
    pub(super) async fn stdio_teardown(
        &self,
        deadline: Instant,
        warm_start_tasks: WarmerGuard,
        task_store: Option<(
            Arc<stdio_tasks::StdioTasks>,
            crate::gateway::task_service::execution::ExpirySweep,
        )>,
        mut hurry: Hurry,
        before: impl Future<Output = ()>,
    ) {
        // Pinned outside the select below: a hurry stops waiting for the
        // preparations that follow it, but replies already produced, and calls
        // the backend kill will fail, are still written before the cut.
        let before = futures::FutureExt::fuse(before);
        tokio::pin!(before);
        let hurried = tokio::select! {
            biased;
            cut = hurry.wait() => {
                warn!("shutdown hurried by a signal; stopping backends now");
                Some(cut)
            }
            () = async {
                before.as_mut().await;
                self.stdio_before_backends(deadline, warm_start_tasks, task_store).await;
            } => None,
        };
        // The backends' waits are planned to end by the teardown deadline (or
        // shutdown_timeout from now, if sooner), so their kill lands before
        // this process returns.
        let mut stop_deadline = deadline.min(Instant::now() + self.config.server.shutdown_timeout);
        if let Some(cut) = hurried {
            stop_deadline = stop_deadline.min(cut);
        }
        let backend_deadline = hurried.map_or(deadline, |cut| deadline.min(cut));
        #[allow(
            clippy::disallowed_methods,
            reason = "Lifecycle: gateway startup, wiring or shutdown; no caller request"
        )]
        let stop = self.backends.stop_all_by(stop_deadline);
        tokio::pin!(stop);
        tokio::select! {
            biased;
            cut = hurry.wait(), if hurried.is_none() => {
                self.backends
                    .hand_over_now(cut.saturating_duration_since(Instant::now()));
                bounded_step(deadline.min(cut), "backend stop", stop).await;
            }
            () = async {
                let stopped = bounded_step(backend_deadline, "backend stop", &mut stop);
                // A hurry that lands after the drain finished (during the
                // post-drain cleanup) has nothing left to flush: a finished
                // future is never polled again.
                let drained = futures::future::FusedFuture::is_terminated(&before);
                if flush_pending(hurried.is_some(), drained) {
                    // The kill fails the calls it reaches, so their replies
                    // join those already produced; both go out before the cut.
                    let flushed =
                        bounded_step(backend_deadline, "reply flush", before.as_mut());
                    tokio::join!(stopped, flushed);
                } else {
                    stopped.await;
                }
            } => {}
        }
    }
}
