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

/// A fresh signal listener installed synchronously when the read loop exits.
/// Windows has no SIGTERM path here: a parent's stop is a job kill. If a
/// parent cannot close stdin, its single SIGTERM is consumed by the read
/// loop as the first signal; that case stays out of scope.
pub(super) struct Hurry {
    signal: std::pin::Pin<Box<dyn Future<Output = ()> + Send>>,
    ready: bool,
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
            deadline,
        }
    }

    async fn wait(&mut self) -> Instant {
        if !self.ready {
            self.signal.as_mut().await;
        }
        self.deadline.hurry(std::time::Instant::now()).into()
    }
}

/// Dropping cancelled preparations must abort the writer, not detach it.
pub(super) struct AbortWriter(pub(super) tokio::task::AbortHandle);

impl Drop for AbortWriter {
    fn drop(&mut self) {
        self.0.abort();
    }
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

impl Gateway {
    pub(super) fn stdio_hurry(&self) -> Hurry {
        let (signal_tx, _) = tokio::sync::broadcast::channel(1);
        #[cfg(test)]
        let signal = super::test_seams::shutdown_signal_or_trigger(
            signal_tx,
            self.test_seams.take_hurry_trigger(),
        );
        #[cfg(not(test))]
        let signal = super::support::shutdown_signal(signal_tx);
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
        // Release the custody store before the backends go. Reached on the EOF
        // path only: a cancelled `run_stdio` releases it by dropping the Gateway.
        if let Some(Err(e)) = bounded_step(
            deadline,
            "account custody shutdown",
            self.shutdown_account_custody(),
        )
        .await
        {
            warn!(error = %e, "Personal account custody shutdown failed");
        }
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
        let hurried = tokio::select! {
            biased;
            cut = hurry.wait() => {
                warn!("shutdown hurried by a signal; stopping backends now");
                Some(cut)
            }
            () = async {
                before.await;
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
                bounded_step(deadline.min(cut), "backend stop", stop).await;
            }
            () = async {
                bounded_step(backend_deadline, "backend stop", &mut stop).await;
            } => {}
        }
    }
}
