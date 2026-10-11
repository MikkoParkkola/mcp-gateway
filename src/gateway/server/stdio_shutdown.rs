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
use tracing::{error, warn};

use super::{Gateway, StdioTelemetry, stdio_tasks, task_runtime, warmstart::WarmerGuard};

/// The teardown window after the stdio drain window.
pub(super) const STDIO_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(10);

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
    pub(super) fn persist_stdio_protocol_telemetry(sink: &StdioTelemetry) {
        use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
        static CALLS: AtomicU64 = AtomicU64::new(0);
        static SOME: AtomicU64 = AtomicU64::new(0);
        static TOTAL_US: AtomicU64 = AtomicU64::new(0);
        let started = std::time::Instant::now();
        let has_sink = Self::persist_stdio_protocol_telemetry_inner(sink);
        let us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        let total = TOTAL_US.fetch_add(us, Relaxed) + us;
        let some = SOME.fetch_add(u64::from(has_sink), Relaxed) + u64::from(has_sink);
        let n = CALLS.fetch_add(1, Relaxed) + 1;
        if n % 100 == 0 {
            eprintln!(
                "T14DIAG {} persist calls={n} with_sink={some} total_ms={} last_us={us}",
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0),
                total / 1000
            );
        }
    }

    fn persist_stdio_protocol_telemetry_inner(sink: &StdioTelemetry) -> bool {
        let mut sink = sink
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(sink) = sink.as_mut()
            && let Err(error) = sink.persist_global()
        {
            warn!(
                %error,
                "failed to persist stdio protocol-revision telemetry; measurement window is incomplete"
            );
        }
        sink.is_some()
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

    /// Everything after the writer join, each step under `deadline`.
    pub(super) async fn stdio_teardown(
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
        bounded_step(deadline, "backend stop", self.backends.stop_all()).await;
    }
}
