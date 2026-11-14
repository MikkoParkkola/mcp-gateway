// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How the runtime ends once `dispatch` returned.

use crate::cli::Command;

/// How long a serving gateway's runtime may wait, after `dispatch` returned, for
/// blocking-pool work still running. Stdio: a stdout write a client
/// stopped reading, which the serve loop already gave up on at its drain
/// deadline. HTTP (MIK-8084): a task-store or audit write stuck on a stalled
/// mount. On a healthy disk what is left is a few millisecond writes, and
/// everything network-bound (request drain, custody refresh) was awaited
/// inside `dispatch` under `server.shutdown_timeout`; without a bound the process
/// never exits.
pub(crate) const SERVE_RUNTIME_SHUTDOWN_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(10);

/// How long `doctor`'s runtime may wait, after `dispatch` returned, for
/// blocking-pool work still running: doctor's npm lookup resolves names
/// on the blocking pool, and a stalled DNS lookup must not hold the exit.
pub(crate) const DOCTOR_RUNTIME_SHUTDOWN_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(1);

/// What `cli::run` does with the runtime once `dispatch` returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RuntimeShutdown {
    /// Wait for every blocking-pool task. Every command but `serve` and
    /// `doctor`: a one-shot command's own writes must not be cut.
    WaitForBlockingWork,
    /// Wait this long, then exit behind whatever is still running. Every serve
    /// mode: stdio loses at most the one in-flight fragment a slow client
    /// stopped reading; HTTP leaves behind only a write stuck on a stalled
    /// mount, which an unbounded wait would never finish either. `doctor`
    /// too, behind a stalled DNS lookup (see
    /// [`DOCTOR_RUNTIME_SHUTDOWN_TIMEOUT`]).
    Bounded(std::time::Duration),
}

impl RuntimeShutdown {
    pub(crate) fn of(command: Option<&Command>) -> Self {
        match command {
            // No subcommand serves HTTP.
            Some(Command::Serve { .. }) | None => Self::Bounded(SERVE_RUNTIME_SHUTDOWN_TIMEOUT),
            Some(Command::Doctor { .. }) => Self::Bounded(DOCTOR_RUNTIME_SHUTDOWN_TIMEOUT),
            Some(_) => Self::WaitForBlockingWork,
        }
    }
}

/// The runtime, shut down by its mode when dropped: on the normal path and on
/// a panic out of `dispatch` alike.
struct ShutdownGuard {
    runtime: Option<tokio::runtime::Runtime>,
    mode: RuntimeShutdown,
    /// The HTTP stop's plan, once stored: its runtime deadline bounds the wait.
    plan: crate::retire::RetireCell,
}

impl ShutdownGuard {
    /// Shut the runtime down now; whether work was left running.
    fn shut_down(&mut self) -> bool {
        self.runtime
            .take()
            .is_some_and(|runtime| shut_down(runtime, self.mode, self.plan.get().copied()))
    }
}

impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        self.shut_down();
    }
}

/// Shut `runtime` down by `mode`. With an HTTP stop's `plan`, a bounded wait
/// also ends by the plan's runtime deadline. Returns whether a bounded wait ran
/// out with blocking work still running, which it also logs at ERROR so an
/// operator can tell a stalled disk or mount from a clean exit.
pub(crate) fn shut_down(
    runtime: tokio::runtime::Runtime,
    mode: RuntimeShutdown,
    plan: Option<crate::retire::RetirePlan>,
) -> bool {
    let RuntimeShutdown::Bounded(timeout) = mode else {
        drop(runtime);
        return false;
    };
    let timeout = wait_bound(timeout, plan, tokio::time::Instant::now());
    let started = std::time::Instant::now();
    runtime.shutdown_timeout(timeout);
    // `shutdown_timeout` returns as soon as the blocking pool is idle, so a
    // wait that lasted the whole bound is read as work left running. Work
    // that ended in the bound's last instant reads the same; the log is a
    // pointer to look at the disk, not a proof.
    let left_running = started.elapsed() >= timeout;
    if left_running {
        tracing::error!(
            target: "mcp_gateway::runtime",
            ?timeout,
            "shutdown exited with blocking work still running after the bound \
             (a disk or mount write that never returned; under doctor, its 1 s bound, \
             possibly the npm lookup's name resolution?)"
        );
    }
    left_running
}

/// The runtime's wait for blocking work: `timeout`, or under an HTTP stop's
/// plan the lesser of [`crate::retire::RUNTIME_WAIT_CAP`] and what is left to
/// the plan's runtime deadline at `now` (none once it has passed).
pub(crate) fn wait_bound(
    timeout: std::time::Duration,
    plan: Option<crate::retire::RetirePlan>,
    now: tokio::time::Instant,
) -> std::time::Duration {
    // STUB (red run): the plan does not bound the wait.
    let _ = (plan, now);
    timeout
}

/// Run `future` to completion on a new multi-thread runtime, then shut the
/// runtime down by `mode` (bounded by the plan in `plan`, once stored), on the
/// normal path and on a panic alike. Returns the output and whether the
/// shutdown left blocking work running.
pub(crate) fn block_on<F: std::future::Future>(
    mode: RuntimeShutdown,
    plan: &crate::retire::RetireCell,
    future: F,
) -> (F::Output, bool) {
    let mut guard = ShutdownGuard {
        runtime: Some(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("build the tokio runtime"),
        ),
        mode,
        plan: std::sync::Arc::clone(plan),
    };
    let output = guard
        .runtime
        .as_ref()
        .expect("the guard holds the runtime until it shuts down")
        .block_on(future);
    let left_running = guard.shut_down();
    (output, left_running)
}

#[cfg(test)]
#[path = "main_runtime_tests.rs"]
mod tests;
