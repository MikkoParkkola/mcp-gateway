// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How the runtime ends once `run` returned (MIK-7683).

use mcp_gateway::cli::Command;

/// How long a serving gateway's runtime may wait, after `run` returned, for
/// blocking-pool work still running. Stdio (MIK-7683): a stdout write a client
/// stopped reading, which the serve loop already gave up on at its drain
/// deadline. HTTP (MIK-8084): a task-store or audit write stuck on a stalled
/// mount. On a healthy disk what is left is a few millisecond writes, and
/// everything network-bound (request drain, custody refresh) was awaited
/// inside `run` under `server.shutdown_timeout`; without a bound the process
/// never exits.
pub(crate) const SERVE_RUNTIME_SHUTDOWN_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(10);

/// What `main` does with the runtime once `run` returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RuntimeShutdown {
    /// Wait for every blocking-pool task. Every command but `serve`: a one-shot
    /// command's own writes must not be cut.
    WaitForBlockingWork,
    /// Wait this long, then exit behind whatever is still running. Every serve
    /// mode: stdio loses at most the one in-flight fragment a slow client
    /// stopped reading; HTTP leaves behind only a write stuck on a stalled
    /// mount, which an unbounded wait would never finish either.
    Bounded(std::time::Duration),
}

impl RuntimeShutdown {
    pub(crate) fn of(command: Option<&Command>) -> Self {
        match command {
            // No subcommand serves HTTP.
            Some(Command::Serve { .. }) | None => Self::Bounded(SERVE_RUNTIME_SHUTDOWN_TIMEOUT),
            Some(_) => Self::WaitForBlockingWork,
        }
    }
}

/// The runtime, shut down by its mode when dropped: on the normal path and on
/// a panic out of `run` alike.
struct ShutdownGuard {
    runtime: Option<tokio::runtime::Runtime>,
    mode: RuntimeShutdown,
}

impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            shut_down(runtime, self.mode);
        }
    }
}

/// Shut `runtime` down by `mode`. Returns whether a bounded wait ran out with
/// blocking work still running, which it also logs at ERROR so an operator
/// can tell a stalled disk or mount from a clean exit.
pub(crate) fn shut_down(runtime: tokio::runtime::Runtime, mode: RuntimeShutdown) -> bool {
    let RuntimeShutdown::Bounded(timeout) = mode else {
        drop(runtime);
        return false;
    };
    let started = std::time::Instant::now();
    runtime.shutdown_timeout(timeout);
    // `shutdown_timeout` returns as soon as the blocking pool is idle, so a
    // wait that lasted the whole bound is read as work left running. Work
    // that ended in the bound's last instant reads the same; the log is a
    // pointer to look at the disk, not a proof.
    let left_running = started.elapsed() >= timeout;
    if left_running {
        tracing::error!(
            ?timeout,
            "shutdown exited with blocking work still running after the bound \
             (a disk or mount write that never returned?)"
        );
    }
    left_running
}

/// Run `future` to completion on a new multi-thread runtime, then shut the
/// runtime down by `mode`, on the normal path and on a panic alike.
pub(crate) fn block_on<F: std::future::Future>(mode: RuntimeShutdown, future: F) -> F::Output {
    let guard = ShutdownGuard {
        runtime: Some(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("build the tokio runtime"),
        ),
        mode,
    };
    guard
        .runtime
        .as_ref()
        .expect("the guard holds the runtime until it drops")
        .block_on(future)
}

#[cfg(test)]
#[path = "main_runtime_tests.rs"]
mod tests;
