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
    /// Wait for every blocking-pool task. Every mode but stdio: an HTTP
    /// gateway's audit, store and exporter flushes are not proven finished
    /// when `run` returns, and must not be cut.
    WaitForBlockingWork,
    /// Wait this long, then exit behind whatever is still running. Stdio only:
    /// no frame is lost for a client that reads within the drain window; a
    /// slower client loses at most the one in-flight fragment, which an
    /// unbounded wait would also only deliver eventually.
    Bounded(std::time::Duration),
}

impl RuntimeShutdown {
    pub(crate) fn of(command: Option<&Command>) -> Self {
        match command {
            Some(Command::Serve { stdio: true }) => Self::Bounded(SERVE_RUNTIME_SHUTDOWN_TIMEOUT),
            _ => Self::WaitForBlockingWork,
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
/// blocking work still running.
pub(crate) fn shut_down(runtime: tokio::runtime::Runtime, mode: RuntimeShutdown) -> bool {
    match mode {
        RuntimeShutdown::WaitForBlockingWork => drop(runtime),
        RuntimeShutdown::Bounded(timeout) => runtime.shutdown_timeout(timeout),
    }
    false
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
