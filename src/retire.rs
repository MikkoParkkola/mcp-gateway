// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Retirement and process exit inside the HTTP stop total: the stop's plan,
//! stored once when the HTTP stop fixes its budget, the deadlines `cli::run`
//! reads from it after `dispatch` returned, the exit status of that tail, and
//! the watchdog that ends the process by D + 500 ms whatever is still running.

use std::process::ExitCode;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::time::Instant;

use crate::log_writer::{FlushEnd, StopOutcome};

/// The exec share of a committed restart: the logger's end moves this much
/// earlier, so the third preflight and `execve` always have time before D.
pub(crate) const EXEC_SHARE: Duration = Duration::from_millis(250);

/// How long past D the watchdog lets the process run; the shipped grace
/// SIGKILLs it at D + 1 s.
pub(crate) const WATCHDOG_SLACK: Duration = Duration::from_millis(500);

/// The most the runtime waits for blocking work under an HTTP stop's plan,
/// whatever is left to its runtime deadline.
pub(crate) const RUNTIME_WAIT_CAP: Duration = Duration::from_millis(250);

/// The exit status of a tail that overran its bound or did not join its logger.
pub(crate) const EXIT_OVERRUN: u8 = 75;

/// How the stop ends: a plain stop, or a committed restart that execs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Exit {
    Plain,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the committed restart path stores it; until then only the exec-share rows build it"
        )
    )]
    Restart,
}

/// One HTTP stop's retirement plan: the deadlines its budget fixed and how it
/// ends. Built only from the budget's own `end` and `runtime_end`, at the one
/// store site, so the budget stays their single source.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RetirePlan {
    end: Instant,
    runtime_end: Instant,
    exit: Exit,
}

/// The boot's plan cell: set once, by the HTTP stop, never by startup.
pub(crate) type RetireCell = Arc<OnceLock<RetirePlan>>;

impl RetirePlan {
    /// The plan of a stop whose budget ends at `end` (D) with its runtime wait
    /// ending at `runtime_end` (Dr).
    pub(crate) fn new(end: Instant, runtime_end: Instant, exit: Exit) -> Self {
        Self {
            end,
            runtime_end,
            exit,
        }
    }

    /// D: the end of the whole stop.
    pub(crate) fn end(&self) -> Instant {
        self.end
    }

    /// Dr: where the runtime wait ends.
    pub(crate) fn runtime_end(&self) -> Instant {
        self.runtime_end
    }

    /// Where the logger's terminal stop ends: D, or D - E for a restart.
    pub(crate) fn logger_end(&self) -> Instant {
        match self.exit {
            Exit::Plain => self.end,
            Exit::Restart => self.end.checked_sub(EXEC_SHARE).unwrap_or(self.end),
        }
    }
}

/// The code `cli::run` stored for the watchdog; negative while none is.
static STORED_CODE: AtomicI32 = AtomicI32::new(-1);

/// The process-wide stored code, for `cli::run`'s tail.
pub(crate) fn stored_code() -> &'static AtomicI32 {
    &STORED_CODE
}

/// The tail's exit status: with a plan (`outcome` is the terminal stop's),
/// [`EXIT_OVERRUN`] when the runtime wait left work running or the logger
/// was not joined, else `code`; stored in `stored` for the watchdog.
/// Without a plan, `code` as today.
pub(crate) fn finish(
    code: ExitCode,
    left_running: bool,
    outcome: Option<&StopOutcome>,
    stored: &AtomicI32,
) -> ExitCode {
    let Some(outcome) = outcome else {
        return code;
    };
    let status = if left_running || !outcome.permits_exec() {
        EXIT_OVERRUN
    } else {
        // An HTTP serve, the one path with a plan, returns SUCCESS or FAILURE.
        u8::from(code != ExitCode::SUCCESS)
    };
    stored.store(i32::from(status), Ordering::SeqCst);
    if status == EXIT_OVERRUN {
        ExitCode::from(EXIT_OVERRUN)
    } else {
        code
    }
}

/// Start the watchdog for a stop ending at `end`: at `end` + [`WATCHDOG_SLACK`]
/// it calls `exit` with the code in `stored`, or [`EXIT_OVERRUN`] when none
/// is stored. Armed late, it fires at once. `None` when the thread could not
/// be started (logged; the stop goes on without it).
pub(crate) fn arm_with(
    end: std::time::Instant,
    stored: &'static AtomicI32,
    exit: impl FnOnce(i32) + Send + 'static,
) -> Option<std::thread::JoinHandle<()>> {
    let at = end + WATCHDOG_SLACK;
    std::thread::Builder::new()
        .name("stop-watchdog".into())
        .spawn(move || {
            // Sleeps at least this long; armed late, not at all.
            std::thread::sleep(at.saturating_duration_since(std::time::Instant::now()));
            let code = stored.load(Ordering::SeqCst);
            exit(if code < 0 {
                i32::from(EXIT_OVERRUN)
            } else {
                code
            });
        })
        .inspect_err(|error| {
            tracing::error!(
                target: "mcp_gateway::runtime",
                %error,
                "cannot start the stop watchdog; the stop goes on without it"
            );
        })
        .ok()
}

/// Arm the process watchdog for `plan`: the process exits by D + 500 ms with
/// the code `cli::run` stored, or 75. Never disarmed: a process that already
/// exited took the thread with it.
pub(crate) fn arm(plan: &RetirePlan) {
    let _ = arm_with(plan.end().into_std(), stored_code(), |code| {
        std::process::exit(code)
    });
}

/// `cli::run`'s tail after the runtime retired: with an HTTP stop's `plan`, the
/// logger's terminal stop bounded by the plan, then [`finish`]; without one,
/// the flush guard drops as before.
pub(crate) fn tail(
    code: ExitCode,
    left_running: bool,
    plan: Option<RetirePlan>,
    flush: crate::log_writer::LogFlush,
) -> ExitCode {
    let Some(plan) = plan else {
        drop(flush);
        return code;
    };
    if left_running {
        // Logged before the terminal stop, which then writes it out.
        tracing::error!(
            target: "mcp_gateway::runtime",
            "the stop's runtime wait left blocking work running; exiting 75"
        );
    }
    let bound = std::time::Instant::now() + crate::log_writer::LOG_FLUSH_DEADLINE;
    let outcome = flush.stop_and_join(bound.min(plan.logger_end().into_std()));
    // The logger is closed: what it could not write is one line straight to
    // stderr, best effort. A writer not joined is left behind; the watchdog
    // bounds whatever it still holds.
    let note = match &outcome {
        StopOutcome::Joined(FlushEnd::Clean) => None,
        StopOutcome::Joined(FlushEnd::SinkError) => {
            Some("its last flush failed; lines may be lost")
        }
        StopOutcome::WorkerFailed => Some("its thread failed; exiting 75"),
        StopOutcome::NotJoined(worker) => Some(if worker.is_finished() {
            "it finished just past its deadline; exiting 75"
        } else {
            "it did not finish by its deadline; exiting 75"
        }),
    };
    if let Some(note) = note {
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), "mcp-gateway: the log writer: {note}");
    }
    finish(code, left_running, Some(&outcome), stored_code())
}

#[cfg(test)]
#[path = "retire_tests.rs"]
mod tests;
