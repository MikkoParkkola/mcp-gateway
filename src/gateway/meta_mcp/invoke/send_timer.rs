// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The guard that times one backend send for the web UI's
//! latency history.
//!
//! Each leaf send (an MCP transport `tools/call`, a CLI capability's run, a
//! capability's HTTP request) starts one after every local step, so waits,
//! start-up and local refusals are never timed. It notes into the call's
//! [`DispatchNotes`](super::audit::DispatchNotes), where the count reads it:
//! one sample per counted call.

use std::time::{Duration, Instant};

use crate::counters::End;

/// Times one backend send. Finish it with how the send ended; drop it
/// unfinished and it notes [`End::Cancelled`] (the send future was dropped,
/// as a timeout wrapper drops it); [`SendTimer::discard`] notes nothing.
#[derive(Debug)]
pub(crate) struct SendTimer {
    started: Option<Instant>,
}

impl SendTimer {
    /// Start timing a send that is about to go out.
    pub(crate) fn start() -> Self {
        Self::start_if(true)
    }

    /// Start timing when `on` (a `tools/call` send); otherwise an inert
    /// timer that notes nothing.
    pub(crate) fn start_if(on: bool) -> Self {
        #[cfg(test)]
        if on {
            seam::note_start();
        }
        Self {
            started: on.then(Instant::now),
        }
    }

    /// Note how the send that returned `result` ended, and hand it back. A
    /// failure that proves nothing reached the backend notes nothing.
    pub(crate) fn finish_with<T>(self, result: crate::Result<T>) -> crate::Result<T> {
        if matches!(&result, Err(e) if never_sent(e)) {
            self.discard();
        } else {
            self.finish(Self::end_of(&result));
        }
        result
    }

    /// The send ended `end`: note its time. Notes at most once.
    pub(crate) fn finish(mut self, end: End) {
        if let Some(started) = self.started.take() {
            super::audit::note_backend(elapsed(started), end);
        }
    }

    /// Nothing reached the backend after all: note nothing.
    pub(crate) fn discard(mut self) {
        self.started = None;
    }

    /// How a send that returned `result` ended: an answer (a tool's
    /// `isError` included), the backend timeout, or any other failure.
    pub(crate) fn end_of<T>(result: &crate::Result<T>) -> End {
        match result {
            Ok(_) => End::Answered,
            Err(crate::Error::BackendTimeout(_)) => End::TimedOut,
            Err(_) => End::Failed,
        }
    }
}

impl Drop for SendTimer {
    fn drop(&mut self) {
        if let Some(started) = self.started.take() {
            super::audit::note_backend(elapsed(started), End::Cancelled);
        }
    }
}

/// Failures that prove nothing was written to the backend: the crate's own
/// pre-dispatch set ([`crate::Error::is_pre_dispatch`]: no caller slot, an
/// authorization that never completed, a connection that never opened (the
/// stdio writer reports an unsent request this way), a refusal before the
/// send), plus shutdown. None of them is the backend's latency.
fn never_sent(e: &crate::Error) -> bool {
    e.is_pre_dispatch() || matches!(e, crate::Error::Shutdown)
}

/// The send's time: the injected test duration when a row set one.
fn elapsed(started: Instant) -> Duration {
    #[cfg(test)]
    if let Some(injected) = seam::injected() {
        return injected;
    }
    started.elapsed()
}

/// Rows set every send's time on this thread, so no row depends on a real
/// clock (the `drain_seam.rs` pattern). Production never compiles it.
#[cfg(test)]
pub(crate) mod seam {
    use std::cell::Cell;
    use std::time::Duration;

    thread_local! {
        static INJECTED: Cell<Option<Duration>> = const { Cell::new(None) };
        static STARTS: Cell<u64> = const { Cell::new(0) };
    }

    pub(super) fn note_start() {
        STARTS.with(|s| s.set(s.get() + 1));
    }

    /// Timers started on this thread so far: a row reads it before and
    /// after, so it can tell a wait that started no timer.
    pub(crate) fn starts() -> u64 {
        STARTS.with(Cell::get)
    }

    pub(super) fn injected() -> Option<Duration> {
        INJECTED.with(Cell::get)
    }

    /// Every send timed on this thread takes `elapsed` until [`clear`].
    pub(crate) fn inject(elapsed: Duration) {
        INJECTED.with(|i| i.set(Some(elapsed)));
    }

    pub(crate) fn clear() {
        INJECTED.with(|i| i.set(None));
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{SendTimer, seam};
    use crate::counters::End;
    use crate::gateway::meta_mcp::invoke::audit::with_dispatch_scope;

    /// Test plan row 28: a finished timer notes once; its drop notes nothing
    /// more. A timer dropped unfinished notes Cancelled.
    #[tokio::test]
    async fn timer_notes_at_most_once() {
        seam::inject(Duration::from_millis(7));
        let ((), notes) = with_dispatch_scope(async {
            SendTimer::start_if(true).finish(End::Answered);
        })
        .await;
        assert_eq!(
            notes.backend_sample(),
            Some((Duration::from_millis(7), End::Answered))
        );
        let ((), notes) = with_dispatch_scope(async {
            drop(SendTimer::start());
        })
        .await;
        assert_eq!(
            notes.backend_sample(),
            Some((Duration::from_millis(7), End::Cancelled))
        );
        let ((), notes) = with_dispatch_scope(async {
            SendTimer::start_if(false).finish(End::Answered);
            SendTimer::start().discard();
        })
        .await;
        seam::clear();
        assert_eq!(
            notes.backend_sample(),
            None,
            "inert and discarded timers note nothing"
        );
    }

    /// Review F1: a transport failure that proves nothing was sent notes no
    /// sample; a failure after the send notes one, Failed.
    #[tokio::test]
    async fn a_send_that_never_left_notes_nothing() {
        seam::inject(Duration::from_millis(7));
        let unsent = [
            crate::Error::TransportConnect("stdout closed before anything was sent".into()),
            crate::Error::IdentitySlotsExhausted {
                backend: "alpha".into(),
                limit: "backend",
            },
            crate::Error::Shutdown,
            // In the crate's pre-dispatch set, not in the narrower list
            // the check once kept: a revert to that list would note it.
            crate::Error::BackendUnavailable("no healthy backend".into()),
        ];
        for error in unsent {
            let ((), notes) = with_dispatch_scope(async {
                let _ = SendTimer::start().finish_with::<()>(Err(error));
            })
            .await;
            assert_eq!(notes.backend_sample(), None);
        }
        let ((), notes) = with_dispatch_scope(async {
            let _ =
                SendTimer::start().finish_with::<()>(Err(crate::Error::Transport("reset".into())));
        })
        .await;
        seam::clear();
        assert_eq!(
            notes.backend_sample(),
            Some((Duration::from_millis(7), End::Failed))
        );
    }

    /// Test plan row 26: a call's rounds (a bridged retry) add up into one
    /// sample; the last round's end is the call's.
    #[tokio::test]
    async fn a_calls_rounds_sum_into_one_sample() {
        let ((), notes) = with_dispatch_scope(async {
            seam::inject(Duration::from_millis(30));
            SendTimer::start().finish(End::TimedOut);
            seam::inject(Duration::from_millis(12));
            SendTimer::start().finish(End::Answered);
        })
        .await;
        seam::clear();
        assert_eq!(
            notes.backend_sample(),
            Some((Duration::from_millis(42), End::Answered))
        );
    }
}

/// Test plan row 30: every leaf backend send sits in a timed scope, and no
/// timer wraps the capability dispatch branch (that would time a send twice).
#[cfg(test)]
#[path = "send_timer_scan_tests.rs"]
mod send_site_scan;
