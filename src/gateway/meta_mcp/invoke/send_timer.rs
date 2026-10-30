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
        Self {
            started: Some(Instant::now()),
        }
    }

    /// Start timing when `on` (a `tools/call` send); otherwise an inert
    /// timer that notes nothing.
    pub(crate) fn start_if(on: bool) -> Self {
        Self {
            started: on.then(Instant::now),
        }
    }

    /// Note how the send that returned `result` ended, and hand it back.
    pub(crate) fn finish_with<T>(self, result: crate::Result<T>) -> crate::Result<T> {
        self.finish(Self::end_of(&result));
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
