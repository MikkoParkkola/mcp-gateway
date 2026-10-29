// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The per-request clock behind `mcp_gateway_added_latency_seconds`: how long
//! a request spent waiting on backend transports, so the gateway's own share
//! is the whole time minus that.

use std::future::Future;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::time::Instant;

use crate::Result;
use crate::protocol::{JsonRpcResponse, Origin};

tokio::task_local! {
    /// The clock of the request this task is working for. Task-locals do not
    /// cross `tokio::spawn`, so a spawn that carries request work re-scopes it.
    static CLOCK: Arc<Clock>;
}

#[derive(Default)]
struct Waits {
    in_flight: u32,
    busy_since: Option<Instant>,
    busy: Duration,
}

/// One request's wall clock and its backend waits. Overlapping waits count
/// once: a span opens when the first wait enters and closes when the last
/// one leaves.
pub(crate) struct Clock {
    started: Instant,
    waits: Mutex<Waits>,
}

impl Clock {
    pub(crate) fn start() -> Arc<Self> {
        Arc::new(Self {
            started: Instant::now(),
            waits: Mutex::new(Waits::default()),
        })
    }

    /// The clock of the request this task works for, if any.
    pub(crate) fn current() -> Option<Arc<Self>> {
        CLOCK.try_with(Arc::clone).ok()
    }

    /// Run `fut` with this clock as the current one.
    pub(crate) fn scope<F: Future>(self: Arc<Self>, fut: F) -> impl Future<Output = F::Output> {
        CLOCK.scope(self, fut)
    }

    fn enter(&self) {
        let mut waits = self.waits.lock();
        if waits.in_flight == 0 {
            waits.busy_since = Some(Instant::now());
        }
        waits.in_flight += 1;
    }

    fn leave(&self) {
        let mut waits = self.waits.lock();
        waits.in_flight = waits.in_flight.saturating_sub(1);
        if waits.in_flight == 0
            && let Some(since) = waits.busy_since.take()
        {
            waits.busy += since.elapsed();
        }
    }

    /// Time spent waiting on backends so far, including a span still open.
    pub(crate) fn busy(&self) -> Duration {
        let waits = self.waits.lock();
        waits.busy
            + waits
                .busy_since
                .map_or(Duration::ZERO, |since| since.elapsed())
    }

    /// Whole time so far minus the backend waits: the gateway's own share.
    pub(crate) fn added(&self) -> Duration {
        self.started.elapsed().saturating_sub(self.busy())
    }
}

/// A wait on a backend, open until dropped, so a cancelled wait keeps the
/// time it had already spent.
struct Wait(Arc<Clock>);

impl Wait {
    fn open() -> Option<Self> {
        let clock = Clock::current()?;
        clock.enter();
        Some(Self(clock))
    }
}

impl Drop for Wait {
    fn drop(&mut self) {
        self.0.leave();
    }
}

/// Await `fut` as a backend wait: its time is not the gateway's. Outside a
/// request scope this is a plain await.
pub(crate) async fn backend_wait<F: Future>(fut: F) -> F::Output {
    let _wait = Wait::open();
    fut.await
}

/// [`backend_wait`] for a request, which also marks the frame it returns as a
/// backend's own, so an error in it is counted as the backend's.
pub(crate) async fn backend_request<F>(fut: F) -> Result<JsonRpcResponse>
where
    F: Future<Output = Result<JsonRpcResponse>>,
{
    let mut answer = backend_wait(fut).await;
    if let Ok(response) = &mut answer {
        response.wire_meta.origin = Origin::Backend;
    }
    answer
}

/// `fut` for a spawned task that carries this request's work: the task
/// counts its backend waits on the clock of the request that spawned it.
pub(crate) fn carried<F: Future>(fut: F) -> impl Future<Output = F::Output> {
    let clock = Clock::current();
    async move {
        match clock {
            Some(clock) => clock.scope(fut).await,
            None => fut.await,
        }
    }
}

/// `fut` polled with `clock` current on every poll, for a future that is
/// polled outside the scope it was made in (a response stream's body).
pub(crate) fn rescoped<F>(clock: Option<Arc<Clock>>, mut fut: F) -> impl Future<Output = F::Output>
where
    F: Future + Unpin,
{
    std::future::poll_fn(move |cx| -> Poll<F::Output> {
        match &clock {
            Some(clock) => {
                CLOCK.sync_scope(Arc::clone(clock), || std::pin::Pin::new(&mut fut).poll(cx))
            }
            None => std::pin::Pin::new(&mut fut).poll(cx),
        }
    })
}
