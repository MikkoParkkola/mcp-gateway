// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7536: an admitted stdio write completes in place when it can and takes
//! a task hop only when it must, and either way goes out whole, byte for byte,
//! after its caller is dropped (MIK-8079).
//!
//! A scripted writer decides exactly how many bytes each poll accepts, so the
//! "k bytes, then Pending" state is pinned rather than left to a pipe's size.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use tokio::io::AsyncWrite;
use tokio_util::sync::CancellationToken;

use super::{HANDED_OVER, finish_whole, write_whole};
use crate::Error;

/// How the scripted writer behaves until its gate opens.
#[derive(Default, Clone, Copy)]
enum Mode {
    /// Every write and flush completes at once.
    #[default]
    Ready,
    /// Accepts this many bytes, then pends until the gate opens.
    AcceptBeforeGate(usize),
    /// Accepts every byte; the flush pends until the gate opens.
    FlushWaitsForGate,
    /// Every write fails.
    Fail,
}

#[derive(Default)]
struct Script {
    mode: Mode,
    gate_open: bool,
    written: Vec<u8>,
    flushed: bool,
    waker: Option<Waker>,
    /// `poll_write` calls that returned Pending.
    pends: usize,
}

#[derive(Clone, Default)]
struct Scripted(Arc<Mutex<Script>>);

impl Scripted {
    fn new(script: Script) -> Self {
        Self(Arc::new(Mutex::new(script)))
    }
    fn open_gate(&self) {
        let mut script = self.0.lock().unwrap();
        script.gate_open = true;
        if let Some(waker) = script.waker.take() {
            waker.wake();
        }
    }
    fn written(&self) -> Vec<u8> {
        self.0.lock().unwrap().written.clone()
    }
    fn flushed(&self) -> bool {
        self.0.lock().unwrap().flushed
    }
    fn pends(&self) -> usize {
        self.0.lock().unwrap().pends
    }
}

impl AsyncWrite for Scripted {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut script = self.0.lock().unwrap();
        if matches!(script.mode, Mode::Fail) {
            return Poll::Ready(Err(io::Error::other("scripted write failure")));
        }
        let room = match script.mode {
            Mode::AcceptBeforeGate(limit) if !script.gate_open => {
                limit.saturating_sub(script.written.len())
            }
            _ => buf.len(),
        };
        if room == 0 {
            script.waker = Some(cx.waker().clone());
            script.pends += 1;
            return Poll::Pending;
        }
        let n = room.min(buf.len());
        script.written.extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut script = self.0.lock().unwrap();
        if matches!(script.mode, Mode::FlushWaitsForGate) && !script.gate_open {
            script.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        script.flushed = true;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn frame() -> Vec<u8> {
    let mut frame = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{}}"#.to_vec();
    frame.push(b'\n');
    frame
}

/// The write `write_frame` hands to `finish_whole`, over the scripted writer.
fn write_of(
    writer: &Scripted,
) -> impl std::future::Future<Output = crate::Result<()>> + Send + 'static {
    let mut stdin = writer.clone();
    let shutdown = CancellationToken::new();
    async move { write_whole(&mut stdin, &frame(), &shutdown).await }
}

fn handed_over() -> usize {
    HANDED_OVER.with(std::cell::Cell::get)
}

/// Drives the runtime until `done`, by yielding: the handed-over task runs on
/// this current-thread runtime only when the test yields. Bounded by count,
/// not by a clock.
async fn yield_until(what: &str, mut done: impl FnMut() -> bool) {
    for _ in 0..10_000 {
        if done() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("{what} within 10000 yields");
}

/// A write that completes on its first poll takes no task hop: it is finished
/// in place, whole and flushed.
#[tokio::test]
async fn a_write_that_completes_at_once_takes_no_task_hop() {
    let writer = Scripted::new(Script::default());
    let before = handed_over();
    finish_whole(write_of(&writer)).await.expect("written");
    assert_eq!(writer.written(), frame(), "the frame went out whole");
    assert!(writer.flushed(), "and was flushed");
    assert_eq!(
        handed_over() - before,
        0,
        "no task hop for a write that completed in place"
    );
}

/// k bytes go out on the first poll, then the write pends. The caller is
/// dropped right there; the handed-over write resumes at byte k and finishes
/// the frame exactly once. A write restarted from byte 0 would duplicate the
/// first k bytes, and a write left inline would stop at k.
#[tokio::test]
async fn a_write_pending_after_k_bytes_finishes_whole_after_its_caller_is_dropped() {
    let writer = Scripted::new(Script {
        mode: Mode::AcceptBeforeGate(5),
        ..Script::default()
    });
    let before = handed_over();
    let mut caller = Box::pin(finish_whole(write_of(&writer)));
    assert!(
        futures::poll!(caller.as_mut()).is_pending(),
        "precondition: the write pends"
    );
    assert_eq!(
        writer.written(),
        frame()[..5],
        "the first poll wrote exactly k bytes in place"
    );
    assert_eq!(
        handed_over() - before,
        1,
        "the pending write was handed over"
    );
    drop(caller);
    writer.open_gate();
    yield_until("the handed-over write finishes", || writer.flushed()).await;
    assert_eq!(
        writer.written(),
        frame(),
        "byte for byte, once, after its caller was dropped"
    );
}

/// A write that pends before its first byte is handed over and finishes whole.
#[tokio::test]
async fn a_write_pending_before_any_byte_finishes_whole_after_its_caller_is_dropped() {
    let writer = Scripted::new(Script {
        mode: Mode::AcceptBeforeGate(0),
        ..Script::default()
    });
    let before = handed_over();
    let mut caller = Box::pin(finish_whole(write_of(&writer)));
    assert!(
        futures::poll!(caller.as_mut()).is_pending(),
        "precondition: the write pends"
    );
    assert!(
        writer.written().is_empty(),
        "precondition: nothing written yet"
    );
    assert_eq!(
        handed_over() - before,
        1,
        "the pending write was handed over"
    );
    drop(caller);
    writer.open_gate();
    yield_until("the handed-over write finishes", || writer.flushed()).await;
    assert_eq!(writer.written(), frame());
}

/// The gate opens only after the handed-over task has itself polled and
/// pended, so the wake goes to the waker that task registered, not to the
/// no-op waker of the in-place poll. A lost wake would leave it pending.
#[tokio::test]
async fn a_handed_over_write_is_woken_by_its_own_waker() {
    let writer = Scripted::new(Script {
        mode: Mode::AcceptBeforeGate(5),
        ..Script::default()
    });
    let mut caller = Box::pin(finish_whole(write_of(&writer)));
    assert!(
        futures::poll!(caller.as_mut()).is_pending(),
        "precondition: the write pends"
    );
    assert_eq!(
        writer.pends(),
        1,
        "precondition: only the in-place poll pended"
    );
    drop(caller);
    yield_until("the handed-over task polls and pends", || {
        writer.pends() >= 2
    })
    .await;
    writer.open_gate();
    yield_until("its own waker wakes it", || writer.flushed()).await;
    assert_eq!(writer.written(), frame(), "byte for byte, once");
}

/// Every byte written, the flush still pending: handed over, and the flush
/// completes after the caller is dropped.
#[tokio::test]
async fn a_flush_still_pending_finishes_after_its_caller_is_dropped() {
    let writer = Scripted::new(Script {
        mode: Mode::FlushWaitsForGate,
        ..Script::default()
    });
    let mut caller = Box::pin(finish_whole(write_of(&writer)));
    assert!(
        futures::poll!(caller.as_mut()).is_pending(),
        "precondition: the flush pends"
    );
    assert_eq!(writer.written(), frame(), "every byte went out in place");
    assert!(!writer.flushed(), "precondition: not flushed yet");
    drop(caller);
    writer.open_gate();
    yield_until("the handed-over flush finishes", || writer.flushed()).await;
}

/// A write error reaches the caller as a transport error, in place.
#[tokio::test]
async fn a_write_error_reaches_the_caller() {
    let writer = Scripted::new(Script {
        mode: Mode::Fail,
        ..Script::default()
    });
    let before = handed_over();
    let outcome = finish_whole(write_of(&writer)).await;
    assert!(
        matches!(&outcome, Err(Error::Transport(m)) if m.contains("scripted write failure")),
        "{outcome:?}"
    );
    assert_eq!(
        handed_over() - before,
        0,
        "an error in the first poll takes no task hop"
    );
}
