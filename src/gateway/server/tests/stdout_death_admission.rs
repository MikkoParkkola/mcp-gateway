// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the stdio writer does when stdout dies, and what the read loop is
//! meant to read off it.
//!
//! The defect this pins: the writer closed its queue on a dead stdout, but the
//! read loop never looked, so the gateway kept admitting and dispatching
//! requests whose responses went nowhere — the side effect still ran, and the
//! only record of it was dropped on the floor.
//!
//! The writer loop is driven here as production drives it, through
//! `Gateway::run_stdout_writer`; only the sink is substituted.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use serde_json::json;
use tokio::io::AsyncWrite;

use crate::gateway::Gateway;

/// A stdout that has gone away: every write fails, as a closed pipe does.
struct DeadSink;

impl AsyncWrite for DeadSink {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "stdout gone",
        )))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A stdout that is still there: the writer must keep the queue open.
struct LiveSink;

impl AsyncWrite for LiveSink {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn a_dead_stdout_closes_the_queue_the_read_loop_admits_on() {
    let (writer, queue) = tokio::sync::mpsc::channel(8);
    let task = tokio::spawn(Gateway::run_stdout_writer(DeadSink, queue));

    writer
        .send(json!({"jsonrpc": "2.0", "id": 1, "result": {}}))
        .await
        .expect("the queue is open before the first failed write");

    // Bounded wait rather than `task.await`: a writer that ignored the failed
    // write would loop forever on an empty queue, and awaiting it would hang
    // the suite instead of failing it. The flag observed here is the one the
    // stdio read loop breaks on; without it the gateway keeps executing
    // requests whose responses are discarded.
    tokio::time::timeout(std::time::Duration::from_secs(5), writer.closed())
        .await
        .expect("a dead stdout must close the queue the read loop admits on");

    assert!(
        writer.is_closed(),
        "the closed queue is observable to producers"
    );
    task.await.expect("the writer task ends rather than panics");
}

#[tokio::test]
async fn a_live_stdout_keeps_the_queue_open() {
    let (writer, queue) = tokio::sync::mpsc::channel(8);
    let task = tokio::spawn(Gateway::run_stdout_writer(LiveSink, queue));

    writer
        .send(json!({"jsonrpc": "2.0", "id": 1, "result": {}}))
        .await
        .expect("a live sink accepts the frame");

    assert!(
        !writer.is_closed(),
        "a healthy stdout must leave the queue open, or the read loop would \
         refuse every request after the first answer"
    );

    drop(writer);
    task.await.expect("the writer task ends rather than panics");
}
