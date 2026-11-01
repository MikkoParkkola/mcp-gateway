// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The stderr writer behind every tracing line: bounded, and lossy when full.
//!
//! A write to a stderr that nobody drains blocks, and a blocked write on a
//! tokio worker stalls every task on it. So each formatted line is handed to
//! one writer thread through a bounded queue, and a line that does not fit is
//! dropped and counted rather than waited for. The thread reports what was
//! dropped in a line of its own once stderr takes writes again. Audit records
//! that must not be lost have their own writers and never come through here.

use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread;
use std::time::{Duration, Instant};

use tracing_subscriber::fmt::MakeWriter;

/// Lines the queue holds before new ones are dropped.
pub(crate) const LOG_QUEUE_LINES: usize = 8192;
/// Bytes of queued lines before new ones are dropped: a bound on queued
/// payload, not on the process's memory (per-event buffers sit outside it).
pub(crate) const LOG_QUEUE_BYTES: usize = 8 * 1024 * 1024;
/// The longest the flush at exit waits, whatever stderr does.
pub(crate) const LOG_FLUSH_DEADLINE: Duration = Duration::from_secs(2);

/// How the writer thread spells its own drop notice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NoticeFormat {
    Text,
    Json,
}

enum Msg {
    Line(Vec<u8>),
    Flush(SyncSender<()>),
}

struct Shared {
    /// Every line dropped so far: queue full, byte bound, writer gone, or a
    /// failed write. Only ever grows.
    total: AtomicU64,
    queued_bytes: AtomicUsize,
    max_bytes: usize,
}

/// The `MakeWriter` for the fmt layer: each event's line goes to the queue.
#[derive(Clone)]
pub(crate) struct LossyStderr {
    tx: SyncSender<Msg>,
    shared: Arc<Shared>,
}

/// Flushes the queue when dropped, within [`LOG_FLUSH_DEADLINE`].
pub(crate) struct LogFlush {
    tx: SyncSender<Msg>,
}

/// One event's line, sent once when the fmt layer is done with it.
pub(crate) struct EventLine<'a> {
    buf: Vec<u8>,
    to: &'a LossyStderr,
}

/// Start the writer thread on `sink`; return the layer's writer and the exit flush.
pub(crate) fn spawn(
    sink: Box<dyn Write + Send>,
    lines: usize,
    bytes: usize,
    format: NoticeFormat,
) -> io::Result<(LossyStderr, LogFlush)> {
    let (tx, rx) = mpsc::sync_channel(lines);
    let shared = Arc::new(Shared {
        total: AtomicU64::new(0),
        queued_bytes: AtomicUsize::new(0),
        max_bytes: bytes,
    });
    let for_thread = Arc::clone(&shared);
    thread::Builder::new()
        .name("log-writer".into())
        .spawn(move || run(&rx, sink, &for_thread, format))?;
    Ok((
        LossyStderr {
            tx: tx.clone(),
            shared,
        },
        LogFlush { tx },
    ))
}

impl LossyStderr {
    /// Queue `line`, or drop and count it. Never waits.
    fn send(&self, line: Vec<u8>) {
        let n = line.len();
        let q = &self.shared.queued_bytes;
        let mut cur = q.load(Ordering::Relaxed);
        loop {
            let Some(next) = cur.checked_add(n).filter(|t| *t <= self.shared.max_bytes) else {
                self.shared.total.fetch_add(1, Ordering::Relaxed);
                return;
            };
            match q.compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
        if self.tx.try_send(Msg::Line(line)).is_err() {
            // Full or disconnected: give the reservation back and count the line.
            q.fetch_sub(n, Ordering::AcqRel);
            self.shared.total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Lines dropped so far.
    #[cfg(test)]
    pub(crate) fn dropped_lines(&self) -> u64 {
        self.shared.total.load(Ordering::Relaxed)
    }

    /// Bytes reserved by queued lines.
    #[cfg(test)]
    pub(crate) fn queued_bytes(&self) -> usize {
        self.shared.queued_bytes.load(Ordering::Acquire)
    }
}

impl<'a> MakeWriter<'a> for LossyStderr {
    type Writer = EventLine<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        EventLine {
            buf: Vec::new(),
            to: self,
        }
    }
}

impl Write for EventLine<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    /// Nothing to do: the line is sent once, on drop, so a write-then-flush
    /// cannot queue it twice.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for EventLine<'_> {
    fn drop(&mut self) {
        if !self.buf.is_empty() {
            self.to.send(std::mem::take(&mut self.buf));
        }
    }
}

/// What a flush attempt to enqueue its marker found.
pub(crate) enum Sent {
    Yes,
    Full,
    Gone,
}

/// The flush at exit, one deadline for all of it: retry the marker while the
/// queue is full, give up at `deadline` without waiting if it never went in,
/// and otherwise wait for the writer's reply only for the time that is left.
pub(crate) fn flush_until(
    deadline: Instant,
    mut send: impl FnMut() -> Sent,
    mut wait: impl FnMut(Duration) -> bool,
    now: impl Fn() -> Instant,
) -> bool {
    loop {
        let t = now();
        if t >= deadline {
            return false;
        }
        match send() {
            Sent::Yes => return wait(deadline - t),
            Sent::Full => {}
            Sent::Gone => return false,
        }
    }
}

impl Drop for LogFlush {
    fn drop(&mut self) {
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        let mut marker = Some(Msg::Flush(ack_tx));
        flush_until(
            Instant::now() + LOG_FLUSH_DEADLINE,
            || match self.tx.try_send(marker.take().expect("one marker")) {
                Ok(()) => Sent::Yes,
                Err(TrySendError::Full(back)) => {
                    marker = Some(back);
                    thread::sleep(Duration::from_millis(5));
                    Sent::Full
                }
                Err(TrySendError::Disconnected(_)) => Sent::Gone,
            },
            |left| ack_rx.recv_timeout(left).is_ok(),
            Instant::now,
        );
    }
}

/// The writer thread: one line at a time, until every sender is gone.
fn run(rx: &Receiver<Msg>, mut sink: Box<dyn Write + Send>, shared: &Shared, format: NoticeFormat) {
    let mut out = Out {
        sink: &mut *sink,
        broken: false,
    };
    let mut reported = 0_u64;
    while let Ok(msg) = rx.recv() {
        match msg {
            Msg::Line(line) => {
                shared.queued_bytes.fetch_sub(line.len(), Ordering::AcqRel);
                if out.record(&line) {
                    reported = out.notice(shared, reported, format);
                } else {
                    shared.total.fetch_add(1, Ordering::Relaxed);
                }
            }
            Msg::Flush(ack) => {
                reported = out.notice(shared, reported, format);
                let _ = out.sink.flush();
                let _ = ack.try_send(());
            }
        }
    }
}

struct Out<'s> {
    sink: &'s mut (dyn Write + Send),
    /// The last write failed part-way: the next record starts on a new line.
    broken: bool,
}

impl Out<'_> {
    fn record(&mut self, bytes: &[u8]) -> bool {
        if self.broken {
            if self.sink.write_all(b"\n").is_err() {
                return false;
            }
            self.broken = false;
        }
        if self.sink.write_all(bytes).is_err() {
            self.broken = true;
            return false;
        }
        true
    }

    /// Report the drops since the last notice; return the new watermark. The
    /// watermark moves to the count the notice printed, and only once it is
    /// written, so drops during or after a failed notice are reported later.
    fn notice(&mut self, shared: &Shared, reported: u64, format: NoticeFormat) -> u64 {
        let snap = shared.total.load(Ordering::Relaxed);
        if snap <= reported {
            return reported;
        }
        let line = notice_line(snap - reported, format);
        if self.record(line.as_bytes()) {
            snap
        } else {
            reported
        }
    }
}

/// The writer's own line about dropped lines, in one fixed shape per format.
pub(crate) fn notice_line(dropped: u64, format: NoticeFormat) -> String {
    let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    match format {
        NoticeFormat::Json => format!(
            "{{\"timestamp\":\"{ts}\",\"level\":\"WARN\",\"target\":\"mcp_gateway::log\",\"message\":\"dropped log lines while stderr was not draining\",\"dropped\":{dropped}}}\n"
        ),
        NoticeFormat::Text => format!(
            "{ts}  WARN mcp_gateway::log: dropped {dropped} log lines while stderr was not draining\n"
        ),
    }
}

#[cfg(test)]
#[path = "log_writer_sinks_tests.rs"]
pub(crate) mod test_sinks;

#[cfg(test)]
#[path = "log_writer_tests.rs"]
mod tests;
