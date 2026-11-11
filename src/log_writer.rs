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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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
    /// The terminal stop's wake for an idle writer.
    Stop,
}

struct Shared {
    /// Every line dropped so far: queue full, byte bound, writer gone, or a
    /// failed write. Only ever grows.
    total: AtomicU64,
    queued_bytes: AtomicUsize,
    max_bytes: usize,
    /// Set by the terminal stop: no clone enqueues after it.
    closed: AtomicBool,
    /// Test hook: parks a send that has passed the closed check.
    #[cfg(test)]
    after_check: std::sync::Mutex<Option<test_sinks::Gate>>,
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
    shared: Arc<Shared>,
    /// Taken by the terminal stop, which then owns the join.
    worker: Option<thread::JoinHandle<FlushEnd>>,
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
        closed: AtomicBool::new(false),
        #[cfg(test)]
        after_check: std::sync::Mutex::new(None),
    });
    let for_thread = Arc::clone(&shared);
    let worker = thread::Builder::new()
        .name("log-writer".into())
        .spawn(move || run(&rx, sink, &for_thread, format))?;
    Ok((
        LossyStderr {
            tx: tx.clone(),
            shared: Arc::clone(&shared),
        },
        LogFlush {
            tx,
            shared,
            worker: Some(worker),
        },
    ))
}

impl LossyStderr {
    /// Queue `line`, or drop and count it. Never waits.
    fn send(&self, line: Vec<u8>) {
        if self.shared.closed.load(Ordering::Acquire) {
            self.shared.total.fetch_add(1, Ordering::Relaxed);
            return;
        }
        #[cfg(test)]
        {
            let gate = self.shared.after_check.lock().expect("hook").clone();
            if let Some(gate) = gate {
                gate.pass();
            }
        }
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

    /// Park every send that has passed the closed check at `gate`.
    #[cfg(test)]
    pub(crate) fn park_after_check(&self, gate: &test_sinks::Gate) {
        *self.shared.after_check.lock().expect("hook") = Some(gate.clone());
    }

    #[cfg(test)]
    pub(crate) fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::Acquire)
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

/// How the final flush of the stopped writer ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FlushEnd {
    Clean,
    SinkError,
}

/// How a terminal stop ended. Only a confirmed stop and join lets the process
/// exec; a joined sink error alone does not forbid it.
#[derive(Debug)]
pub(crate) enum StopOutcome {
    Joined(FlushEnd),
    WorkerFailed,
    /// The worker did not finish by the deadline; the caller keeps owning it.
    NotJoined(thread::JoinHandle<FlushEnd>),
}

impl StopOutcome {
    pub(crate) fn permits_exec(&self) -> bool {
        matches!(self, Self::Joined(_))
    }
}

impl LogFlush {
    /// Terminal stop: close enqueue admission on every clone, drain what was
    /// accepted, flush, and join the writer, all by `deadline`.
    pub(crate) fn stop_and_join(mut self, deadline: Instant) -> StopOutcome {
        // Admission closes first, so a clone cannot keep the queue busy. An idle
        // writer wakes on the Stop message; a writer with a full queue is busy
        // and sees the flag after its next message, so a failed try_send is fine.
        self.shared.closed.store(true, Ordering::Release);
        let _ = self.tx.try_send(Msg::Stop);
        let Some(worker) = self.worker.take() else {
            return StopOutcome::WorkerFailed;
        };
        while !worker.is_finished() {
            if Instant::now() >= deadline {
                return StopOutcome::NotJoined(worker);
            }
            thread::sleep(Duration::from_millis(2));
        }
        match worker.join() {
            Ok(end) => StopOutcome::Joined(end),
            Err(_) => StopOutcome::WorkerFailed,
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
            // What is left once the marker is in: the send itself takes time.
            Sent::Yes => return wait(deadline.saturating_duration_since(now())),
            Sent::Full => {}
            Sent::Gone => return false,
        }
    }
}

impl Drop for LogFlush {
    fn drop(&mut self) {
        if self.worker.is_none() {
            // A terminal stop already ran; it was bounded by its own deadline.
            return;
        }
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        let mut marker = Some(Msg::Flush(ack_tx));
        flush_until(
            Instant::now() + LOG_FLUSH_DEADLINE,
            || {
                // A Full send hands the marker back, so it is always here;
                // were it not, there is nothing left to send.
                let Some(m) = marker.take() else {
                    return Sent::Gone;
                };
                match self.tx.try_send(m) {
                    Ok(()) => Sent::Yes,
                    Err(TrySendError::Full(back)) => {
                        marker = Some(back);
                        thread::sleep(Duration::from_millis(5));
                        Sent::Full
                    }
                    Err(TrySendError::Disconnected(_)) => Sent::Gone,
                }
            },
            |left| ack_rx.recv_timeout(left).is_ok(),
            Instant::now,
        );
    }
}

/// The writer thread: one line at a time, until every sender is gone or the
/// terminal stop closes admission and the accepted lines are drained.
fn run(
    rx: &Receiver<Msg>,
    mut sink: Box<dyn Write + Send>,
    shared: &Shared,
    format: NoticeFormat,
) -> FlushEnd {
    let mut out = Out {
        sink: &mut *sink,
        broken: false,
    };
    let mut reported = 0_u64;
    loop {
        match rx.recv() {
            Ok(Msg::Stop) => break,
            Ok(msg) => {
                reported = serve(msg, &mut out, shared, reported, format);
                if shared.closed.load(Ordering::Acquire) {
                    break;
                }
            }
            Err(_) => return FlushEnd::Clean,
        }
    }
    // Accepted before the close: still written. A send that passed the closed
    // check just before it may land after this drain and is then lost.
    while let Ok(msg) = rx.try_recv() {
        reported = serve(msg, &mut out, shared, reported, format);
    }
    out.notice(shared, reported, format);
    match out.sink.flush() {
        Ok(()) => FlushEnd::Clean,
        Err(_) => FlushEnd::SinkError,
    }
}

/// Handle one queued message; return the new drop-notice watermark.
fn serve(
    msg: Msg,
    out: &mut Out<'_>,
    shared: &Shared,
    mut reported: u64,
    format: NoticeFormat,
) -> u64 {
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
        Msg::Stop => {}
    }
    reported
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
    // A clock that cannot be read still gets the notice out, dated at the
    // epoch: the drop count matters more than when it was reported.
    let ts = crate::clock::utc_now()
        .unwrap_or(chrono::DateTime::UNIX_EPOCH)
        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
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
#[path = "log_writer_stop_tests.rs"]
mod stop_tests;
#[cfg(test)]
#[path = "log_writer_tests.rs"]
mod tests;
