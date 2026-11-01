// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test sinks for the lossy stderr writer: a sink that parks at a gate the
//! test opens, a sink that follows a script of failures, and the helpers that
//! drive them. Shared by the writer's rows and the request-path rows.

use std::io::{self, Write};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use super::{LogFlush, LossyStderr, NoticeFormat, spawn};

/// The hang guard: past this a parked sink is released and the row fails.
pub(crate) const WATCHDOG: Duration = Duration::from_secs(30);

/// Bytes a sink has accepted, shared with the test, which can wait on them.
#[derive(Clone, Default)]
pub(crate) struct Accepted(Arc<(Mutex<Vec<u8>>, Condvar)>);

impl Accepted {
    pub(crate) fn push(&self, bytes: &[u8]) {
        self.0.0.lock().expect("accepted").extend_from_slice(bytes);
        self.0.1.notify_all();
    }
    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.0.lock().expect("accepted")).into_owned()
    }
    /// Wait until the accepted text satisfies `done`; false past the watchdog.
    pub(crate) fn wait_for(&self, done: impl Fn(&str) -> bool) -> bool {
        let (m, cv) = &*self.0;
        let (g, timeout) = cv
            .wait_timeout_while(m.lock().expect("accepted"), WATCHDOG, |b| {
                !done(&String::from_utf8_lossy(b))
            })
            .expect("accepted");
        drop(g);
        !timeout.timed_out()
    }
    pub(crate) fn lines(&self) -> Vec<String> {
        self.text().lines().map(str::to_owned).collect()
    }
}

/// A gate the test opens: `write_all` waits on it once it is closed.
#[derive(Clone, Default)]
pub(crate) struct Gate(Arc<(Mutex<GateState>, Condvar)>);

#[derive(Default)]
pub(crate) struct GateState {
    closed: bool,
    entered: bool,
    /// The watchdog opened the gate: a write waited past it.
    fired: bool,
}

impl Gate {
    pub(crate) fn closed() -> Self {
        let g = Self::default();
        g.0.0.lock().expect("gate").closed = true;
        g
    }
    pub(crate) fn open(&self) {
        self.0.0.lock().expect("gate").closed = false;
        self.0.1.notify_all();
    }
    /// Wait until a write has reached the gate; false past the watchdog.
    pub(crate) fn wait_entered(&self) -> bool {
        let (m, cv) = &*self.0;
        let (g, timeout) = cv
            .wait_timeout_while(m.lock().expect("gate"), WATCHDOG, |s| !s.entered)
            .expect("gate");
        drop(g);
        !timeout.timed_out()
    }
    pub(crate) fn pass(&self) {
        let (m, cv) = &*self.0;
        let mut g = m.lock().expect("gate");
        g.entered = true;
        cv.notify_all();
        let (mut g, timeout) = cv
            .wait_timeout_while(g, WATCHDOG, |s| s.closed)
            .expect("gate");
        if timeout.timed_out() {
            // Open for good, so a regression fails once instead of per write.
            g.closed = false;
            g.fired = true;
            cv.notify_all();
        }
        drop(g);
    }
    /// Whether a write waited past the watchdog.
    pub(crate) fn fired(&self) -> bool {
        self.0.0.lock().expect("gate").fired
    }
}

/// A tracing layer that parks, at its gate, each event with a field whose
/// value contains `needle`: a subscriber layer that stops, standing in for
/// any slow one, so a row can look at the locks while a line is being written.
pub(crate) struct ParkingLayer {
    gate: Gate,
    needle: &'static str,
}

impl ParkingLayer {
    pub(crate) fn on(needle: &'static str, gate: &Gate) -> Self {
        Self {
            gate: gate.clone(),
            needle,
        }
    }
}

struct Finds {
    needle: &'static str,
    found: bool,
}

impl tracing::field::Visit for Finds {
    fn record_str(&mut self, _: &tracing::field::Field, value: &str) {
        self.found |= value.contains(self.needle);
    }

    fn record_debug(&mut self, _: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.found |= format!("{value:?}").contains(self.needle);
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for ParkingLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        let mut finds = Finds {
            needle: self.needle,
            found: false,
        };
        event.record(&mut finds);
        if finds.found {
            self.gate.pass();
        }
    }
}

/// A sink that parks writes at its gate until the test opens it: every write,
/// or only those containing `park_on`.
pub(crate) struct ParkedSink {
    gate: Gate,
    park_on: Option<&'static str>,
    accepted: Accepted,
}

impl Write for ParkedSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let text = String::from_utf8_lossy(bytes);
        if self.park_on.is_none_or(|p| text.contains(p)) {
            self.gate.pass();
        }
        self.accepted.push(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// What a scripted sink does with the n-th `write_all` call.
#[derive(Clone, Copy)]
pub(crate) enum Step {
    Accept,
    Half,
    Fail,
}

/// A sink that follows a script, call by call, then accepts.
pub(crate) struct FailingSink {
    script: Vec<Step>,
    call: usize,
    accepted: Accepted,
}

impl Write for FailingSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let step = self.script.get(self.call).copied().unwrap_or(Step::Accept);
        self.call += 1;
        match step {
            Step::Accept => {
                self.accepted.push(bytes);
                Ok(bytes.len())
            }
            Step::Half => {
                self.accepted.push(&bytes[..bytes.len() / 2]);
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "half"))
            }
            Step::Fail => Err(io::Error::new(io::ErrorKind::BrokenPipe, "fail")),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn parked(lines: usize, bytes: usize) -> (LossyStderr, LogFlush, Gate, Accepted) {
    parked_on(None, lines, bytes)
}

pub(crate) fn parked_on(
    park_on: Option<&'static str>,
    lines: usize,
    bytes: usize,
) -> (LossyStderr, LogFlush, Gate, Accepted) {
    let gate = Gate::closed();
    let accepted = Accepted::default();
    let sink = ParkedSink {
        gate: gate.clone(),
        park_on,
        accepted: accepted.clone(),
    };
    let (w, f) = spawn(Box::new(sink), lines, bytes, NoticeFormat::Text).expect("spawn");
    (w, f, gate, accepted)
}

pub(crate) fn scripted(script: Vec<Step>) -> (LossyStderr, LogFlush, Accepted) {
    scripted_with(script, 1 << 20)
}

pub(crate) fn scripted_with(script: Vec<Step>, bytes: usize) -> (LossyStderr, LogFlush, Accepted) {
    let accepted = Accepted::default();
    let sink = FailingSink {
        script,
        call: 0,
        accepted: accepted.clone(),
    };
    let (w, f) = spawn(Box::new(sink), 64, bytes, NoticeFormat::Text).expect("spawn");
    (w, f, accepted)
}

/// One line through the writer, as the fmt layer sends it.
pub(crate) fn line(w: &LossyStderr, text: &str) {
    use tracing_subscriber::fmt::MakeWriter;
    let mut out = w.make_writer();
    out.write_all(text.as_bytes()).expect("buffer");
    out.write_all(b"\n").expect("buffer");
    out.flush().expect("no-op");
}

/// Drop the flush guard and wait for its drop to return, within the watchdog.
pub(crate) fn flush(f: LogFlush) {
    let (done_tx, done_rx) = mpsc::channel();
    thread::spawn(move || {
        drop(f);
        let _ = done_tx.send(());
    });
    done_rx.recv_timeout(WATCHDOG).expect("the flush returned");
}

/// Count of notices in `lines`, with the dropped count each reports.
pub(crate) fn notices(lines: &[String]) -> Vec<u64> {
    lines
        .iter()
        .filter_map(|l| l.split("dropped ").nth(1)?.split(' ').next()?.parse().ok())
        .collect()
}

/// A thread-local subscriber whose lossy writer is parked with its queue full:
/// every tracing line on this thread is dropped while it lives. Dropping it
/// opens the gate.
pub(crate) struct Stalled {
    pub(crate) writer: LossyStderr,
    gate: Gate,
    _flush: LogFlush,
    _default: tracing::subscriber::DefaultGuard,
}

pub(crate) fn stalled_log() -> Stalled {
    use tracing_subscriber::layer::SubscriberExt;
    crate::test_log_capture::keep_interest_open();
    let (writer, flush, gate, _out) = parked(1, 1 << 20);
    line(&writer, "first");
    assert!(gate.wait_entered(), "the writer never took a line");
    line(&writer, "fills the one slot");
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::filter::LevelFilter::TRACE)
        .with(crate::log_layer(NoticeFormat::Text, writer.clone()));
    Stalled {
        writer,
        gate,
        _flush: flush,
        _default: tracing::subscriber::set_default(subscriber),
    }
}

impl Drop for Stalled {
    fn drop(&mut self) {
        self.gate.open();
    }
}
