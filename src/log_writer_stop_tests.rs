// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The terminal stop of the log writer: admission closes, accepted lines drain,
//! and the worker is joined, or the stop says it was not.

use std::io::{self, Write};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use super::test_sinks::{Accepted, Gate, WATCHDOG, line, notices, parked, scripted, slow_parked};
use super::{FlushEnd, NoticeFormat, StopOutcome, spawn};

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

/// Join `handle` within ten seconds: a regression that deadlocks fails here
/// instead of hanging the run.
fn bounded<T: Send + 'static>(handle: thread::JoinHandle<T>, what: &str) -> T {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(handle.join());
    });
    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(value)) => value,
        Ok(Err(payload)) => panic!("{what} panicked: {payload:?}"),
        Err(waited) => panic!(
            "{what} did not finish in 10 s ({waited}): a stop and a sender wait on each other"
        ),
    }
}

/// Wait for a state the writer is certain to reach; fails past the watchdog.
fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ready() {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "never happened: {what}"
        );
        thread::yield_now();
    }
}

fn kept(out: &Accepted) -> Vec<String> {
    out.lines().into_iter().filter(|l| !l.is_empty()).collect()
}

#[test]
fn a_stop_drains_every_accepted_line_in_order_and_joins() {
    let (w, f, gate, out) = slow_parked(64, 1 << 20, Duration::from_millis(20));
    gate.open();
    for n in 1..=20 {
        line(&w, &format!("line-{n}"));
    }
    let outcome = f.stop_and_join(soon());
    assert!(
        matches!(outcome, StopOutcome::Joined(FlushEnd::Clean)),
        "{outcome:?}"
    );
    let want: Vec<String> = (1..=20).map(|n| format!("line-{n}")).collect();
    assert_eq!(
        kept(&out),
        want,
        "every accepted line is on the sink at join"
    );
}

/// A writer idle on an empty queue is woken by the stop itself: nothing else is
/// left to send it a message, so only the `Stop` wake can end it. The row stops
/// only once the writer has written its line and come round to wait again.
#[test]
fn an_idle_writer_is_woken_by_the_stop() {
    let (w, f, _out) = scripted(vec![]);
    wait_until("the writer waits for its first message", || {
        w.idle_polls() >= 1
    });
    line(&w, "x");
    wait_until("the writer wrote the line and waits again", || {
        w.idle_polls() >= 2
    });
    let outcome = f.stop_and_join(soon());
    assert!(
        matches!(outcome, StopOutcome::Joined(FlushEnd::Clean)),
        "{outcome:?}"
    );
    drop(w);
}

/// A send that starts after the close must not hold the writer up: a stream of
/// such sends would otherwise keep the in-flight count above zero for good and
/// the stop could never join. The late send is parked right after it would
/// register; the writer, released afterwards, must still finish.
#[test]
fn a_send_that_starts_after_the_close_does_not_hold_the_writer_up() {
    let (w, f, sink_gate, _out) = parked(64, 1 << 20);
    line(&w, "first");
    assert!(
        sink_gate.wait_entered(),
        "the writer is parked inside the sink"
    );
    let outcome = f.stop_and_join(Instant::now());
    let StopOutcome::NotJoined(worker) = outcome else {
        panic!("a parked worker is not joined: {outcome:?}");
    };
    let late_gate = Gate::closed();
    w.park_after_register(&late_gate);
    let late = {
        let w = w.clone();
        thread::spawn(move || line(&w, "late"))
    };
    // The late send either parks after registering or, when the close is
    // checked first, returns at once: neither may keep the writer waiting. Wait
    // until it has done one or the other before the writer is let go.
    wait_until("the late send parked or returned", || {
        late_gate.has_entered() || late.is_finished()
    });
    sink_gate.open();
    bounded(worker, "the kept worker");
    late_gate.open();
    bounded(late, "the late sender");
    assert_eq!(w.dropped_lines(), 1, "the late line is counted");
}

#[test]
fn a_clone_cannot_enqueue_once_the_writer_is_stopped() {
    // The writer is parked inside its sink, so it is alive and could still take
    // a line: only the closed flag can refuse the late one.
    let (w, f, gate, out) = parked(64, 1 << 20);
    let clone = w.clone();
    line(&w, "first");
    assert!(gate.wait_entered(), "the writer is parked inside the sink");
    let outcome = f.stop_and_join(Instant::now());
    let StopOutcome::NotJoined(worker) = outcome else {
        panic!("a parked worker is not joined: {outcome:?}");
    };
    line(&clone, "after");
    assert_eq!(clone.dropped_lines(), 1, "a late line is counted");
    assert_eq!(clone.queued_bytes(), 0, "and never queued");
    gate.open();
    bounded(worker, "the kept worker");
    assert!(!out.text().contains("after"), "{}", out.text());
}

#[test]
fn a_blocked_sink_and_a_full_queue_end_the_stop_at_the_deadline_with_the_worker_kept() {
    let (w, f, gate, _out) = parked(1, 1 << 20);
    line(&w, "a");
    assert!(gate.wait_entered(), "the worker is parked inside the sink");
    line(&w, "b");
    line(&w, "c");
    let outcome = f.stop_and_join(Instant::now());
    assert!(!outcome.permits_exec(), "an unjoined writer forbids exec");
    let StopOutcome::NotJoined(worker) = outcome else {
        panic!("a parked worker is not joined: {outcome:?}");
    };
    gate.open();
    bounded(worker, "the kept worker");
}

struct PanicSink;

impl Write for PanicSink {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        panic!("sink fault");
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_worker_that_failed_is_reported_and_forbids_exec() {
    let (w, f) = spawn(Box::new(PanicSink), 64, 1 << 20, NoticeFormat::Text).expect("spawn");
    line(&w, "x");
    let outcome = f.stop_and_join(soon());
    assert!(matches!(outcome, StopOutcome::WorkerFailed), "{outcome:?}");
    assert!(!outcome.permits_exec());
}

struct FlushFails(Accepted);

impl Write for FlushFails {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.push(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "flush"))
    }
}

#[test]
fn a_joined_flush_error_still_permits_exec() {
    let out = Accepted::default();
    let (w, f) = spawn(
        Box::new(FlushFails(out.clone())),
        64,
        1 << 20,
        NoticeFormat::Text,
    )
    .expect("spawn");
    line(&w, "x");
    let outcome = f.stop_and_join(soon());
    assert!(
        matches!(outcome, StopOutcome::Joined(FlushEnd::SinkError)),
        "{outcome:?}"
    );
    assert!(
        outcome.permits_exec(),
        "a joined sink error alone does not block exec"
    );
    assert_eq!(kept(&out), ["x"]);
}

#[test]
fn only_a_joined_stop_permits_exec() {
    assert!(StopOutcome::Joined(FlushEnd::Clean).permits_exec());
    assert!(StopOutcome::Joined(FlushEnd::SinkError).permits_exec());
    assert!(!StopOutcome::WorkerFailed.permits_exec());
    let running = thread::spawn(|| FlushEnd::Clean);
    assert!(!StopOutcome::NotJoined(running).permits_exec());
}

/// The one race a stop has: a line already past the closed check when the stop
/// begins. It must reach the sink, not vanish between the drain and the exit.
/// The writer is parked after its drain pass, then let go while the sender is
/// still in flight; the sender is released only once the writer is seen waiting
/// for it, so no clock decides which of the two comes first.
#[test]
fn a_send_in_flight_when_the_stop_begins_is_written_not_lost() {
    let (w, f, out) = scripted(vec![]);
    let check_gate = Gate::closed();
    let drain_gate = Gate::closed();
    w.park_after_check(&check_gate);
    w.park_after_drain(&drain_gate);
    let sender = {
        let w = w.clone();
        thread::spawn(move || line(&w, "racing"))
    };
    assert!(
        check_gate.wait_entered(),
        "the sender is past the closed check"
    );
    let stopper = thread::spawn(move || f.stop_and_join(Instant::now() + WATCHDOG));
    assert!(
        drain_gate.wait_entered(),
        "the writer finished a drain pass"
    );
    // The writer goes on while the sender is still in flight, and must wait for
    // it: the sender is released only once the writer is seen waiting.
    drain_gate.open();
    wait_until("the writer waits for the in-flight sender", || {
        w.inflight_waits() >= 1
    });
    check_gate.open();
    bounded(sender, "the sender");
    let outcome = bounded(stopper, "the stop");
    assert!(matches!(outcome, StopOutcome::Joined(_)), "{outcome:?}");
    assert_eq!(kept(&out), ["racing"], "the in-flight line was written");
    assert_eq!(w.dropped_lines(), 0, "and nothing was dropped");
}

/// A sender parked inside the stop's in-flight window while the queue is full
/// and the sink is parked: the stop still ends at its deadline with the worker
/// kept, and once everything moves, every line is written or counted.
#[test]
fn a_parked_sender_and_a_full_queue_still_end_the_stop_at_the_deadline() {
    let (w, f, sink_gate, out) = parked(1, 1 << 20);
    line(&w, "a");
    assert!(
        sink_gate.wait_entered(),
        "the worker is parked inside the sink"
    );
    line(&w, "b");
    let sender_gate = Gate::closed();
    w.park_after_check(&sender_gate);
    let sender = {
        let w = w.clone();
        thread::spawn(move || line(&w, "c"))
    };
    assert!(
        sender_gate.wait_entered(),
        "the sender is past the closed check"
    );
    let outcome = f.stop_and_join(Instant::now());
    let StopOutcome::NotJoined(worker) = outcome else {
        panic!("a parked worker is not joined: {outcome:?}");
    };
    // The sender finishes against the still-full queue before the sink moves,
    // so the writer cannot make room for it first.
    sender_gate.open();
    bounded(sender, "the sender");
    sink_gate.open();
    bounded(worker, "the kept worker");
    let (notes, data): (Vec<String>, Vec<String>) =
        kept(&out).into_iter().partition(|l| l.contains("dropped "));
    assert_eq!(data, ["a", "b"]);
    assert_eq!(
        w.dropped_lines(),
        1,
        "the line that found a full queue is counted"
    );
    assert_eq!(
        notices(&notes),
        [1],
        "and the writer reported it: {notes:?}"
    );
}
