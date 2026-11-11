// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The terminal stop of the log writer: admission closes, accepted lines drain,
//! and the worker is joined, or the stop says it was not.

use std::io::{self, Write};
use std::thread;
use std::time::{Duration, Instant};

use super::test_sinks::{Accepted, Gate, WATCHDOG, line, parked, scripted, slow_parked};
use super::{FlushEnd, NoticeFormat, StopOutcome, spawn};

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(10)
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

#[test]
fn a_clone_cannot_enqueue_once_the_writer_is_stopped() {
    let (w, f, out) = scripted(vec![]);
    let clone = w.clone();
    line(&w, "before");
    let outcome = f.stop_and_join(soon());
    assert!(matches!(outcome, StopOutcome::Joined(_)), "{outcome:?}");
    let before = clone.dropped_lines();
    line(&clone, "after");
    assert_eq!(clone.dropped_lines(), before + 1, "a late line is counted");
    assert!(!out.text().contains("after"), "{}", out.text());
}

#[test]
fn a_blocked_sink_and_a_full_queue_end_the_stop_at_the_deadline_with_the_worker_kept() {
    let (w, f, gate, _out) = parked(1, 1 << 20);
    line(&w, "a");
    assert!(gate.wait_entered(), "the worker is parked inside the sink");
    line(&w, "b");
    line(&w, "c");
    let started = Instant::now();
    let outcome = f.stop_and_join(Instant::now() + Duration::from_millis(300));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the stop is bounded"
    );
    assert!(!outcome.permits_exec(), "an unjoined writer forbids exec");
    let StopOutcome::NotJoined(worker) = outcome else {
        panic!("a parked worker is not joined: {outcome:?}");
    };
    gate.open();
    assert!(
        worker.join().is_ok(),
        "the kept worker ends once the sink moves"
    );
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
#[test]
fn a_send_in_flight_when_the_stop_begins_is_written_not_lost() {
    let (w, f, out) = scripted(vec![]);
    let gate = Gate::closed();
    w.park_after_check(&gate);
    let sender = {
        let w = w.clone();
        thread::spawn(move || line(&w, "racing"))
    };
    assert!(gate.wait_entered(), "the sender is past the closed check");
    let stopper = thread::spawn(move || f.stop_and_join(Instant::now() + WATCHDOG));
    let until = Instant::now() + WATCHDOG;
    while !w.is_closed() {
        assert!(Instant::now() < until, "the stop never closed admission");
        thread::yield_now();
    }
    gate.open();
    sender.join().expect("the sender returned");
    let outcome = stopper.join().expect("the stop returned");
    assert!(matches!(outcome, StopOutcome::Joined(_)), "{outcome:?}");
    assert_eq!(kept(&out), ["racing"], "the in-flight line was written");
    assert_eq!(w.dropped_lines(), 0, "and nothing was dropped");
}
