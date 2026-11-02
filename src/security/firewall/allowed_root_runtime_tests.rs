// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Runtime-context rows: the check waits for a blocked read without
//! panicking in any caller context, keeps other tasks moving, and refuses at
//! once when every resolver is held (R16c-R16h; design section 4's table).
//! Each row first proves its check reached the resolver in that context,
//! then expires the deadline with the clock seam. Every hang guard is 30 s.
//! Batch 3c.

use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use serde_json::json;

use super::super::*;
use super::seam::{Event, Gated, Manual, forced, seamed};
use super::tree::Fx;

const HANG: Duration = Duration::from_secs(30);

struct Rig {
    fx: Arc<Fx>,
    gate: Arc<Gated>,
    clock: Arc<Manual>,
    tx: Sender<Event>,
    rx: Receiver<Event>,
}

fn rig() -> Rig {
    let (gate, tx, rx) = Gated::new();
    let clock = Manual::new();
    let (g, c) = (Arc::clone(&gate), Arc::clone(&clock));
    let fx = seamed(Fx::new(&["path"], FirewallAction::Block), |fw| {
        fw.with_resolver(g).with_clock(c)
    });
    Rig {
        fx: Arc::new(fx),
        gate,
        clock,
        tx,
        rx,
    }
}

/// Runs the check and reports its outcome on the rig's channel.
fn report(fx: &Fx, tx: &Sender<Event>) {
    let outcome = forced(fx, &json!({"path": fx.path("safe/f")}));
    let _ = tx.send(Event::Done(outcome));
}

fn entered(rx: &Receiver<Event>) {
    match rx.recv_timeout(HANG) {
        Ok(Event::Entered) => {}
        other => panic!("the check must reach the resolver first: {other:?}"),
    }
}

fn done(rx: &Receiver<Event>) -> Option<RootReason> {
    loop {
        match rx.recv_timeout(HANG) {
            Ok(Event::Entered) => {}
            Ok(Event::Done(outcome)) => return outcome,
            Err(e) => panic!("the check never returned: {e}"),
        }
    }
}

/// Starts the check in a context through `start`, proves it entered the
/// resolver, moves the clock past the budget and expects `timeout`.
fn expires_in(row: &str, start: impl FnOnce(Arc<Fx>, Sender<Event>)) {
    let rig = rig();
    let _open = rig.gate.guard();
    start(Arc::clone(&rig.fx), rig.tx.clone());
    entered(&rig.rx);
    rig.clock.advance(Duration::from_secs(3));
    assert_eq!(done(&rig.rx), Some(RootReason::Timeout), "{row}");
}

/// R16d: inside a current-thread runtime's `block_on`, where
/// `block_in_place` panics, the check waits directly; R16h: on a plain
/// thread with no runtime too.
#[test]
fn r16d_r16h_current_thread_and_no_runtime_wait_directly() {
    expires_in("R16d", |fx, tx| {
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("runtime");
            rt.block_on(async { report(&fx, &tx) });
        });
    });
    expires_in("R16h", |fx, tx| {
        std::thread::spawn(move || report(&fx, &tx));
    });
}

/// R16f: inside `spawn_blocking` on a multi-thread runtime; R16g: a plain
/// thread with an entered multi-thread handle.
#[test]
fn r16f_r16g_multi_thread_contexts_do_not_panic() {
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .build()
            .expect("runtime"),
    );
    expires_in("R16f", |fx, tx| {
        drop(rt.spawn_blocking(move || report(&fx, &tx)));
    });
    let handle = rt.handle().clone();
    expires_in("R16g", |fx, tx| {
        std::thread::spawn(move || {
            let _entered = handle.enter();
            report(&fx, &tx);
        });
    });
}

/// R16c: with all four resolvers held by blocked checks, a fifth check
/// refuses `resolver_busy` without queueing.
#[test]
fn r16c_all_slots_held_refuses_at_once() {
    let rig = rig();
    let _open = rig.gate.guard();
    for _ in 0..RESOLVER_THREADS {
        let (fx, tx) = (Arc::clone(&rig.fx), rig.tx.clone());
        std::thread::spawn(move || report(&fx, &tx));
        entered(&rig.rx);
    }
    let (fifth_tx, fifth_rx) = mpsc::channel();
    let fx = Arc::clone(&rig.fx);
    std::thread::spawn(move || report(&fx, &fifth_tx));
    assert_eq!(done(&fifth_rx), Some(RootReason::ResolverBusy));
}

/// R16e: on a two-worker runtime, two checks blocked on reads leave a third
/// task free to run before either read is released: the third task records
/// how many checks had returned when it ran, and none had, so it did not
/// wait for a worker their timeout freed.
#[test]
fn r16e_blocked_checks_do_not_pin_the_workers() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .build()
        .expect("runtime");
    let rig = rig();
    let _open = rig.gate.guard();
    let returned = Arc::new(AtomicUsize::new(0));
    for _ in 0..2 {
        let (fx, tx, r) = (Arc::clone(&rig.fx), rig.tx.clone(), Arc::clone(&returned));
        drop(rt.spawn(async move {
            report(&fx, &tx);
            r.fetch_add(1, Ordering::SeqCst);
        }));
        entered(&rig.rx);
    }
    let (ran_tx, ran_rx) = mpsc::channel();
    let r = Arc::clone(&returned);
    drop(rt.spawn(async move {
        let _ = ran_tx.send(r.load(Ordering::SeqCst));
    }));
    let seen = ran_rx
        .recv_timeout(HANG)
        .expect("a third task ran while both checks waited");
    assert_eq!(seen, 0, "the third task ran only after a check returned");
}
