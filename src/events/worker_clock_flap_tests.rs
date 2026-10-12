// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202: a clock that fails at one window read and reads again before
//! the send. Since the send reads the clock once more (and refuses there), a
//! window judged on a failed read would pass through to a later, readable
//! check; these rows pin each window read on its own.
//! The last row (MIK-8202.AC.16 R8) runs the delivery worker's loop itself
//! across a clock that fails and then reads again.

use super::{
    NAME, assert_kept_unsent, counting_callback, logged_services, offer, private_callbacks, queued,
    queued_overdue, stored,
};
use crate::clock::test_clock::{Forced, queued as scripted};
use crate::events::EventsHub;

/// Run `attempt` with this thread's next clock reads from pause point `slot`
/// scripted as `reads` (`None` reads before 1970); every later read is the
/// real clock. The returned guard keeps the script until dropped.
async fn clock_scripted_at(
    slot: &crate::test_pause::Slot,
    reads: &[Option<u64>],
    attempt: impl std::future::Future<Output = ()>,
) -> Forced {
    let (reached, release) = slot.arm();
    let drive = async {
        reached.notified().await;
        let clock = scripted(reads);
        release.notify_one();
        clock
    };
    let ((), clock) =
        crate::test_pause::within("the attempt", async { tokio::join!(attempt, drive) }).await;
    clock
}

/// E3, a flap: the access check after the claim reads the clock, the retry
/// window's read fails, and the clock reads again afterwards. The overdue
/// record is kept unsent with its date: not buried on a window that could
/// not be judged, and not sent.
#[tokio::test]
async fn a_window_read_that_fails_once_keeps_an_overdue_record() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&private_callbacks(), dir.path()).expect("hub");
    let services = logged_services(dir.path());
    offer(&hub, &[NAME]);
    let (port, accepted) = counting_callback().await;
    queued_overdue(&hub, port, "evt_f1");
    let before = stored(dir.path(), "evt_f1");
    let secs = crate::clock::unix_secs().expect("a readable clock");
    let clock = Box::pin(clock_scripted_at(
        &hub.after_claim,
        &[Some(secs), None],
        hub.attempt(&services, "evt_f1"),
    ))
    .await;
    drop(clock);
    let posts = accepted.load(std::sync::atomic::Ordering::SeqCst);
    assert_kept_unsent(&hub, dir.path(), &before, "evt_f1", posts);
}

/// E3b, a flap: the last window read before the send fails, and the send's
/// own read is readable again. Nothing is sent on a lease and window that
/// were never judged.
#[tokio::test]
async fn a_last_window_read_that_fails_once_sends_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&private_callbacks(), dir.path()).expect("hub");
    let services = logged_services(dir.path());
    offer(&hub, &[NAME]);
    let (port, accepted) = counting_callback().await;
    queued(&hub, port, "evt_f2");
    let before = stored(dir.path(), "evt_f2");
    let clock = Box::pin(clock_scripted_at(
        &hub.before_window,
        &[None],
        hub.attempt(&services, "evt_f2"),
    ))
    .await;
    drop(clock);
    let posts = accepted.load(std::sync::atomic::Ordering::SeqCst);
    assert_kept_unsent(&hub, dir.path(), &before, "evt_f2", posts);
}

/// MIK-8202.AC.16 R8 (P4a): the events delivery worker stays alive on a clock
/// before 1970 (release builds abort on a panic, so a clock read that panics
/// there takes the gateway down). Green on base: P3 routed every events
/// clock read through `crate::clock`, and the worker skips what it cannot
/// date. This is the proof AC.16 names, not a red.
///
/// The worker is the loop `EventsHub::start` spawns, `deliver_forever`. The
/// clock override is per thread; this runtime is current-thread, so the
/// spawned worker is polled on this thread and every clock read of its ticks
/// is forced. Time is paused while the clock is forced: the sleep below ends
/// only once the runtime is idle, so the worker has run whole ticks at 0, 5
/// and 10 s (its idle wait is 5 s). The first tick sweeps (dead letters and
/// lifecycle): the loop sweeps on its first tick. Its 30 s sweep period is
/// measured on std time, which a paused clock does not move, so that first
/// sweep is the one this row covers.
///
/// Mutant M8, "the worker's clock refusal panics": in
/// `src/events/worker_dispatch.rs:55-57` (`dispatch`, run every tick) replace
/// `let Ok(now) = crate::clock::utc_now() else { return IDLE; };` with
/// `let now = crate::clock::utc_now().expect("a readable clock");`. The worker
/// panics at its first tick and its task finishes: this row fails at
/// `is_finished`.
#[tokio::test(start_paused = true)]
async fn the_delivery_worker_outlives_a_clock_before_1970() {
    use std::sync::atomic::Ordering::{Release, SeqCst};
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&private_callbacks(), dir.path()).expect("hub");
    let services = std::sync::Arc::new(logged_services(dir.path()));
    offer(&hub, &[NAME]);
    let (port, accepted) = counting_callback().await;
    queued(&hub, port, "evt_r8");
    // Startup reconciled: only the clock stands between the record and its send.
    hub.runtime.reconciled.store(true, Release);

    let clock = crate::clock::test_clock::before_epoch();
    let worker = tokio::spawn({
        let (hub, services) = (
            std::sync::Arc::clone(&hub),
            std::sync::Arc::clone(&services),
        );
        async move { hub.deliver_forever(&services).await }
    });
    // Paused: three of the worker's ticks, not a window.
    tokio::time::sleep(std::time::Duration::from_secs(11)).await;
    assert!(
        !worker.is_finished(),
        "the delivery worker died on a clock before 1970"
    );
    assert_eq!(accepted.load(SeqCst), 0, "sent on an unreadable clock");

    // Recovery: the clock reads again, and the same worker sends the record.
    drop(clock);
    tokio::time::resume();
    hub.runtime.wake.notify_one();
    crate::test_wait::wait_until(crate::test_wait::HANG_BOUND, || async {
        match accepted.load(SeqCst) {
            0 => std::ops::ControlFlow::Continue("no send yet".to_owned()),
            _ => std::ops::ControlFlow::Break(()),
        }
    })
    .await
    .expect("the worker sends once the clock reads");
    assert_eq!(accepted.load(SeqCst), 1, "sent more than once");
    assert!(!worker.is_finished(), "the worker stopped after recovering");
    worker.abort();
}
