// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202: a clock that fails at one window read and reads again before
//! the send. Since the send reads the clock once more (and refuses there), a
//! window judged on a failed read would pass through to a later, readable
//! check; these rows pin each window read on its own.

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
