// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit rows for the session lifecycle registry.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn an_idle_deadline_does_not_fire_a_session_end_handler() {
    let lifecycle = SessionLifecycle::new();
    let ended = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&ended);
    lifecycle.register_session_end("ended", move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
    });
    lifecycle.track("quiet-session", 0);

    assert_eq!(lifecycle.reap(1), 1);
    assert_eq!(
        ended.load(Ordering::SeqCst),
        0,
        "a session that is only idle is still live"
    );

    lifecycle.on_disconnect("quiet-session");
    assert_eq!(ended.load(Ordering::SeqCst), 1, "a real end fires it once");
}

#[test]
fn a_session_end_is_cleaned_a_second_time_after_the_grace_period() {
    let lifecycle = SessionLifecycle::new();
    let fired = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&fired);
    lifecycle.register_session_end("count", move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
    });

    lifecycle.on_disconnect("ended");
    assert_eq!(fired.load(Ordering::SeqCst), 1);

    // A call in flight at the end writes after the first pass.
    lifecycle.reap(now_unix().expect("clock after 1970"));
    assert_eq!(fired.load(Ordering::SeqCst), 1, "not before the grace");

    lifecycle.reap(now_unix().expect("clock after 1970") + END_GRACE.as_secs() + 1);
    assert_eq!(fired.load(Ordering::SeqCst), 2, "the second pass");

    lifecycle.reap(now_unix().expect("clock after 1970") + 2 * END_GRACE.as_secs());
    assert_eq!(fired.load(Ordering::SeqCst), 2, "and only once");
}

#[test]
fn a_refreshed_key_keeps_only_its_latest_deadline() {
    // Tracking the same key twice used to keep both deadlines. The older
    // one then reclaimed a caller that was still live, and the handlers —
    // which free things — ran twice for one key.
    let lifecycle = SessionLifecycle::new();
    let fired = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&fired);
    lifecycle.register("test", move |_key| {
        counter.fetch_add(1, Ordering::SeqCst);
    });

    lifecycle.track("caller-a", 100);
    lifecycle.track("caller-a", 200);
    assert_eq!(
        lifecycle.tracked_count(),
        1,
        "one key must hold one deadline, not one per refresh"
    );

    lifecycle.reap(150);
    assert_eq!(
        fired.load(Ordering::SeqCst),
        0,
        "a refreshed caller must not be reclaimed on its previous deadline"
    );
    assert_eq!(lifecycle.tracked_count(), 1, "and must still be tracked");

    lifecycle.reap(250);
    assert_eq!(
        fired.load(Ordering::SeqCst),
        1,
        "past its real deadline it is reclaimed exactly once"
    );
}

#[test]
fn a_disconnect_drops_the_deadline_so_reaping_cannot_repeat_it() {
    let lifecycle = SessionLifecycle::new();
    let fired = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&fired);
    lifecycle.register("test", move |_key| {
        counter.fetch_add(1, Ordering::SeqCst);
    });

    lifecycle.track("caller-b", 100);
    lifecycle.on_disconnect("caller-b");
    assert_eq!(fired.load(Ordering::SeqCst), 1);

    lifecycle.reap(200);
    assert_eq!(
        fired.load(Ordering::SeqCst),
        1,
        "a key already reclaimed must not be reclaimed again by a later reap"
    );
}

#[test]
fn test_callback_fires_on_disconnect() {
    let lifecycle = SessionLifecycle::new();
    let counter = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&counter);
    lifecycle.register("test", move |_sid| {
        c.fetch_add(1, Ordering::SeqCst);
    });

    lifecycle.on_disconnect("session-123");
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    // Multiple disconnects increment
    lifecycle.on_disconnect("session-456");
    assert_eq!(counter.load(Ordering::SeqCst), 2);
}

#[test]
fn test_multiple_callbacks() {
    let lifecycle = SessionLifecycle::new();
    let counter = Arc::new(AtomicUsize::new(0));

    for i in 0..3 {
        let c = Arc::clone(&counter);
        lifecycle.register(format!("handler-{i}"), move |_sid| {
            c.fetch_add(1, Ordering::SeqCst);
        });
    }

    lifecycle.on_disconnect("sess-1");
    assert_eq!(counter.load(Ordering::SeqCst), 3);
    assert_eq!(lifecycle.handler_count(), 3);
}

#[test]
fn test_receives_correct_session_id() {
    let lifecycle = SessionLifecycle::new();
    let captured = Arc::new(RwLock::new(String::new()));
    let c = Arc::clone(&captured);
    lifecycle.register("id-check", move |sid| {
        *c.write() = sid.to_string();
    });

    lifecycle.on_disconnect("abc-def-123");
    assert_eq!(*captured.read(), "abc-def-123");
}

#[test]
fn test_empty_lifecycle_is_noop() {
    let lifecycle = SessionLifecycle::new();
    lifecycle.on_disconnect("no-handlers"); // should not panic
    assert_eq!(lifecycle.handler_count(), 0);
}

/// MIK-7828.FIX.2: a held key survives a sweep past its deadline, stays
/// held until its last holder lets go, and is then due one `IDLE_TTL`
/// from that moment, not on the deadline it had before.
#[test]
fn a_held_key_is_reclaimed_only_an_idle_ttl_after_its_last_hold() {
    let lifecycle = Arc::new(SessionLifecycle::new());
    let fired = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&fired);
    lifecycle.register("count", move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
    });
    lifecycle.track("caller", 10);
    let first = lifecycle.hold("caller");
    let second = lifecycle.hold("caller");
    assert_eq!(lifecycle.reap(20), 0, "reclaimed while held");
    drop(first);
    assert_eq!(
        lifecycle.reap(20),
        0,
        "reclaimed while one call still holds it"
    );
    assert_eq!(
        lifecycle.reap(now_unix().expect("clock after 1970") + IDLE_TTL.as_secs() + 1),
        0,
        "the first release freed a key the second call still holds"
    );
    drop(second);
    let released = now_unix().expect("clock after 1970");
    assert_eq!(
        lifecycle.reap(20),
        0,
        "reclaimed on the deadline before the hold"
    );
    assert_eq!(
        lifecycle.reap(released + IDLE_TTL.as_secs() - 1),
        0,
        "reclaimed before an idle TTL had passed since the call ended"
    );
    assert_eq!(
        lifecycle.reap(now_unix().expect("clock after 1970") + IDLE_TTL.as_secs() + 1),
        1
    );
    assert_eq!(fired.load(Ordering::SeqCst), 1);
}

/// A hold asked for while a sweep is freeing that key's state is granted
/// only once the freeing is done, so the held call's writes come after it.
/// The handler does not finish until it is told to, so a hold granted
/// early is seen as early. A holder thread slower than the 500 ms wait
/// can still hide a missing wait (never fail a correct one); the
/// handler counts as finished only when told to, not on its timeout.
#[test]
fn a_hold_waits_for_a_sweep_already_freeing_its_key() {
    use std::sync::mpsc::{RecvTimeoutError, channel};
    use std::time::Duration;
    let lifecycle = Arc::new(SessionLifecycle::new());
    let freed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (started_tx, started_rx) = channel();
    let (go_tx, go_rx) = channel::<()>();
    let go_rx = parking_lot::Mutex::new(go_rx);
    let done = Arc::clone(&freed);
    lifecycle.register("slow", move |_| {
        started_tx.send(()).expect("test alive");
        if go_rx.lock().recv_timeout(Duration::from_secs(10)).is_ok() {
            done.store(true, Ordering::SeqCst);
        }
    });
    lifecycle.track("caller", 0);
    let sweeper = Arc::clone(&lifecycle);
    let sweep = std::thread::spawn(move || sweeper.reap(1));
    started_rx.recv().expect("the sweep chose the key");

    let (held_tx, held_rx) = channel();
    let (holder, seen) = (Arc::clone(&lifecycle), Arc::clone(&freed));
    let hold = std::thread::spawn(move || {
        let hold = holder.hold("caller");
        held_tx
            .send(seen.load(Ordering::SeqCst))
            .expect("test alive");
        drop(hold);
    });
    let freed_when_held = match held_rx.recv_timeout(Duration::from_millis(500)) {
        Ok(freed_when_held) => freed_when_held,
        Err(RecvTimeoutError::Timeout) => {
            go_tx.send(()).expect("handler alive");
            held_rx.recv().expect("the hold is granted after the sweep")
        }
        Err(RecvTimeoutError::Disconnected) => panic!("the holder died"),
    };
    let _ = go_tx.send(());
    assert!(
        freed_when_held,
        "a hold was granted while a sweep was still freeing its key"
    );
    hold.join().expect("holder");
    assert_eq!(sweep.join().expect("sweep"), 1);
}

/// A key a request re-tracks after the sweep's snapshot is not reclaimed:
/// each key is decided again under the locks that free it. Before the
/// first key's turn, `b` is renewed; whichever key comes first, only `a`
/// is reclaimed.
#[test]
fn a_key_retracked_after_the_sweep_chose_it_keeps_its_state() {
    let lifecycle = Arc::new(SessionLifecycle::new());
    let fired = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let seen = Arc::clone(&fired);
    lifecycle.register("records", move |key| {
        seen.lock().expect("seen").push(key.to_owned());
    });
    let renew = Arc::downgrade(&lifecycle);
    let mut first = true;
    *lifecycle.between_keys.lock() = Some(Box::new(move || {
        if std::mem::take(&mut first)
            && let Some(lifecycle) = renew.upgrade()
        {
            lifecycle.track("b", u64::MAX);
        }
    }));
    lifecycle.track("a", 0);
    lifecycle.track("b", 0);
    assert_eq!(lifecycle.reap(1), 1, "only a reclaimed: {fired:?}");
    assert_eq!(*fired.lock().expect("seen"), ["a"]);
    assert_eq!(lifecycle.tracked_count(), 1, "b keeps its renewed deadline");
}

/// Likewise a hold taken after the snapshot: the held key is skipped.
#[test]
fn a_key_held_after_the_sweep_chose_it_keeps_its_state() {
    let lifecycle = Arc::new(SessionLifecycle::new());
    let fired = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let seen = Arc::clone(&fired);
    lifecycle.register("records", move |key| {
        seen.lock().expect("seen").push(key.to_owned());
    });
    let holds = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let (taker, kept) = (Arc::downgrade(&lifecycle), Arc::clone(&holds));
    *lifecycle.between_keys.lock() = Some(Box::new(move || {
        let first = kept.lock().is_empty();
        if first && let Some(lifecycle) = taker.upgrade() {
            let hold = lifecycle.hold("b");
            kept.lock().push(hold);
        }
    }));
    lifecycle.track("a", 0);
    lifecycle.track("b", 0);
    assert_eq!(lifecycle.reap(1), 1, "only a reclaimed: {fired:?}");
    assert_eq!(*fired.lock().expect("seen"), ["a"]);
    *lifecycle.between_keys.lock() = None;
    holds.lock().clear();
}

/// A caller that renews while its old deadline's handler is running and
/// then writes fresh state keeps that state (MIK-7746). The handler waits
/// up to 500 ms for the renewer to have written before it wipes. If a
/// renewal can land during the handler, the write is wiped; if the renewal
/// waits for the handler, the wait times out and the write comes after
/// the wipe. A runner slower than the wait can hide the defect, never
/// fail a correct registry.
#[test]
fn a_renewal_during_the_reap_keeps_the_state_it_writes() {
    assert_a_renewal_during_the_handlers_keeps_its_state(|lifecycle| {
        assert_eq!(lifecycle.reap(1), 1);
    });
}

/// The same for a real disconnect: its handlers run under the lock that
/// dropped the deadline.
#[test]
fn a_renewal_during_a_disconnect_keeps_the_state_it_writes() {
    assert_a_renewal_during_the_handlers_keeps_its_state(|lifecycle| {
        lifecycle.on_disconnect("caller");
    });
}

fn assert_a_renewal_during_the_handlers_keeps_its_state(end: impl FnOnce(&SessionLifecycle)) {
    use std::sync::mpsc::channel;
    use std::time::Duration;
    let lifecycle = Arc::new(SessionLifecycle::new());
    let store = Arc::new(parking_lot::Mutex::new(Vec::<&str>::new()));
    let (entered_tx, entered_rx) = channel::<()>();
    let (written_tx, written_rx) = channel::<()>();
    let written_rx = parking_lot::Mutex::new(written_rx);
    let wiped = Arc::clone(&store);
    let probe = Arc::downgrade(&lifecycle);
    lifecycle.register("hints", move |_key| {
        // Whatever the scheduler does, the handler runs under the lock
        // a renewal takes.
        let lifecycle = probe.upgrade().expect("the registry is alive");
        assert!(
            lifecycle.tracked.try_read().is_none(),
            "a cleanup handler ran outside the lock a renewal takes"
        );
        let _ = entered_tx.send(());
        let _ = written_rx.lock().recv_timeout(Duration::from_millis(500));
        wiped.lock().clear();
    });
    lifecycle.track("caller", 0);

    let renewer = std::thread::spawn({
        let (lifecycle, store) = (Arc::clone(&lifecycle), Arc::clone(&store));
        move || {
            entered_rx.recv().expect("the handler started");
            lifecycle.track("caller", u64::MAX);
            store.lock().push("fresh");
            let _ = written_tx.send(());
        }
    });
    end(&lifecycle);
    renewer.join().expect("renewer");

    assert_eq!(
        *store.lock(),
        ["fresh"],
        "a caller renewed while its old deadline was reaped lost its fresh state"
    );
    assert_eq!(lifecycle.tracked_count(), 1, "and its new deadline stays");
}
