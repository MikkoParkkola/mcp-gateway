// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the tools debt a listener owes across refills and sessions
//! (MIK-8007).

use super::super::*;
use super::{Reload, changed, shared};
use crate::events::upstream_need::Interest;

/// MIK-8007: a refill that did not fill is retried once, no sooner than the
/// backend's list-fill cooldown, and silently; a failed retry is not retried
/// again; the debt outlives the session that took it on.
#[test]
fn a_failed_refill_is_retried_once_after_the_cooldown() {
    let shared = shared();
    let due = || shared.tools.lock().due;
    let mut state = State::new(&shared, Era::Modern);
    // A notice the hub has not heard of, due now.
    *shared.tools.lock() = ToolsDebt {
        due: Some(Instant::now()),
        retrying: false,
        unannounced: true,
    };
    assert!(state.take_due_refill(), "the notice's refill is due");
    state.refill_ended(false);
    assert!(
        state.tools_pending,
        "a refill that did not fill still announces"
    );
    state.tools_pending = false;
    let retry = due().expect("the failed refill is retried");
    assert!(retry + Duration::from_secs(1) >= Instant::now() + REFILL_RETRY);
    // A new session keeps the retry and its time.
    let mut state = State::new(&shared, Era::Modern);
    assert!(!state.take_due_refill(), "no retry inside the cooldown");
    shared.tools.lock().due = Some(Instant::now());
    assert!(state.take_due_refill());
    state.refill_ended(false);
    assert!(!state.tools_pending, "the retry is silent");
    assert_eq!(due(), None, "a failed retry is not retried again");
    // A newer notice joining a retry earns its own.
    shared.tools.lock().due = Some(Instant::now());
    state.refill_ended(false);
    {
        let mut debt = shared.tools.lock();
        assert!(debt.retrying, "armed");
        debt.due = Some(Instant::now());
        debt.unannounced = true;
    }
    assert!(state.take_due_refill());
    state.refill_ended(false);
    assert!(state.tools_pending, "the joined notice is announced");
    assert!(
        due().is_some(),
        "the joined notice's failed refill is retried"
    );
}

/// MIK-8007: a silent retry keeps the tool list a reader filled after the
/// failed refill; only a refill serving a notice drops it.
#[tokio::test]
async fn a_silent_retry_keeps_a_readers_fill() {
    let dir = tempfile::tempdir().expect("dir");
    let reload = Reload::new(dir.path());
    reload.to(true).await;
    let backend = reload.registry.get("b").expect("b registered");
    let shared = shared();
    let mut state = State::new(&shared, Era::Modern);
    for (unannounced, kept) in [(false, true), (true, false)] {
        backend.fill_tools_for_test().await;
        assert!(backend.has_cached_tools(), "the reader's fill is cached");
        *shared.tools.lock() = ToolsDebt {
            due: Some(Instant::now()),
            retrying: true,
            unannounced,
        };
        // Left unpolled: only the start's own effect on the cache is seen.
        assert!(start_due_refill(&mut state, &backend).is_some(), "due");
        assert_eq!(
            backend.has_cached_tools(),
            kept,
            "cache kept with unannounced = {unannounced}"
        );
    }
}

/// MIK-8007: a backend tools notice owes a refill, due within a tick, that
/// the hub has not heard of yet.
#[test]
fn a_tools_notice_owes_a_refill_due_within_a_tick() {
    let shared = shared();
    shared
        .need
        .lock()
        .add(&Interest::ToolsChanged)
        .expect("room");
    let mut state = State::new(&shared, Era::Legacy);
    let noted = Instant::now();
    state.note(changed(NoteKind::ToolsChanged), false);
    let debt = shared.tools.lock();
    let due = debt.due.expect("the notice's refill is owed");
    assert!(
        due <= Instant::now() + TICK && due >= noted,
        "due within a tick"
    );
    assert!(debt.unannounced, "the hub has not heard of it");
}

/// MIK-8007: a backend gone from the config owes no tools notice; one added
/// again later starts afresh.
#[tokio::test]
async fn a_removed_backend_owes_no_tools_notice() {
    let shared = shared();
    shared.tools.lock().due = Some(Instant::now());
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    let task = tokio::spawn(run(
        Arc::clone(&shared),
        Arc::new(crate::backend::BackendRegistry::new()),
        Arc::downgrade(&hub),
    ));
    let cleared = tokio::time::timeout(Duration::from_secs(5), async {
        while shared.tools.lock().due.is_some() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    shared.stop.cancel();
    task.await.expect("task");
    assert!(
        cleared.is_ok(),
        "a removed backend still owed a tools refill"
    );
}

/// MIK-8043.ORDER.5: while a finished refill's change waits to be announced,
/// the next due refill is not taken, so the cache the hub announces is not
/// emptied first; it is taken once the change is announced.
#[tokio::test]
async fn a_due_refill_waits_for_the_last_change_to_be_announced() {
    let dir = tempfile::tempdir().expect("dir");
    let reload = Reload::new(dir.path());
    reload.to(true).await;
    let backend = reload.registry.get("b").expect("b registered");
    let shared = shared();
    let mut state = State::new(&shared, Era::Modern);
    backend.fill_tools_for_test().await;
    *shared.tools.lock() = ToolsDebt {
        due: Some(Instant::now()),
        retrying: false,
        unannounced: true,
    };
    state.tools_pending = true;
    assert!(
        start_due_refill(&mut state, &backend).is_none(),
        "a refill started before the last change was announced"
    );
    assert!(
        backend.has_cached_tools(),
        "the announced cache was emptied"
    );
    assert!(
        shared.tools.lock().due.is_some(),
        "the notice is still owed"
    );
    state.tools_pending = false;
    assert!(start_due_refill(&mut state, &backend).is_some(), "then due");
    assert!(!backend.has_cached_tools(), "the notice's refill drops it");
}
