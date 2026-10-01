// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7681.GH2473.2 and MIK-7682.GH2568.2: the per-session stores stay
//! bounded. Many sessions reaped by their TTL leave no entry in any store, and
//! a call still in flight when its session ends leaves nothing after the grace
//! pass. Both go through the production wiring: `wire_meta_session_cleanup`,
//! the multiplexer reaper and `SessionLifecycle::reap`.

use std::sync::Arc;
use std::time::Duration;

use super::MetaMcp;
use crate::backend::BackendRegistry;
use crate::config::StreamingConfig;
use crate::gateway::session_id::SessionOwner;
use crate::gateway::session_lifecycle::{
    END_GRACE, SessionLifecycle, now_unix, wire_meta_session_cleanup,
};
use crate::gateway::streaming::NotificationMultiplexer;
use crate::transition::TransitionTracker;

const SESSIONS: usize = 64;

struct Wired {
    meta: Arc<MetaMcp>,
    lifecycle: Arc<SessionLifecycle>,
    tracker: Arc<TransitionTracker>,
}

fn wired() -> Wired {
    let tracker = Arc::new(TransitionTracker::new());
    let meta = Arc::new(MetaMcp::with_features(
        Arc::new(BackendRegistry::new()),
        None,
        None,
        None,
        Duration::from_secs(60),
    ));
    meta.set_transition_tracker(Arc::clone(&tracker));
    let lifecycle = Arc::new(SessionLifecycle::new());
    wire_meta_session_cleanup(&lifecycle, &meta);
    Wired {
        meta,
        lifecycle,
        tracker,
    }
}

/// Write one entry under `id` in every per-session store, as a call would.
fn write_every_store(w: &Wired, id: &str) {
    w.meta.session_profiles.set_profile(id, "strict");
    w.meta.session_state.set_state(id, "working");
    w.meta
        .cost_tracker
        .record(id, None, "backend", "tool", 10, 1.0);
    w.tracker.record_transition(id, "backend:tool");
    #[cfg(feature = "spec-preview")]
    w.meta
        .session_promoted
        .insert(id.to_owned(), vec!["tool".to_owned()]);
}

/// Entries per store: profile, FSM state, cost, last tool, promoted tools.
fn counts(w: &Wired) -> [usize; 5] {
    #[cfg(feature = "spec-preview")]
    let promoted = w.meta.session_promoted.len();
    #[cfg(not(feature = "spec-preview"))]
    let promoted = 0;
    [
        w.meta.session_profiles.len(),
        w.meta.session_state.len(),
        usize::try_from(w.meta.cost_tracker.aggregate().session_count)
            .expect("fits"),
        w.tracker.key_count(),
        promoted,
    ]
}

#[tokio::test]
async fn many_sessions_reaped_by_their_ttl_leave_no_entry_in_any_store() {
    let w = wired();
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::new(BackendRegistry::new()),
        StreamingConfig {
            session_ttl: Duration::from_millis(1),
            session_reaper_interval: Duration::from_millis(20),
            ..StreamingConfig::default()
        },
    ));
    let owner = SessionOwner::Credential("bound".to_owned());
    for _ in 0..SESSIONS {
        let (id, receiver) = multiplexer.get_or_create_session_for(None, &owner);
        drop(receiver);
        write_every_store(&w, &id);
    }
    let seeded = counts(&w);
    assert_eq!(seeded[0], SESSIONS, "seeded every store: {seeded:?}");

    multiplexer.spawn_reaper_on(Arc::clone(&w.lifecycle));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while multiplexer.session_count() > 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the reaper never ran"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert_eq!(
        counts(&w),
        [0; 5],
        "every store returns to empty once its sessions expire"
    );
}

#[tokio::test]
async fn a_call_in_flight_when_its_session_ends_leaves_no_state_after_the_grace_pass() {
    let w = Arc::new(wired());
    let release = Arc::new(tokio::sync::Notify::new());
    // The call resolved its session before the end and writes after it.
    let call = {
        let w = Arc::clone(&w);
        let release = Arc::clone(&release);
        tokio::spawn(async move {
            release.notified().await;
            write_every_store(&w, "gone");
        })
    };

    w.lifecycle.on_disconnect("gone");
    release.notify_one();
    call.await.expect("the call finished");
    assert_eq!(
        counts(&w)[0],
        1,
        "the late write landed after the first cleanup pass"
    );

    w.lifecycle.reap(now_unix() + END_GRACE.as_secs() + 1);

    assert_eq!(counts(&w), [0; 5], "nothing the late call wrote survives");
}
