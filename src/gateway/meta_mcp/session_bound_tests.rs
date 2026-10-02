// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7681.GH2473.2: each per-session store stays bounded. Many sessions
//! reaped by their TTL leave no entry, one test per store, through the
//! production wiring: `wire_meta_session_cleanup` and the multiplexer reaper.

use std::sync::Arc;
use std::time::Duration;

use super::MetaMcp;
use crate::backend::BackendRegistry;
use crate::config::StreamingConfig;
use crate::gateway::session_id::SessionOwner;
use crate::gateway::session_lifecycle::{SessionLifecycle, wire_meta_session_cleanup};
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

/// One per-session store: how a call writes it, and how many entries it holds.
struct Store {
    write: fn(&Wired, &str),
    count: fn(&Wired) -> usize,
}

const PROFILE: Store = Store {
    write: |w, id| w.meta.session_profiles.set_profile(id, "strict"),
    count: |w| w.meta.session_profiles.len(),
};
const FSM_STATE: Store = Store {
    write: |w, id| {
        w.meta.session_state.set_state(id, "working");
    },
    count: |w| w.meta.session_state.len(),
};
const COST: Store = Store {
    write: |w, id| {
        w.meta
            .cost_tracker
            .record(id, None, "backend", "tool", 10, 1.0);
    },
    count: cost_sessions,
};

fn cost_sessions(w: &Wired) -> usize {
    let sessions = w.meta.cost_tracker.aggregate().session_count;
    usize::try_from(sessions).expect("fits")
}
const LAST_TOOL: Store = Store {
    write: |w, id| w.tracker.record_transition(id, "backend:tool"),
    count: |w| w.tracker.key_count(),
};
#[cfg(feature = "spec-preview")]
const PROMOTED: Store = Store {
    write: |w, id| {
        w.meta
            .session_promoted
            .insert(id.to_owned(), vec!["tool".to_owned()]);
    },
    count: |w| w.meta.session_promoted.len(),
};

/// Open `SESSIONS` legacy sessions, write `store` under each, let the reaper
/// expire them all by their TTL, and find the store empty again.
async fn reaped_sessions_leave_the_store_empty(store: &Store) {
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
        (store.write)(&w, &id);
    }
    assert_eq!((store.count)(&w), SESSIONS, "one entry per session");

    multiplexer.spawn_reaper_on(Arc::clone(&w.lifecycle));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while multiplexer.session_count() > 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the reaper never ran"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert_eq!((store.count)(&w), 0, "the expired sessions left entries");
}

#[tokio::test]
async fn reaped_sessions_leave_no_routing_profile() {
    reaped_sessions_leave_the_store_empty(&PROFILE).await;
}

#[tokio::test]
async fn reaped_sessions_leave_no_fsm_state() {
    reaped_sessions_leave_the_store_empty(&FSM_STATE).await;
}

#[tokio::test]
async fn reaped_sessions_leave_no_cost_bucket() {
    reaped_sessions_leave_the_store_empty(&COST).await;
}

#[tokio::test]
async fn reaped_sessions_leave_no_last_tool() {
    reaped_sessions_leave_the_store_empty(&LAST_TOOL).await;
}

#[cfg(feature = "spec-preview")]
#[tokio::test]
async fn reaped_sessions_leave_no_promoted_tools() {
    reaped_sessions_leave_the_store_empty(&PROMOTED).await;
}
