// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7215.CONTROL.5, gap G2: each per-session store `MetaMcp` owns is
//! reclaimed when the session lifecycle fires for its id. Every test goes
//! through `wire_meta_session_cleanup` and `on_disconnect`, the production
//! path, so a store a handler forgets to clear fails here.

use std::sync::Arc;
use std::time::Duration;

use super::MetaMcp;
use crate::backend::BackendRegistry;
use crate::gateway::session_lifecycle::{SessionLifecycle, wire_meta_session_cleanup};
use crate::stats::UsageStats;
use crate::transition::TransitionTracker;

struct Wired {
    meta: Arc<MetaMcp>,
    lifecycle: Arc<SessionLifecycle>,
    stats: Arc<UsageStats>,
    tracker: Arc<TransitionTracker>,
}

fn wired() -> Wired {
    let stats = Arc::new(UsageStats::new());
    let tracker = Arc::new(TransitionTracker::new());
    let meta = Arc::new(MetaMcp::with_features(
        Arc::new(BackendRegistry::new()),
        None,
        Some(Arc::clone(&stats)),
        None,
        Duration::from_secs(60),
    ));
    meta.set_transition_tracker(Arc::clone(&tracker));
    let lifecycle = Arc::new(SessionLifecycle::new());
    wire_meta_session_cleanup(&lifecycle, &meta);
    Wired {
        meta,
        lifecycle,
        stats,
        tracker,
    }
}

#[test]
fn a_disconnect_reclaims_the_routing_profile_and_spares_other_sessions() {
    let w = wired();
    w.meta.session_profiles.set_profile("gone", "strict");
    w.meta.session_profiles.set_profile("kept", "strict");

    w.lifecycle.on_disconnect("gone");

    assert_eq!(
        w.meta.session_profiles.get_profile_name("gone", "default"),
        "default"
    );
    assert_eq!(
        w.meta.session_profiles.get_profile_name("kept", "default"),
        "strict"
    );
}

#[test]
fn a_disconnect_reclaims_the_fsm_state() {
    let w = wired();
    w.meta.session_state.set_state("gone", "working");
    w.meta.session_state.set_state("kept", "working");

    w.lifecycle.on_disconnect("gone");

    assert_eq!(w.meta.session_state.get_state("gone"), "default");
    assert_eq!(w.meta.session_state.get_state("kept"), "working");
    assert_eq!(w.meta.session_state.len(), 1);
}

#[test]
fn a_disconnect_reclaims_the_session_cost_bucket() {
    let w = wired();
    w.meta
        .cost_tracker
        .record("gone", None, "backend", "tool", 10, 1.0);
    w.meta
        .cost_tracker
        .record("kept", None, "backend", "tool", 10, 1.0);

    w.lifecycle.on_disconnect("gone");

    assert!(w.meta.cost_tracker.session_snapshot("gone").is_none());
    assert!(w.meta.cost_tracker.session_snapshot("kept").is_some());
}

#[test]
fn a_disconnect_forgets_the_last_tool_so_no_transition_spans_it() {
    let w = wired();
    w.tracker.record_transition("gone", "a:first");
    w.lifecycle.on_disconnect("gone");

    w.tracker.record_transition("gone", "b:second");

    assert_eq!(
        w.tracker.total_transitions(),
        0,
        "the first call after a disconnect has no predecessor"
    );
}

#[test]
fn a_disconnect_reclaims_the_cached_token_counter() {
    let w = wired();
    w.stats.record_cached_tokens("backend", Some("gone"), 5);
    w.stats.record_cached_tokens("backend", Some("kept"), 7);

    w.lifecycle.on_disconnect("gone");

    assert_eq!(w.stats.cached_tokens_for_session("gone"), 0);
    assert_eq!(w.stats.cached_tokens_for_session("kept"), 7);
}

#[cfg(feature = "spec-preview")]
#[test]
fn a_disconnect_reclaims_the_promoted_tools() {
    let w = wired();
    w.meta
        .session_promoted
        .insert("gone".to_owned(), vec!["tool".to_owned()]);
    w.meta
        .session_promoted
        .insert("kept".to_owned(), vec!["tool".to_owned()]);

    w.lifecycle.on_disconnect("gone");

    assert!(!w.meta.session_promoted.contains_key("gone"));
    assert!(w.meta.session_promoted.contains_key("kept"));
}

#[test]
fn the_registration_does_not_keep_the_gateway_alive() {
    let w = wired();
    let weak = Arc::downgrade(&w.meta);
    drop(w.meta);
    assert!(weak.upgrade().is_none(), "the registry holds a Weak only");
    w.lifecycle.on_disconnect("any");
}
