// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! #1785 and #2093: the caller key holds on the per-backend and legacy routes.
//!
//! A child of `caller_key`, so it reuses that file's callers and requests; it
//! lives apart only to keep both files under the size limit.

use super::Outcome::{BudgetSpent, Delivered, TenantReach};
use super::{
    Caller, api_key, call, call_with, direct_call, firewall, keys, send,
    state_with_firewalls_and_auth, tenant_firewall,
};
use crate::gateway::router::create_router;
use crate::security::firewall::{Firewall, FirewallConfig};
use crate::transition::TransitionTracker;
use serde_json::json;
use std::sync::Arc;

/// Anomaly detection learning into `tracker`, which the row keeps to read what
/// was learned. The warm-up is pinned high so no call is ever scored, let alone
/// blocked: every call is admitted and learned, and only its predecessor (the
/// caller's own history) decides whether it adds a transition.
fn learning_firewall(tracker: &Arc<TransitionTracker>) -> Arc<Firewall> {
    Arc::new(Firewall::from_config(
        FirewallConfig {
            enabled: true,
            scan_requests: true,
            scan_responses: false,
            anomaly_detection: true,
            anomaly_min_observations: 20,
            ..FirewallConfig::default()
        },
        Some(Arc::clone(tracker)),
    ))
}

// ── #1785: each /mcp/{name} caller builds its own anomaly history ────────────

#[tokio::test]
async fn h21_each_direct_route_caller_has_its_own_anomaly_history() {
    // A call learns one transition only when its caller has a previous call.
    // Keyed per caller, key-two's first call has none. Keyed on the shared
    // `direct:demo` bucket, key-one's call is its predecessor: one caller's
    // sequence is scored against, and poisons, another's.
    let tracker = Arc::new(TransitionTracker::new());
    let fw = learning_firewall(&tracker);
    let auth = keys(vec![api_key("key-one", "one"), api_key("key-two", "two")]);
    let (state, _store) = state_with_firewalls_and_auth(Arc::clone(&fw), fw, &auth).await;
    let router = create_router(state);
    let callers = ["key-one", "key-two"];
    for (n, bearer) in callers.into_iter().enumerate() {
        let (outcome, _, body) = send(&router, direct_call(bearer, n)).await;
        assert_eq!(outcome, Delivered, "call {n}: {body}");
    }
    assert_eq!(
        tracker.total_transitions(),
        0,
        "key-two's first call followed key-one's: the two share one history"
    );
    // Not vacuous: each caller's second call does extend its own history.
    for (n, bearer) in callers.into_iter().enumerate() {
        let (outcome, _, body) = send(&router, direct_call(bearer, n + 2)).await;
        assert_eq!(outcome, Delivered, "call {}: {body}", n + 2);
    }
    assert_eq!(
        tracker.total_transitions(),
        2,
        "one learned transition per caller's second call"
    );
}

// ── #2093: a legacy session does not reset its credential's limits ───────────

#[tokio::test]
async fn h22_legacy_sessions_of_one_credential_share_one_budget() {
    // Before the fix a legacy call keyed on its session, so opening a new
    // session bought a fresh budget: the second call is delivered.
    let fw = firewall(false);
    let auth = keys(vec![api_key("key-one", "one"), api_key("key-two", "two")]);
    let (state, _store) = state_with_firewalls_and_auth(Arc::clone(&fw), fw, &auth).await;
    let router = create_router(state);
    let holder = |bearer| Caller {
        bearer: Some(bearer),
        ..Caller::default()
    };
    let (first, opened, body) = send(&router, call(&holder("key-one"), false, None, 0)).await;
    assert_eq!(
        first, Delivered,
        "the first session's call is the first spend: {body}"
    );
    let opened = opened.expect("a legacy call is given a session");
    // No session header: the gateway mints a second session for this call.
    let (second, minted, body) = send(&router, call(&holder("key-one"), false, None, 1)).await;
    // A call that got no session header at all must not pass as "not resumed".
    let minted = minted.expect("the second call is given a session of its own");
    assert_ne!(minted, opened, "the second call resumed the first session");
    assert_eq!(
        second, BudgetSpent,
        "a new session reset the credential's budget: {body}"
    );
    // Guard: the refusal is per credential, not global.
    let (other, _, body) = send(&router, call(&holder("key-two"), false, None, 2)).await;
    assert_eq!(
        other, Delivered,
        "another credential has its own budget: {body}"
    );
}

// ── MIK-7116.TENANT.1: a legacy session does not reset tenant breadth ────────

#[tokio::test]
async fn h23_legacy_sessions_of_one_credential_share_one_tenant_bucket() {
    // The tenant guard allows one tenant per caller. Keyed on the session, a
    // new legacy session would start an empty bucket and reach a second tenant.
    let fw = tenant_firewall();
    let auth = keys(vec![api_key("key-one", "one"), api_key("key-two", "two")]);
    let (state, _store) = state_with_firewalls_and_auth(Arc::clone(&fw), fw, &auth).await;
    let router = create_router(state);
    let holder = |bearer| Caller {
        bearer: Some(bearer),
        ..Caller::default()
    };
    let tenant = |name| json!({ "tenant": name });
    let (first, opened, body) = send(
        &router,
        call_with(&holder("key-one"), false, None, 0, &tenant("acme")),
    )
    .await;
    assert_eq!(
        first, Delivered,
        "the first tenant is within the limit: {body}"
    );
    let opened = opened.expect("a legacy call is given a session");
    // No session header: the gateway mints a second session for this call.
    let (second, minted, body) = send(
        &router,
        call_with(&holder("key-one"), false, None, 1, &tenant("globex")),
    )
    .await;
    // A call that got no session header at all must not pass as "not resumed".
    let minted = minted.expect("the second call is given a session of its own");
    assert_ne!(minted, opened, "the second call resumed the first session");
    assert_eq!(
        second, TenantReach,
        "a new session reset the credential's tenant bucket: {body}"
    );
    // Guard: the bucket is per credential, not global.
    let (other, _, body) = send(
        &router,
        call_with(&holder("key-two"), false, None, 3, &tenant("globex")),
    )
    .await;
    assert_eq!(
        other, Delivered,
        "another credential has its own tenant bucket: {body}"
    );
}
