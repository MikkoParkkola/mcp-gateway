// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T1 and T2 of the `MIK-7215.CONTROL.4` test plan
//! (`docs/design/2026-09-08-control4-session-lifecycle-test-plan.md:52`).
//!
//! The write site. T4 proves a sweep reclaims what the registry holds; these
//! two prove the route ever puts anything there, and that it puts nothing
//! there for a caller the firewall refuses to score.
#![cfg(feature = "firewall")]

mod common;

use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use common::{Fixture, api_key, auth_with, modern, post, state};
use mcp_gateway::gateway::session_lifecycle::{IDLE_TTL, SessionLifecycle, now_unix};
use mcp_gateway::security::firewall::{Firewall, FirewallConfig};
use serde_json::json;

/// A registry that records every key a sweep reclaims, so a case can assert
/// WHICH identity was tracked and not merely that something was.
fn recording_lifecycle() -> (Arc<SessionLifecycle>, Arc<Mutex<Vec<String>>>) {
    let lifecycle = Arc::new(SessionLifecycle::new());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    lifecycle.register("recorder", move |key| {
        sink.lock().expect("recorder").push(key.to_string());
    });
    (lifecycle, seen)
}

/// A `tools/call` the firewall scans: `gateway_invoke` carries its own target
/// in its arguments, which is how it reaches the gate against the empty
/// `BackendRegistry` every router fixture builds.
fn scanned_call() -> serde_json::Value {
    modern(
        "tools/call",
        json!({
            "name": "gateway_invoke",
            "arguments": { "server": "backend", "tool": "echo", "arguments": { "cmd": "ls" } }
        }),
    )
}

/// T1 — a call from an identity the firewall scores leaves that identity in
/// the registry, with a deadline one `IDLE_TTL` out.
#[tokio::test]
async fn a_scored_call_tracks_its_identity_with_an_idle_ttl_deadline() {
    let (lifecycle, reclaimed) = recording_lifecycle();
    let app = state(Fixture {
        auth: auth_with(vec![api_key("k", 0, None)], None),
        firewall: Some(Arc::new(Firewall::from_config(
            FirewallConfig::default(),
            None,
        ))),
        session_lifecycle: Some(Arc::clone(&lifecycle)),
        ..Default::default()
    });

    let before = now_unix();
    let (status, body) = post(&app, scanned_call(), &[("authorization", "Bearer k")]).await;
    assert_ne!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(lifecycle.tracked_count(), 1, "the route tracked nothing");

    // The deadline is one IDLE_TTL out, not zero and not some other constant:
    // a sweep a second short of it reclaims nothing, and the next one does.
    // `reap` is strict (`now > expires_at`, `session_lifecycle.rs:157`), so the
    // sweep that must reclaim is the one a second PAST the deadline.
    assert_eq!(
        lifecycle.reap(before + IDLE_TTL.as_secs() - 1),
        0,
        "reclaimed before its deadline: the write site used a shorter TTL"
    );
    assert_eq!(
        lifecycle.reap(now_unix() + IDLE_TTL.as_secs() + 1),
        1,
        "not reclaimed past its deadline: the write site used a longer TTL"
    );

    // Keyed on the validated credential, never on the operator-configured
    // display name two API keys may share (`session_owner_key`).
    let keys = reclaimed.lock().expect("recorder").clone();
    assert_eq!(keys.len(), 1, "keys: {keys:?}");
    assert!(
        keys[0].starts_with("credential:"),
        "tracked under a key that is not the scored identity: {keys:?}"
    );
}

/// T2 — the negative. An unauthenticated caller has no identity the firewall
/// will score, so it has no per-identity state, so nothing is tracked for it.
/// Without this row a write site that tracked unconditionally would pass T1.
#[tokio::test]
async fn an_unscored_call_tracks_nothing() {
    let (lifecycle, _reclaimed) = recording_lifecycle();
    let app = state(Fixture {
        firewall: Some(Arc::new(Firewall::from_config(
            FirewallConfig::default(),
            None,
        ))),
        session_lifecycle: Some(Arc::clone(&lifecycle)),
        ..Default::default()
    });

    let (status, body) = post(&app, scanned_call(), &[]).await;
    assert_ne!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert_eq!(
        lifecycle.tracked_count(),
        0,
        "an empty identity was tracked: the sweep would then reclaim a key \
         the firewall holds no state under, and every anonymous caller shares it"
    );
}
