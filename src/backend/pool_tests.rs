// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests for the MIK-6735 per-identity transport/session pool: slot
//! isolation, cross-tenant circuit-breaker independence, notification
//! routing, idle eviction, and the evictor-vs-start race in
//! `Backend::reconcile_after_start`.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use async_trait::async_trait;
use serde_json::{Value, json};

use super::*;
use crate::backend::registry::BackendLifecycle;
use crate::config::TransportConfig;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transport::Transport;
use crate::{Error, Result};

// ---- MIK-6735: per-user transport/session pool ----

// Method-agnostic transport that echoes the session tag it was built for,
// so a routed request proves which pool slot served it.
struct SessionMock {
    session: String,
    requests: AtomicUsize,
    notifications: AtomicUsize,
    closed: AtomicBool,
}

impl SessionMock {
    fn new(session: &str) -> Self {
        Self {
            session: session.to_string(),
            requests: AtomicUsize::new(0),
            notifications: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl Transport for SessionMock {
    async fn request(&self, _method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({ "session": self.session }),
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        self.notifications.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

fn per_user_backend() -> Arc<Backend> {
    let idp = crate::identity_propagation::IdentityPropagationConfig {
        strategy: crate::identity_propagation::PropagationStrategyKind::SignedAssertion,
        audience: "https://mem.internal".to_string(),
        required: true,
        session_mode: crate::identity_propagation::SessionMode::PerUser,
        token_exchange_endpoint: None,
        token_exchange_scope: None,
    };
    let cfg = BackendConfig {
        transport: TransportConfig::Http {
            http_url: "https://mem.internal/mcp".to_string(),
            streamable_http: false,
            protocol_version: None,
        },
        identity_propagation: Some(idp),
        ..BackendConfig::default()
    };
    Arc::new(Backend::new(
        "mem",
        cfg,
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

/// A gateway-OWNED backend (declared with a command) that opts into being
/// stopped when idle. Ownership is what makes stopping meaningful: the gateway
/// spawned this process, so it can stop it.
fn stoppable_backend(idle_for: Duration) -> Arc<Backend> {
    stoppable_backend_with_command("echo hi", idle_for)
}

/// A stoppable backend whose start command is observable from outside the
/// process. Tests that need to prove a start did NOT happen need a witness in
/// the world - a file, the process table - rather than an in-memory flag.
fn stoppable_backend_with_command(command: &str, idle_for: Duration) -> Arc<Backend> {
    let cfg = BackendConfig {
        transport: TransportConfig::Stdio {
            command: command.to_string(),
            cwd: None,
            protocol_version: None,
        },
        stop_when_idle_for: Some(idle_for),
        ..BackendConfig::default()
    };
    Arc::new(Backend::new(
        "ownedtool",
        cfg,
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

fn per_user_key(binding: &str) -> PoolKey {
    PoolKey::PerUser {
        binding: binding.to_string(),
    }
}

// POOL.4 (headline isolation guarantee): two callers on a per_user backend
// are served by distinct transport instances and distinct sessions, and a
// caller reusing its identity reuses its one slot — userA traffic never
// touches userB's session (IDP.7).
#[tokio::test]
async fn per_user_requests_route_to_isolated_transport_slots() {
    let backend = per_user_backend();

    let mock_a = Arc::new(SessionMock::new("A"));
    let mock_b = Arc::new(SessionMock::new("B"));
    backend.set_pooled_transport_for_test(
        &per_user_key("userA"),
        mock_a.clone() as Arc<dyn Transport>,
    );
    backend.set_pooled_transport_for_test(
        &per_user_key("userB"),
        mock_b.clone() as Arc<dyn Transport>,
    );

    let resp_a = backend
        .request_with_headers("tools/list", None, &[], Some("userA"))
        .await
        .unwrap();
    let resp_b = backend
        .request_with_headers("tools/list", None, &[], Some("userB"))
        .await
        .unwrap();
    assert_eq!(resp_a.result.unwrap()["session"], json!("A"));
    assert_eq!(resp_b.result.unwrap()["session"], json!("B"));

    let transport_a = backend
        .pooled_transport_for_test(&per_user_key("userA"))
        .unwrap();
    let transport_b = backend
        .pooled_transport_for_test(&per_user_key("userB"))
        .unwrap();
    assert!(
        !Arc::ptr_eq(&transport_a, &transport_b),
        "distinct users must not share a transport instance"
    );

    // Same identity reuses the one slot; userB is untouched by userA traffic.
    backend
        .request_with_headers("tools/list", None, &[], Some("userA"))
        .await
        .unwrap();
    assert_eq!(
        mock_a.requests.load(Ordering::SeqCst),
        2,
        "userA must reuse its own slot"
    );
    assert_eq!(
        mock_b.requests.load(Ordering::SeqCst),
        1,
        "userB session must not serve userA traffic"
    );
}

// MIK-6735 fix 1 (adversarial review of commit bfd62b91): the headline
// regression this fix closes. Before the fix, `request_with_headers`
// gated every caller on ONE backend-wide `Failsafe`, so tripping the
// breaker for userA's traffic also rejected userB's — one identity's
// outage took down every other tenant sharing the backend, exactly the
// blast radius the per-user pool exists to eliminate. Each slot must now
// fail independently: tripping userA's slot rejects ONLY userA, and
// userB's request on its own (untripped) slot still succeeds.
#[tokio::test]
async fn cross_tenant_circuit_breaker_trip_does_not_reject_other_identity() {
    let backend = per_user_backend();
    backend.set_pooled_transport_for_test(&per_user_key("userA"), Arc::new(SessionMock::new("A")));
    let mock_b = Arc::new(SessionMock::new("B"));
    backend.set_pooled_transport_for_test(&per_user_key("userB"), mock_b.clone());

    // Trip ONLY userA's slot.
    backend.trip_circuit_breaker_for_test_key(&per_user_key("userA"));

    let err = backend
        .request_with_headers("tools/list", None, &[], Some("userA"))
        .await
        .expect_err("userA's own tripped slot must reject its traffic");
    assert!(
        matches!(err, Error::CircuitOpen(_)),
        "expected CircuitOpen for userA, got {err:?}"
    );

    // userB's slot was never tripped and must be entirely unaffected.
    let resp_b = backend
        .request_with_headers("tools/list", None, &[], Some("userB"))
        .await
        .expect("userB's untripped slot must still serve requests");
    assert_eq!(resp_b.result.unwrap()["session"], json!("B"));
    assert_eq!(mock_b.requests.load(Ordering::SeqCst), 1);

    // The canonical Shared slot (and thus backend-wide status/metrics
    // accessors) must also be unaffected by a per-user slot tripping.
    assert!(
        !backend.is_circuit_tripped(),
        "Shared slot must stay closed when only a PerUser slot tripped"
    );
}

// MIK-6735 fix 2: before this fix, `Backend::notify` unconditionally used
// `ensure_started()` (the canonical Shared slot) regardless of the
// caller's identity, so a notification correlating a per-user request
// went out on the WRONG transport instance (and, once routed correctly,
// still the wrong upstream session — fixed at the `Transport` layer by
// `notify_with_headers`). Assert `notify_with_headers` routes to the SAME
// slot `request_with_headers` uses for that identity: userA's
// notification reaches only userA's transport, never userB's.
#[tokio::test]
async fn notify_with_headers_routes_to_the_callers_own_pool_slot() {
    let backend = per_user_backend();
    let mock_a = Arc::new(SessionMock::new("A"));
    let mock_b = Arc::new(SessionMock::new("B"));
    backend.set_pooled_transport_for_test(&per_user_key("userA"), mock_a.clone());
    backend.set_pooled_transport_for_test(&per_user_key("userB"), mock_b.clone());

    backend
        .notify_with_headers("notifications/cancelled", None, Some("userA"))
        .await
        .expect("userA's notification must succeed");

    assert_eq!(
        mock_a.notifications.load(Ordering::SeqCst),
        1,
        "userA's notification must reach userA's own transport slot"
    );
    assert_eq!(
        mock_b.notifications.load(Ordering::SeqCst),
        0,
        "userA's notification must never reach userB's transport slot"
    );

    // Plain `notify` (no identity) is a pass-through to the Shared slot,
    // never a per-user slot — single-tenant behavior unchanged (IDP.5).
    backend.set_pooled_transport_for_test(&PoolKey::Shared, Arc::new(SessionMock::new("S")));
    backend
        .notify("notifications/cancelled", None)
        .await
        .expect("shared-slot notification must succeed");
    assert_eq!(
        mock_a.notifications.load(Ordering::SeqCst),
        1,
        "an identity-less notify must not touch a per-user slot"
    );
}

// POOL.1 / IDP.5: without a resolved per-user identity — or on a backend
// that is not per_user at all — every request collapses to the shared
// canonical slot, preserving single-tenant behavior byte-for-byte.
#[test]
fn pool_key_collapses_to_shared_without_per_user_identity() {
    let backend = per_user_backend();
    assert_eq!(backend.pool_key_for(None), PoolKey::Shared);
    assert_eq!(backend.pool_key_for(Some("userA")), per_user_key("userA"));

    let plain = Backend::new(
        "plain",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    );
    assert_eq!(
        plain.pool_key_for(Some("userA")),
        PoolKey::Shared,
        "a non-idp backend never mints a per-user slot"
    );
}

// POOL.2: idle per-user slots are evicted and their transports closed, the
// shared canonical slot is NEVER evicted, and a later request lazily
// re-creates a fresh slot.
#[tokio::test]
async fn evict_idle_per_user_entries_reaps_idle_users_but_spares_shared() {
    let backend = per_user_backend();
    backend.set_pooled_transport_for_test(&per_user_key("userA"), Arc::new(SessionMock::new("A")));

    // Age BOTH the user slot and the shared slot into the deep past.
    for key in [per_user_key("userA"), PoolKey::Shared] {
        backend
            .pool
            .get(&key)
            .unwrap()
            .value()
            .last_used
            .store(0, Ordering::Relaxed);
    }

    let closed = backend
        .evict_idle_per_user_entries(Duration::from_secs(1))
        .await;
    assert_eq!(closed, 1, "only the per-user slot is reaped");
    assert!(
        backend
            .pooled_transport_for_test(&per_user_key("userA"))
            .is_none(),
        "evicted per-user slot is gone"
    );
    assert!(
        backend.pool.contains_key(&PoolKey::Shared),
        "shared canonical slot must survive eviction even when idle"
    );

    // A fresh request re-creates the slot lazily with a new transport.
    backend.set_pooled_transport_for_test(&per_user_key("userA"), Arc::new(SessionMock::new("A2")));
    let resp = backend
        .request_with_headers("tools/list", None, &[], Some("userA"))
        .await
        .unwrap();
    assert_eq!(resp.result.unwrap()["session"], json!("A2"));
}

// POOL.3 companion: a per_user request and a no-identity request on the same
// backend land in different slots, so canonical/init traffic (shared) is
// never commingled with a user's session.
#[tokio::test]
async fn shared_and_per_user_slots_are_separate_on_one_backend() {
    let backend = per_user_backend();
    backend.set_pooled_transport_for_test(&PoolKey::Shared, Arc::new(SessionMock::new("shared")));
    backend.set_pooled_transport_for_test(&per_user_key("userA"), Arc::new(SessionMock::new("A")));

    let shared = backend
        .request_with_headers("tools/list", None, &[], None)
        .await
        .unwrap();
    let user = backend
        .request_with_headers("tools/list", None, &[], Some("userA"))
        .await
        .unwrap();
    assert_eq!(shared.result.unwrap()["session"], json!("shared"));
    assert_eq!(user.result.unwrap()["session"], json!("A"));
}

// POOL race fix (adversarial review): `evict_idle_per_user_entries` can
// `remove_if` a per-user slot out of `pool` WHILE `ensure_entry_started`
// is mid-build for that exact slot — the entry is cloned out of the pool
// via `pooled_entry` before it is touched, so the evictor's idleness
// re-check still sees it as stale and wins. `PooledEntry` has no async
// `Drop`, so a transport stored into an orphaned entry would otherwise
// leak the connection until OS teardown. This drives `reconcile_after_start`
// (the exact method `ensure_entry_started` calls after `start_entry`)
// directly, simulating the evictor having already won, and asserts the
// orphaned transport is closed rather than leaked.
#[tokio::test]
async fn reconcile_after_start_closes_orphaned_transport_when_evictor_wins_race() {
    let backend = per_user_backend();
    let key = per_user_key("userA");

    // Simulate ensure_entry_started's in-flight state: an entry was
    // cloned out of the pool (as pooled_entry would) and start_entry
    // just finished building its transport into it.
    let entry = backend.pooled_entry(&key);
    let transport = Arc::new(SessionMock::new("A"));
    *entry.transport.write() = Some(Arc::clone(&transport) as Arc<dyn Transport>);

    // The evictor wins the race: it removes this exact entry from the
    // pool before the build above is reconciled.
    let removed = backend.pool.remove(&key);
    assert!(
        removed.is_some_and(|(_, removed_entry)| Arc::ptr_eq(&removed_entry, &entry)),
        "the entry removed by the simulated evictor must be the SAME entry \
         the in-flight start was building into"
    );

    let outcome = backend
        .reconcile_after_start(&key, &entry, Arc::clone(&transport) as Arc<dyn Transport>)
        .await;

    assert!(
        outcome.is_none(),
        "a lost race must be reported so ensure_entry_started retries \
         against a fresh entry instead of handing back a doomed transport"
    );
    assert!(
        transport.closed.load(Ordering::SeqCst),
        "the orphaned transport must be closed by the side that lost the \
         race, not silently dropped/leaked"
    );
    assert!(
        entry.transport.read().is_none(),
        "the orphaned entry's transport slot must be cleared after close"
    );
}

// Companion happy-path: when nobody evicted the entry mid-build,
// reconcile_after_start must hand the transport back untouched and never
// close a live, still-registered connection.
#[tokio::test]
async fn reconcile_after_start_keeps_transport_when_still_registered() {
    let backend = per_user_backend();
    let key = per_user_key("userA");

    let entry = backend.pooled_entry(&key);
    let transport = Arc::new(SessionMock::new("A"));
    *entry.transport.write() = Some(Arc::clone(&transport) as Arc<dyn Transport>);

    // No eviction happened: `entry` is still the pool's registered slot.
    let outcome = backend
        .reconcile_after_start(&key, &entry, Arc::clone(&transport) as Arc<dyn Transport>)
        .await;

    assert!(
        outcome.is_some(),
        "a still-registered entry must hand its transport back, not report a lost race"
    );
    assert!(
        !transport.closed.load(Ordering::SeqCst),
        "the winning side's live transport must never be closed"
    );
}

// ── GW.IDLE.9 — the co-simulation test ───────────────────────────────────────
//
// Written BEFORE the implementation, deliberately. This feature has shipped
// twice as a silent no-op with a green suite, both times because the test
// exercised the reaper ALONE while the failure lived in its interaction with the
// health loop. This asserts the interaction that actually deploys.
//
// The health loop's gate is `is_running() || is_circuit_tripped()`. A backend
// stopped on purpose has no transport and a closed breaker, so it must be
// skipped. If it is not, the reaper stops the child and health restarts it, and
// "hibernation" becomes a spawn/kill cycle every health interval — strictly
// worse than never stopping at all.
#[tokio::test]
async fn idle_backend_stops_once_and_stays_stopped_under_health_traffic() {
    let backend = stoppable_backend(Duration::from_secs(1));
    let transport = Arc::new(SessionMock::new("shared"));
    backend.set_transport_for_test(transport.clone());

    assert!(backend.is_running(), "precondition: backend is up");
    assert!(
        !backend.is_circuit_tripped(),
        "precondition: breaker closed"
    );

    // Age the slot past any plausible deadline.
    backend
        .pool
        .get(&PoolKey::Shared)
        .unwrap()
        .value()
        .last_used
        .store(0, Ordering::Relaxed);

    // One reaper sweep.
    let stopped = backend.stop_if_idle().await;
    assert!(
        stopped,
        "GW.IDLE.1: an idle backend past its deadline must be stopped"
    );
    assert!(
        transport.closed.load(Ordering::SeqCst),
        "GW.IDLE.1: stopping must actually close the transport - that is what kills the child"
    );

    // Now simulate several health-loop intervals against the stopped backend.
    for interval in 0..5 {
        let would_probe = backend.is_running() || backend.is_circuit_tripped();
        assert!(
            !would_probe,
            "GW.IDLE.9: health interval {interval}: the health loop would probe a \
             deliberately-stopped backend, and probing starts it. Hibernation would \
             degrade into a spawn/kill cycle every health interval."
        );
    }

    // And it is still stopped: nothing materialised behind our back.
    assert!(
        backend
            .pooled_transport_for_test(&PoolKey::Shared)
            .is_none(),
        "GW.IDLE.9: backend must remain stopped until a real client request arrives"
    );
    assert!(
        !backend.is_running(),
        "GW.IDLE.9: a stopped backend must not report as running"
    );
}

// GW.IDLE.9 (companion): the clock must track CLIENT traffic only.
//
// `ensure_entry_started` used to touch the idle clock unconditionally, and
// `health_probe` -> `ensure_started` routes straight through it. On the 10s
// default health interval against a 300s deadline, the clock was refreshed
// forever and the feature could never fire. This is the regression test for that
// exact no-op.
#[tokio::test]
async fn internal_starts_do_not_defer_stopping() {
    let backend = stoppable_backend(Duration::from_secs(1));
    backend.set_transport_for_test(Arc::new(SessionMock::new("warm")));

    // Stale: no client has touched it.
    backend
        .pool
        .get(&PoolKey::Shared)
        .unwrap()
        .value()
        .last_used
        .store(0, Ordering::Relaxed);

    // Exactly what the health loop does, every 10s by default.
    backend
        .ensure_started()
        .await
        .expect("a connected transport short-circuits the start path");

    assert_eq!(
        backend
            .pool
            .get(&PoolKey::Shared)
            .unwrap()
            .value()
            .last_used
            .load(Ordering::Relaxed),
        0,
        "internal health/metadata traffic must NOT refresh the client idle clock"
    );
    assert!(
        backend.stop_if_idle().await,
        "a backend seeing only internal traffic must still be stoppable"
    );
}

// The converse: real client traffic DOES defer stopping.
#[tokio::test]
async fn client_traffic_defers_stopping() {
    let backend = stoppable_backend(Duration::from_secs(3600));
    backend.set_transport_for_test(Arc::new(SessionMock::new("live")));
    backend
        .pool
        .get(&PoolKey::Shared)
        .unwrap()
        .value()
        .last_used
        .store(0, Ordering::Relaxed);

    drop(backend.begin_activity(&PoolKey::Shared));

    assert!(
        !backend.stop_if_idle().await,
        "a slot a client just used must not be stopped"
    );
}

// GW.IDLE.5 — a request in flight past the deadline must never be torn down.
// `last_used` records when a request STARTED, so the clock alone cannot express
// "work is happening right now".
#[tokio::test]
async fn in_flight_request_is_never_stopped() {
    let backend = stoppable_backend(Duration::from_secs(1));
    let transport = Arc::new(SessionMock::new("busy"));
    backend.set_transport_for_test(transport.clone());

    // A request is running...
    let activity = backend.begin_activity(&PoolKey::Shared);
    // ...but it began long ago (a slow upstream call).
    backend
        .pool
        .get(&PoolKey::Shared)
        .unwrap()
        .value()
        .last_used
        .store(0, Ordering::Relaxed);

    assert!(
        !backend.stop_if_idle().await,
        "in-flight work must block stopping regardless of the clock"
    );
    assert!(
        !transport.closed.load(Ordering::SeqCst),
        "a live request's transport must never be closed underneath it"
    );

    // Once it finishes, the backend becomes eligible again.
    drop(activity);
    backend
        .pool
        .get(&PoolKey::Shared)
        .unwrap()
        .value()
        .last_used
        .store(0, Ordering::Relaxed);
    assert!(
        backend.stop_if_idle().await,
        "stopping resumes once the request completes"
    );
}

// A backend that did not opt in is never stopped, however idle.
#[tokio::test]
async fn backend_without_the_setting_is_never_stopped() {
    let backend = per_user_backend(); // no stop_when_idle_for
    let transport = Arc::new(SessionMock::new("optout"));
    backend.set_transport_for_test(transport.clone());
    backend
        .pool
        .get(&PoolKey::Shared)
        .unwrap()
        .value()
        .last_used
        .store(0, Ordering::Relaxed);

    assert!(
        !backend.stop_if_idle().await,
        "absent setting must mean never stop - upgrading must not change behaviour"
    );
    assert!(!transport.closed.load(Ordering::SeqCst));
}

// Stopping an already-stopped backend is a no-op, not a double close.
#[tokio::test]
async fn stopping_is_idempotent() {
    let backend = stoppable_backend(Duration::from_secs(1));
    backend.set_transport_for_test(Arc::new(SessionMock::new("once")));
    backend
        .pool
        .get(&PoolKey::Shared)
        .unwrap()
        .value()
        .last_used
        .store(0, Ordering::Relaxed);

    assert!(backend.stop_if_idle().await, "first call stops it");
    assert!(
        !backend.stop_if_idle().await,
        "second call is a no-op, not a double close"
    );
}

// Sub-second deadlines must not truncate to a zero cutoff and expire everything.
#[tokio::test]
async fn subsecond_deadline_does_not_stop_a_fresh_backend() {
    let backend = stoppable_backend(Duration::from_millis(1));
    let transport = Arc::new(SessionMock::new("fresh"));
    backend.set_transport_for_test(transport.clone());
    drop(backend.begin_activity(&PoolKey::Shared));

    assert!(
        !backend.stop_if_idle().await,
        "a sub-second deadline must clamp to >=1s, not expire everything instantly"
    );
    assert!(!transport.closed.load(Ordering::SeqCst));
}

// ── GW.IDLE.4 — dormant is not unhealthy ────────────────────────────────────
//
// Reporting a deliberately-stopped backend as unhealthy would trip its circuit
// breaker and show it broken while it behaves exactly as configured. Reporting
// it as healthy would hide that its process is gone.
#[tokio::test]
async fn a_stopped_backend_reports_dormant_not_unhealthy() {
    let backend = stoppable_backend(Duration::from_secs(1));
    backend.set_transport_for_test(Arc::new(SessionMock::new("shared")));
    assert_eq!(backend.lifecycle(), BackendLifecycle::Running);

    backend
        .pool
        .get(&PoolKey::Shared)
        .unwrap()
        .value()
        .last_used
        .store(0, Ordering::Relaxed);
    assert!(backend.stop_if_idle().await);

    assert_eq!(
        backend.lifecycle(),
        BackendLifecycle::Dormant,
        "a backend stopped on purpose is neither running nor broken"
    );
    assert!(
        !backend.is_circuit_tripped(),
        "stopping must not trip the breaker - it records no failure"
    );
    assert_eq!(
        backend.status().lifecycle,
        BackendLifecycle::Dormant,
        "status output must carry the distinction, not just the internal method"
    );
}

// A real failure is never disguised as a nap.
#[tokio::test]
async fn a_failed_backend_reports_unhealthy_even_if_it_opted_into_stopping() {
    let backend = stoppable_backend(Duration::from_secs(1));
    backend.set_transport_for_test(Arc::new(SessionMock::new("shared")));
    backend
        .pool
        .get(&PoolKey::Shared)
        .unwrap()
        .value()
        .last_used
        .store(0, Ordering::Relaxed);
    assert!(backend.stop_if_idle().await);
    assert_eq!(backend.lifecycle(), BackendLifecycle::Dormant);

    backend.trip_circuit_breaker_for_test();

    assert_eq!(
        backend.lifecycle(),
        BackendLifecycle::Unhealthy,
        "an open breaker must win over dormant - a fault must never look like a nap"
    );
}

// A backend that never opted in and was never started is not "dormant".
#[tokio::test]
async fn a_never_started_backend_is_not_dormant() {
    let backend = per_user_backend(); // no stop_when_idle_for, no transport
    assert_eq!(
        backend.lifecycle(),
        BackendLifecycle::NotStarted,
        "lazy-start is the normal state for an unused backend, not a stopped one"
    );
}

// The health loop must skip a dormant backend: probing it would start it, and
// hibernation would degrade into a spawn/kill cycle every health interval.
#[tokio::test]
async fn the_health_loop_skips_a_dormant_backend_but_still_probes_a_failed_one() {
    let backend = stoppable_backend(Duration::from_secs(1));
    backend.set_transport_for_test(Arc::new(SessionMock::new("shared")));
    backend
        .pool
        .get(&PoolKey::Shared)
        .unwrap()
        .value()
        .last_used
        .store(0, Ordering::Relaxed);
    assert!(backend.stop_if_idle().await);

    // This is the serve path's gate, verbatim.
    assert!(
        !(backend.is_running() || backend.is_circuit_tripped()),
        "GW.IDLE.4: the health loop must not probe a dormant backend"
    );

    // But a dormant backend that then FAILS must still be probed for recovery.
    backend.trip_circuit_breaker_for_test();
    assert!(
        backend.is_running() || backend.is_circuit_tripped(),
        "recovery probing must not be blocked by having been stopped"
    );
}

// ── Review finding 1 (CRITICAL) — the health probe must hold the transport ──
//
// The gate check and the probe are not atomic. Between "is_running() == true"
// and the probe's ping, the reaper can take the transport; the probe then reads
// that as a fault and calls force_restart(), so an idle backend is stopped and
// instantly restarted. With a 10s health interval against a 60s sweep the ticks
// coincide regularly.
//
// The earlier co-simulation test did NOT cover this: it stopped the backend and
// only then evaluated the gate, so the overlap never happened.
#[tokio::test]
async fn a_probe_in_progress_blocks_the_reaper() {
    use tokio::sync::oneshot;

    // A transport whose request() parks, so a real health_probe is genuinely
    // in-flight while the reaper sweeps. Driving `health_probe` itself is the
    // point: an earlier version of this test called `begin_internal_activity`
    // directly and therefore passed even with the lease removed from the probe.
    struct ParkingMock {
        started: std::sync::Mutex<Option<oneshot::Sender<()>>>,
        release: std::sync::Mutex<Option<oneshot::Receiver<()>>>,
        closed: AtomicBool,
    }

    #[async_trait]
    impl Transport for ParkingMock {
        async fn request(&self, _m: &str, _p: Option<Value>) -> Result<JsonRpcResponse> {
            if let Some(tx) = self.started.lock().unwrap().take() {
                let _ = tx.send(());
            }
            let rx = self.release.lock().unwrap().take();
            if let Some(rx) = rx {
                let _ = rx.await;
            }
            Ok(JsonRpcResponse::success_serialized(
                RequestId::Number(1),
                json!({}),
            ))
        }
        async fn notify(&self, _m: &str, _p: Option<Value>) -> Result<()> {
            Ok(())
        }
        fn is_connected(&self) -> bool {
            true
        }
        async fn close(&self) -> Result<()> {
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let transport = Arc::new(ParkingMock {
        started: std::sync::Mutex::new(Some(started_tx)),
        release: std::sync::Mutex::new(Some(release_rx)),
        closed: AtomicBool::new(false),
    });

    let backend = stoppable_backend(Duration::from_secs(1));
    backend.set_transport_for_test(transport.clone());
    backend
        .pool
        .get(&PoolKey::Shared)
        .unwrap()
        .value()
        .last_used
        .store(0, Ordering::Relaxed);

    // Start a REAL health probe and wait until it is genuinely mid-flight.
    let probing = Arc::clone(&backend);
    let probe = tokio::spawn(async move { probing.health_probe(Duration::from_secs(5)).await });
    started_rx.await.expect("probe should reach the transport");

    // The reaper sweeps while that probe is running.
    assert!(
        !backend.stop_if_idle().await,
        "the reaper must not stop a backend while a health probe is in flight - \
         closing the transport makes the probe read a fault and force_restart()"
    );
    assert!(
        !transport.closed.load(Ordering::SeqCst),
        "transport was closed underneath a live probe"
    );

    let _ = release_tx.send(());
    let _ = probe.await;
}

// An internal lease must NOT defer the idle deadline, or health traffic keeps
// the backend warm forever - the original no-op by another route.
#[tokio::test]
async fn an_internal_lease_does_not_refresh_the_idle_clock() {
    let backend = stoppable_backend(Duration::from_secs(1));
    backend.set_transport_for_test(Arc::new(SessionMock::new("probing")));
    backend
        .pool
        .get(&PoolKey::Shared)
        .unwrap()
        .value()
        .last_used
        .store(0, Ordering::Relaxed);

    drop(backend.begin_internal_activity());

    assert_eq!(
        backend
            .pool
            .get(&PoolKey::Shared)
            .unwrap()
            .value()
            .last_used
            .load(Ordering::Relaxed),
        0,
        "internal work must protect the transport WITHOUT claiming client activity"
    );
    assert!(
        backend.stop_if_idle().await,
        "a backend seeing only internal traffic must still be stoppable"
    );
}

// ── Review finding 3 (HIGH) — per-user eviction ignored in_flight ───────────
//
// The comment claiming the timestamp recheck means active requests are "never
// torn down" was false here: a request can hold the entry and have incremented
// in_flight while the clock still reads stale, notably while it waits on the
// backend semaphore.
#[tokio::test]
async fn per_user_eviction_spares_a_slot_with_work_in_flight() {
    let backend = per_user_backend();
    let key = per_user_key("userA");
    let transport = Arc::new(SessionMock::new("A"));
    backend.set_pooled_transport_for_test(&key, transport.clone());

    backend
        .pool
        .get(&key)
        .unwrap()
        .value()
        .last_used
        .store(0, Ordering::Relaxed);

    // A request is running against this per-user slot.
    let activity = backend.begin_activity(&key);
    backend
        .pool
        .get(&key)
        .unwrap()
        .value()
        .last_used
        .store(0, Ordering::Relaxed);

    let closed = backend
        .evict_idle_per_user_entries(Duration::from_secs(1))
        .await;
    assert_eq!(
        closed, 0,
        "a per-user slot with work in flight must not be evicted"
    );
    assert!(
        !transport.closed.load(Ordering::SeqCst),
        "eviction closed the transport underneath a live request"
    );

    drop(activity);
    backend
        .pool
        .get(&key)
        .unwrap()
        .value()
        .last_used
        .store(0, Ordering::Relaxed);
    assert_eq!(
        backend
            .evict_idle_per_user_entries(Duration::from_secs(1))
            .await,
        1,
        "eviction resumes once the request completes"
    );
}

// ── Review finding 4 (MEDIUM) — dormant must be recorded, not inferred ─────
//
// Inferring from "opted in + no transport + breaker closed" misreports a backend
// whose FIRST start failed: nothing has updated the failsafe yet, so it still
// looks healthy, and "never came up" is indistinguishable from "resting".
#[tokio::test]
async fn a_backend_that_never_started_is_not_reported_dormant() {
    let backend = stoppable_backend(Duration::from_secs(1));
    // Opted in, no transport, breaker closed - but the reaper never stopped it.
    assert_eq!(
        backend.lifecycle(),
        BackendLifecycle::NotStarted,
        "a backend that never came up must not be reported as sleeping"
    );
}

#[tokio::test]
async fn dormant_is_cleared_once_the_backend_is_running_again() {
    let backend = stoppable_backend(Duration::from_secs(1));
    backend.set_transport_for_test(Arc::new(SessionMock::new("first")));
    backend
        .pool
        .get(&PoolKey::Shared)
        .unwrap()
        .value()
        .last_used
        .store(0, Ordering::Relaxed);
    assert!(backend.stop_if_idle().await);
    assert_eq!(backend.lifecycle(), BackendLifecycle::Dormant);

    // Stand in for a restart: a live transport means it is up again.
    backend.set_transport_for_test(Arc::new(SessionMock::new("second")));
    assert_eq!(
        backend.lifecycle(),
        BackendLifecycle::Running,
        "a restarted backend must not still report dormant"
    );
}

// force_restart() calls start_entry() directly, bypassing ensure_entry_started.
// Clearing the dormant flag only in the latter left a restarted backend flagged
// as stopped-for-idleness while it was actually running.
#[tokio::test]
async fn a_restarted_backend_is_not_flagged_dormant() {
    let backend = stoppable_backend(Duration::from_secs(1));
    backend.set_transport_for_test(Arc::new(SessionMock::new("first")));
    backend
        .pool
        .get(&PoolKey::Shared)
        .unwrap()
        .value()
        .last_used
        .store(0, Ordering::Relaxed);
    assert!(backend.stop_if_idle().await);
    assert!(
        backend
            .shared_entry()
            .stopped_when_idle
            .load(Ordering::SeqCst),
        "precondition: the reaper recorded that it stopped this slot"
    );

    // ensure_entry_started drives start_entry, which is where the flag clears.
    // A connected transport short-circuits before start_entry, so drop it first
    // to force a real start attempt.
    let _ = backend.ensure_started().await;

    assert!(
        !backend
            .shared_entry()
            .stopped_when_idle
            .load(Ordering::SeqCst),
        "starting a backend by ANY route must clear the stopped-for-idleness flag, \
         or a restarted backend keeps reporting dormant"
    );
}

// GW.IDLE.RACE.1 - the reaper's check-and-take must EXCLUDE lease acquisition.
//
// Positioned inside the window rather than after it. The test holds the
// transport WRITE guard, which is precisely what `stop_if_idle` holds between
// reading `in_flight` and taking the transport. If claiming a lease does not
// take the READ guard, it slips into that window: the reaper passes its
// zero-check, then closes a transport a live request is about to use. `SeqCst`
// cannot prevent that - it does not make an earlier read conditional on a later
// increment - so the lock is the only thing that can, and this asserts the lock.
#[test]
fn claiming_a_lease_is_excluded_while_the_reaper_holds_the_transport() {
    let backend = stoppable_backend(Duration::from_secs(1));
    backend.set_transport_for_test(Arc::new(SessionMock::new("live")));
    let entry = backend.shared_entry();

    let claimed = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));

    // Stand in for the reaper, holding the guard across the whole window.
    let reaper_guard = entry.transport.write();

    let claimer = {
        let backend = Arc::clone(&backend);
        let claimed = Arc::clone(&claimed);
        let release = Arc::clone(&release);
        std::thread::spawn(move || {
            let _lease = backend.begin_activity(&PoolKey::Shared);
            claimed.store(true, Ordering::SeqCst);
            // Keep the lease alive so the assertions below see a real count.
            while !release.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
        })
    };

    // Bounded wait: an unexcluded claim would have landed many times over.
    std::thread::sleep(Duration::from_millis(150));
    assert!(
        !claimed.load(Ordering::SeqCst),
        "a lease was claimed while the reaper held the transport write guard; \
         the claim does not take the read guard, so check-and-take is not atomic"
    );
    assert_eq!(
        entry.in_flight.load(Ordering::SeqCst),
        0,
        "in_flight moved inside the reaper's window"
    );

    drop(reaper_guard);

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !claimed.load(Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "the claim never completed after the reaper released the transport"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        entry.in_flight.load(Ordering::SeqCst),
        1,
        "the claim completed but did not register in_flight"
    );

    release.store(true, Ordering::SeqCst);
    claimer.join().expect("claimer thread panicked");
}

/// A transport whose `close()` parks until released, letting a test position
/// itself INSIDE the reaper's post-take window: transport already removed from
/// the slot, stop not yet finished.
struct BlockingCloseMock {
    entered_close: Arc<AtomicBool>,
    release: Arc<AtomicBool>,
}

#[async_trait]
impl Transport for BlockingCloseMock {
    async fn request(&self, _method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({}),
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> Result<()> {
        self.entered_close.store(true, Ordering::SeqCst);
        while !self.release.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Ok(())
    }
}

/// How many times this backend's command has been spawned, read from the file
/// the command itself appends to. An external witness: it reflects the process
/// table, not a field the code under test maintains.
fn spawn_count(log: &std::path::Path) -> usize {
    std::fs::read_to_string(log).map_or(0, |s| s.lines().count())
}

// GW.IDLE.RACE.2 - the health probe must not restart a backend the reaper is
// in the middle of stopping.
//
// The window is between the reaper taking the transport and its stop being
// complete. A probe entering there sees a slot with no transport; if it cannot
// tell "deliberately stopped" from "not started yet" it calls ensure_started()
// and respawns the process the sweep just released - a periodic silent no-op,
// which is the exact failure this feature exists to prevent. Recording
// `stopped_when_idle` under the same write guard that takes the transport is
// what closes it; recording it after `close()` completes leaves it open.
//
// The test parks the reaper inside `close()` so it is genuinely in the window,
// rather than asserting after the stop has finished - the mistake that let six
// earlier tests pass against broken code.
#[tokio::test(flavor = "multi_thread")]
async fn the_health_probe_does_not_restart_a_backend_mid_stop() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let log = dir.path().join("spawns");
    let backend = stoppable_backend_with_command(
        &format!("sh -c 'echo spawn >> {}; sleep 1'", log.display()),
        Duration::from_secs(1),
    );

    let entered_close = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    backend.set_transport_for_test(Arc::new(BlockingCloseMock {
        entered_close: Arc::clone(&entered_close),
        release: Arc::clone(&release),
    }));
    backend.shared_entry().last_used.store(0, Ordering::Relaxed);

    let stopper = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.stop_if_idle().await })
    };

    // Park until the reaper is demonstrably inside the window.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !entered_close.load(Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "the reaper never reached close(); the test never entered the window"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(
        backend.shared_entry().transport.read().is_none(),
        "precondition: the reaper has taken the transport"
    );

    let spawns_before = spawn_count(&log);
    let _ = backend.health_probe(Duration::from_millis(200)).await;

    assert_eq!(
        spawn_count(&log),
        spawns_before,
        "the health probe spawned a child while the reaper was stopping this \
         backend; stopping and restarting on every sweep is the silent no-op \
         this feature exists to prevent"
    );
    assert!(
        backend.shared_entry().transport.read().is_none(),
        "the health probe installed a transport for a backend being stopped"
    );

    release.store(true, Ordering::SeqCst);
    assert!(
        stopper.await.expect("stopper task panicked"),
        "stop_if_idle should report that it closed a live transport"
    );
}
