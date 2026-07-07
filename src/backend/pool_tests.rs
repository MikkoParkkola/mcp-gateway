//! Unit tests for the MIK-6735 per-identity transport/session pool: slot
//! isolation, cross-tenant circuit-breaker independence, notification
//! routing, idle eviction, and the evictor-vs-start race in
//! `Backend::reconcile_after_start`.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use async_trait::async_trait;
use serde_json::{Value, json};

use super::*;
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
