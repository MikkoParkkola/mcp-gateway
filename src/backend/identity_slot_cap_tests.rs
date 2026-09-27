// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7547.SLOTS.1: a propagating backend serves at most
//! `identity_propagation.max_identity_slots` identities at once. A new identity
//! past the cap is refused before any I/O, never moved onto the shared slot,
//! and its refusal records nothing on any breaker.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};

use super::*;
use crate::config::TransportConfig;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transport::Transport;
use crate::{Error, Result};

/// Counts what reached it, so "zero upstream requests" is observable.
#[derive(Default)]
struct Recorder {
    requests: AtomicUsize,
    notifications: AtomicUsize,
}

#[async_trait]
impl Transport for Recorder {
    async fn request(&self, _method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({}),
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
        Ok(())
    }
}

fn capped_backend(cap: usize) -> Arc<Backend> {
    capped_backend_named("mem", cap)
}

fn capped_backend_named(name: &str, cap: usize) -> Arc<Backend> {
    let idp = crate::identity_propagation::IdentityPropagationConfig {
        strategy: crate::identity_propagation::PropagationStrategyKind::SignedAssertion,
        audience: "https://mem.internal".to_string(),
        required: true,
        session_mode: crate::identity_propagation::SessionMode::PerUser,
        token_exchange_endpoint: None,
        token_exchange_scope: None,
        max_identity_slots: cap,
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
        name,
        cfg,
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

fn user(binding: &str) -> PoolKey {
    PoolKey::PerUser {
        binding: binding.to_string(),
    }
}

/// Seed `binding` with a recording transport, spending one identity slot.
fn seed(backend: &Backend, binding: &str) -> Arc<Recorder> {
    let recorder = Arc::new(Recorder::default());
    backend.set_pooled_transport_for_test(&user(binding), recorder.clone() as Arc<dyn Transport>);
    recorder
}

/// A backend at cap 2 serving `a` and `b`, with a recorder on the shared slot.
fn at_cap() -> (Arc<Backend>, Arc<Recorder>, Arc<Recorder>, Arc<Recorder>) {
    let backend = capped_backend(2);
    let shared = Arc::new(Recorder::default());
    backend.set_transport_for_test(shared.clone() as Arc<dyn Transport>);
    let a = seed(&backend, "a");
    let b = seed(&backend, "b");
    assert_eq!(
        backend.identity_slots_in_use_for_test(),
        2,
        "premise: at the cap"
    );
    (backend, shared, a, b)
}

fn breaker(backend: &Backend, key: &PoolKey) -> (crate::failsafe::CircuitState, u64, u32) {
    let stats = backend
        .pool
        .get(key)
        .expect("slot present")
        .failsafe
        .circuit_breaker
        .stats();
    (stats.state, stats.trips_count, stats.current_failures)
}

fn assert_refused_at_cap(result: &Result<impl std::fmt::Debug>, cap: usize) {
    match result {
        Err(Error::IdentitySlotsExhausted { backend, cap: got }) => {
            assert_eq!((backend.as_str(), *got), ("mem", cap));
        }
        other => panic!("expected IdentitySlotsExhausted at cap {cap}, got {other:?}"),
    }
}

/// S1 + S2: a third identity is refused, reaches no upstream on any slot, and
/// gets no slot. The shared slot hears nothing (the #727 rule).
#[tokio::test]
async fn new_identity_past_the_cap_is_refused() {
    let (backend, shared, a, b) = at_cap();
    for binding in ["a", "b"] {
        backend
            .request_with_headers("tools/list", None, &[], Some(binding))
            .await
            .expect("an admitted identity is served");
    }

    let refused = backend
        .request_with_headers("tools/list", None, &[], Some("c"))
        .await;

    assert_refused_at_cap(&refused, 2);
    let message = refused.expect_err("refused").to_string();
    assert!(
        message.contains("identity_propagation.max_identity_slots"),
        "{message}"
    );
    assert_eq!(
        a.requests.load(Ordering::SeqCst),
        1,
        "c must not ride a's slot"
    );
    assert_eq!(
        b.requests.load(Ordering::SeqCst),
        1,
        "c must not ride b's slot"
    );
    assert_eq!(
        shared.requests.load(Ordering::SeqCst),
        0,
        "c must never reach Shared"
    );
    assert!(
        !backend.pool_has_slot_for_test(&user("c")),
        "no slot for a refused identity"
    );
    assert_eq!(backend.identity_slots_in_use_for_test(), 2);
}

/// S3: refusals record nothing on any breaker, not merely too little to trip it.
#[tokio::test]
async fn refusal_records_no_failsafe_failure() {
    let (backend, _shared, _a, _b) = at_cap();
    let keys = [PoolKey::Shared, user("a"), user("b")];
    let before: Vec<_> = keys.iter().map(|k| breaker(&backend, k)).collect();

    for i in 0..6 {
        let refused = backend
            .request_with_headers("tools/list", None, &[], Some(&format!("new-{i}")))
            .await;
        assert_refused_at_cap(&refused, 2);
    }

    let after: Vec<_> = keys.iter().map(|k| breaker(&backend, k)).collect();
    assert_eq!(before, after, "a capacity refusal is not a backend failure");
}

/// S4: eviction frees slots, by idle reaping and by identity revocation.
#[tokio::test]
async fn eviction_frees_a_slot() {
    let (backend, _shared, _a, _b) = at_cap();
    backend.evict_idle_per_user_entries(Duration::ZERO).await;
    assert_eq!(backend.identity_slots_in_use_for_test(), 0);
    seed(&backend, "c");

    let (backend, _shared, _a, _b) = at_cap();
    backend.evict_identity_slots("a").await;
    assert_eq!(backend.identity_slots_in_use_for_test(), 1);
    seed(&backend, "c");
    assert_eq!(backend.identity_slots_in_use_for_test(), 2);
}

/// S5 + S9: a removed entry frees its slot, and an identity that already has
/// one is served at the cap without spending another.
#[tokio::test]
async fn slot_count_exact_after_replace_and_drop() {
    let (backend, _shared, a, _b) = at_cap();
    backend
        .request_with_headers("tools/list", None, &[], Some("a"))
        .await
        .expect("an existing identity is served at the cap");
    assert_eq!(a.requests.load(Ordering::SeqCst), 1);
    assert_eq!(
        backend.identity_slots_in_use_for_test(),
        2,
        "no second slot for a"
    );

    backend.pool.remove(&user("b"));
    assert_eq!(backend.identity_slots_in_use_for_test(), 1);
    seed(&backend, "c");
    assert_eq!(backend.identity_slots_in_use_for_test(), 2);
}

/// S6: a reload that rebuilds the backend drops the old pool; the old counter
/// drains to zero once its last entry (here, one held across the reload) goes,
/// and the new backend counts from zero on its own.
#[tokio::test]
async fn reload_keeps_slot_count_exact() {
    let (old, _shared, _a, _b) = at_cap();
    let old_slots = old.identity_slots_handle_for_test();
    let held = Arc::clone(old.pool.get(&user("a")).expect("a's slot").value());
    drop(old);
    assert_eq!(old_slots.in_use(), 1, "the held entry still owns its slot");
    drop(held);
    assert_eq!(
        old_slots.in_use(),
        0,
        "the old counter drains with its last entry"
    );

    let new = capped_backend(2);
    assert_eq!(new.identity_slots_in_use_for_test(), 0);
    seed(&new, "a");
    seed(&new, "b");
    assert_eq!(new.identity_slots_in_use_for_test(), 2);
    assert_eq!(old_slots.in_use(), 0, "the two counters are independent");
}

/// S7: an evicted slot still held by a request keeps counting until the
/// request ends, because the transport it bounds is still live.
#[tokio::test]
async fn evicted_but_in_flight_slot_counts_until_release() {
    let (backend, _shared, _a, _b) = at_cap();
    let guard = backend.begin_activity(&user("a")).expect("a is admitted");
    backend.evict_identity_slots("a").await;
    assert!(!backend.pool_has_slot_for_test(&user("a")));
    assert_eq!(
        backend.identity_slots_in_use_for_test(),
        2,
        "a's request still holds it"
    );
    drop(guard);
    assert_eq!(backend.identity_slots_in_use_for_test(), 1);
}

/// S10: a metadata question about an identity with no slot answers "nothing
/// cached" and spends no slot.
#[tokio::test]
async fn freshness_probe_creates_no_slot() {
    let (backend, _shared, _a, _b) = at_cap();
    assert!(!backend.has_cached_tools_for(Some("unseen")));
    assert_eq!(backend.cached_tools_count_for(Some("unseen")), 0);
    assert!(backend.get_cached_tool_names_for(Some("unseen")).is_empty());
    assert!(!backend.pool_has_slot_for_test(&user("unseen")));
    assert_eq!(backend.identity_slots_in_use_for_test(), 2);
}

/// S11: a cap of zero is a configuration error that names the field.
#[test]
fn zero_cap_is_a_config_error() {
    let mut cfg = capped_backend(1)
        .config
        .identity_propagation
        .clone()
        .expect("propagation configured");
    cfg.max_identity_slots = 0;
    let error = cfg.validate().expect_err("a zero cap can serve nobody");
    assert!(error.to_string().contains("max_identity_slots"), "{error}");
    cfg.max_identity_slots = 1;
    assert!(cfg.validate().is_ok());
}

/// S12: two reservations that both read `cap - 1` race for the last slot, and
/// exactly one wins. The barrier parks each between its read and its claim.
#[test]
fn concurrent_admission_never_exceeds_the_cap() {
    let backend = capped_backend(2);
    let _first = backend.reserve_identity_slot().expect("slot 1 of 2");
    *backend.identity_slots.reserve_barrier.lock().expect("lock") =
        Some(Arc::new(std::sync::Barrier::new(2)));

    let racers: Vec<_> = (0..2)
        .map(|_| {
            let backend = Arc::clone(&backend);
            std::thread::spawn(move || backend.reserve_identity_slot().map(|_lease| ()))
        })
        .collect();
    let won = racers
        .into_iter()
        .map(|racer| racer.join().expect("racer thread"))
        .filter(Result::is_ok)
        .count();

    assert_eq!(won, 1, "both read cap - 1; only one may take the last slot");
}

/// S12, end to end: eight identities at once against cap four, and eight
/// requests for one new identity at once.
#[tokio::test]
async fn concurrent_identities_are_admitted_exactly_to_the_cap() {
    let backend = capped_backend(4);
    let attempts = (0..8).map(|i| {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.pooled_entry(&user(&format!("u{i}"))).is_ok() })
    });
    let admitted = futures::future::join_all(attempts)
        .await
        .into_iter()
        .filter(|joined| *joined.as_ref().expect("task"))
        .count();
    assert_eq!(admitted, 4);
    assert_eq!(backend.identity_slots_in_use_for_test(), 4);

    let backend = capped_backend(4);
    let same = (0..8).map(|_| {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.pooled_entry(&user("one")).is_ok() })
    });
    let served = futures::future::join_all(same).await;
    assert!(served.iter().all(|joined| *joined.as_ref().expect("task")));
    assert_eq!(
        backend.identity_slots_in_use_for_test(),
        1,
        "one identity, one slot"
    );
}

/// S13: every path that can create a `PerUser` slot refuses at the cap and
/// never falls back to `Shared`.
#[tokio::test]
async fn refusal_propagates_on_every_per_user_caller() {
    let (backend, shared, _a, _b) = at_cap();
    let shared_breaker = breaker(&backend, &PoolKey::Shared);

    let notified = backend
        .notify_with_headers("notifications/initialized", None, &[], Some("c"))
        .await;
    assert_refused_at_cap(&notified, 2);
    let started = backend.ensure_entry_started(&user("c")).await;
    assert_refused_at_cap(&started.map(|_| ()), 2);
    let active = backend.begin_activity(&user("c"));
    assert_refused_at_cap(&active.map(|_| ()), 2);
    let internal = backend.begin_internal_activity_for(&user("c"));
    assert_refused_at_cap(&internal.map(|_| ()), 2);

    assert_eq!(shared.requests.load(Ordering::SeqCst), 0);
    assert_eq!(shared.notifications.load(Ordering::SeqCst), 0);
    assert_eq!(breaker(&backend, &PoolKey::Shared), shared_breaker);
    assert!(!backend.pool_has_slot_for_test(&user("c")));
}

/// S14: a request parked between its lookup and its activity claim while the
/// reaper evicts its slot. The orphan it holds keeps counting while it lives;
/// once it ends, the count equals the live `PerUser` entries.
#[tokio::test]
async fn eviction_racing_a_request_keeps_the_count_exact() {
    let (backend, _shared, _a, _b) = at_cap();
    let parked = backend.pooled_entry(&user("a")).expect("a is admitted");
    backend.evict_idle_per_user_entries(Duration::ZERO).await;
    assert_eq!(
        backend.identity_slots_in_use_for_test(),
        1,
        "only the parked orphan"
    );

    let guard = backend
        .begin_activity(&user("a"))
        .expect("a gets a fresh slot");
    assert_eq!(
        backend.identity_slots_in_use_for_test(),
        2,
        "orphan plus the fresh slot"
    );
    drop(parked);
    drop(guard);
    let live = backend
        .pool
        .iter()
        .filter(|entry| matches!(entry.key(), PoolKey::PerUser { .. }))
        .count();
    assert_eq!(backend.identity_slots_in_use_for_test(), live);
}

/// S8: each refusal increments `identity_slots_refused_total{backend}` once,
/// and an admission does not.
#[cfg(feature = "metrics")]
#[tokio::test]
async fn refusal_increments_refused_total() {
    fn refused_total(backend: &str) -> u64 {
        crate::metrics::render()
            .lines()
            .find(|line| {
                line.starts_with("identity_slots_refused_total")
                    && line.contains(&format!("backend=\"{backend}\""))
            })
            .and_then(|line| line.rsplit(' ').next())
            .and_then(|n| n.parse().ok())
            .unwrap_or(0)
    }
    crate::metrics::install();
    // A name no other test uses: the recorder is process-global.
    let backend = capped_backend_named("mem-refused-total", 1);
    let before = refused_total("mem-refused-total");
    seed(&backend, "a");
    assert_eq!(
        refused_total("mem-refused-total"),
        before,
        "an admission is not a refusal"
    );
    let refused = backend.pooled_entry(&user("b"));
    assert!(matches!(
        refused,
        Err(Error::IdentitySlotsExhausted { cap: 1, .. })
    ));
    assert_eq!(refused_total("mem-refused-total"), before + 1);
}
