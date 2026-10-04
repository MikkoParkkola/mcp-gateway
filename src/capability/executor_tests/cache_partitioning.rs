// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The response cache and its principal and snapshot partitioning.

use super::*;

/// Finite-timeout client for swapped-client fixtures. Bare `Client::new()`
/// has no request timeout; a hung listener would stall the suite.
fn finite_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap()
}

/// Counting loopback server plus a cacheable Shared capability. The client is
/// swapped so `localhost` clears SSRF without relaxing `allow_loopback_egress`.
async fn cacheable_counting_executor()
-> (CapabilityExecutor, CapabilityDefinition, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_for_handler = Arc::clone(&hits);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/probe",
                get(move || {
                    let hits = Arc::clone(&hits_for_handler);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        Json(serde_json::json!({"ok": true}))
                    }
                }),
            ),
        )
        .await
        .unwrap();
    });

    let mut executor = CapabilityExecutor::new();
    executor.client = finite_http_client();
    let capability = crate::capability::parse_capability(&format!(
        r"
name: cache_probe
description: Shared cacheable probe
cache:
  ttl: 60
  strategy: memory
providers:
  primary:
    service: rest
    config:
      base_url: http://localhost:{port}
      path: /probe
      method: GET
"
    ))
    .unwrap();
    (executor, capability, hits)
}

fn alice() -> CapabilityExecutionContext {
    CapabilityExecutionContext::with_caller_identity(GrantSubject::new(
        "cloudflare_access",
        "alice",
        None,
    ))
}

fn bob() -> CapabilityExecutionContext {
    CapabilityExecutionContext::with_caller_identity(GrantSubject::new(
        "cloudflare_access",
        "bob",
        None,
    ))
}

fn with_snapshot(
    mut context: CapabilityExecutionContext,
    revision: Option<&str>,
    profile: Option<&str>,
    epoch: Option<u64>,
) -> CapabilityExecutionContext {
    context.protocol_revision = revision.map(str::to_owned);
    context.routing_profile = profile.map(str::to_owned);
    context.policy_epoch = epoch;
    context
}

fn with_binding(
    mut context: CapabilityExecutionContext,
    binding: &str,
) -> CapabilityExecutionContext {
    context.cache_binding = Some(binding.to_owned());
    context
}

/// CACHE.4 executor — two principals must not share an entry. Hit control:
/// alice twice stays at 1, so a miss for bob is isolation, not a dead cache.
#[tokio::test]
async fn cache_4_executor_two_principals_do_not_share_an_entry() {
    let (executor, capability, hits) = cacheable_counting_executor().await;
    let params = serde_json::json!({});

    executor
        .execute_with_context(&capability, params.clone(), alice())
        .await
        .unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1, "alice primes the cache");

    executor
        .execute_with_context(&capability, params.clone(), alice())
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "hit control: alice's second call must be served from cache"
    );

    executor
        .execute_with_context(&capability, params, bob())
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "bob must not be served alice's body"
    );
}

/// CACHE.4 executor — two loopback-relaxed calls both dispatch. This case
/// proves the relaxed fetch is not stored. It does not claim a later
/// enforcing-context caller is refused that body.
#[tokio::test]
async fn cache_4_executor_loopback_context_is_not_cached() {
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_for_handler = Arc::clone(&hits);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/probe",
                get(move || {
                    let hits = Arc::clone(&hits_for_handler);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        Json(serde_json::json!({"ok": true}))
                    }
                }),
            ),
        )
        .await
        .unwrap();
    });

    let mut executor = CapabilityExecutor::new();
    executor.client = finite_http_client();
    let capability = crate::capability::parse_capability(&format!(
        r"
name: loopback_probe
description: Loopback cacheable probe
cache:
  ttl: 60
  strategy: memory
providers:
  primary:
    service: rest
    config:
      base_url: http://127.0.0.1:{port}
      path: /probe
      method: GET
"
    ))
    .unwrap();
    let context = CapabilityExecutionContext::default().with_isolated_loopback_egress();
    let params = serde_json::json!({});

    executor
        .execute_with_context(&capability, params.clone(), context.clone())
        .await
        .unwrap();
    executor
        .execute_with_context(&capability, params, context)
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "two loopback-relaxed calls must both dispatch; a hit here means the \
         relaxed fetch was stored"
    );
}

/// Executor must key on the invoke snapshot, not a reread of the shared Arc.
#[tokio::test]
async fn cache_4_executor_uses_context_epoch_not_a_reread() {
    let (mut executor, capability, hits) = cacheable_counting_executor().await;
    let epoch = Arc::new(std::sync::atomic::AtomicU64::new(0));
    executor = executor.with_policy_epoch(Arc::clone(&epoch));
    let context = with_snapshot(
        alice(),
        Some(crate::protocol::PROTOCOL_VERSION),
        Some("default"),
        Some(0),
    );
    let params = serde_json::json!({});

    executor
        .execute_with_context(&capability, params.clone(), context.clone())
        .await
        .unwrap();
    epoch.fetch_add(1, Ordering::Release);
    executor
        .execute_with_context(&capability, params, context)
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "a bump of the Arc after capture must not change the write key; \
         rereading the Arc at insert would miss"
    );
}

/// An attached production executor without a request snapshot must not cache.
/// Epoch 0 after a reload would keep serving pre-reload bodies.
#[tokio::test]
async fn cache_4_executor_attached_without_snapshot_is_not_cached() {
    let (mut executor, capability, hits) = cacheable_counting_executor().await;
    executor = executor.with_policy_epoch(Arc::new(std::sync::atomic::AtomicU64::new(7)));
    let params = serde_json::json!({});
    let context = with_snapshot(
        alice(),
        Some(crate::protocol::PROTOCOL_VERSION),
        Some("default"),
        None,
    );
    executor
        .execute_with_context(&capability, params.clone(), context.clone())
        .await
        .unwrap();
    executor
        .execute_with_context(&capability, params, context)
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "missing snapshot on an attached executor must bypass, not key epoch 0"
    );
}

/// Attached executor missing a routing profile must bypass, even with epoch
/// and a known revision.
#[tokio::test]
async fn cache_4_executor_attached_without_profile_is_not_cached() {
    let (mut executor, capability, hits) = cacheable_counting_executor().await;
    executor = executor.with_policy_epoch(Arc::new(std::sync::atomic::AtomicU64::new(0)));
    let params = serde_json::json!({});
    let context = with_snapshot(
        alice(),
        Some(crate::protocol::PROTOCOL_VERSION),
        None,
        Some(0),
    );
    executor
        .execute_with_context(&capability, params.clone(), context.clone())
        .await
        .unwrap();
    executor
        .execute_with_context(&capability, params, context)
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "attached executor without a routing profile must bypass inner cache"
    );
}

/// Attached executor missing a known revision must bypass, even with epoch.
#[tokio::test]
async fn cache_4_executor_attached_without_known_revision_is_not_cached() {
    let (mut executor, capability, hits) = cacheable_counting_executor().await;
    executor = executor.with_policy_epoch(Arc::new(std::sync::atomic::AtomicU64::new(0)));
    let params = serde_json::json!({});
    let context = with_snapshot(alice(), None, Some("default"), Some(0));
    executor
        .execute_with_context(&capability, params.clone(), context.clone())
        .await
        .unwrap();
    executor
        .execute_with_context(&capability, params, context)
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "attached executor without a known revision must bypass inner cache"
    );
}

/// Same {revision, profile, epoch, principal} must hit. Hit control for the
/// partition tests below: a dead cache would make every miss look like isolation.
#[tokio::test]
async fn cache_4_executor_same_context_hits() {
    let (mut executor, capability, hits) = cacheable_counting_executor().await;
    executor = executor.with_policy_epoch(Arc::new(std::sync::atomic::AtomicU64::new(0)));
    let params = serde_json::json!({});
    let context = with_snapshot(
        alice(),
        Some(crate::protocol::PROTOCOL_VERSION),
        Some("default"),
        Some(0),
    );
    executor
        .execute_with_context(&capability, params.clone(), context.clone())
        .await
        .unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1, "first call dispatches");
    executor
        .execute_with_context(&capability, params, context)
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "same revision, profile, and epoch must hit"
    );
}

/// Two classified revisions must not share an inner entry.
#[tokio::test]
async fn cache_4_executor_two_revisions_do_not_share_an_entry() {
    let (mut executor, capability, hits) = cacheable_counting_executor().await;
    executor = executor.with_policy_epoch(Arc::new(std::sync::atomic::AtomicU64::new(0)));
    let params = serde_json::json!({});
    let first = with_snapshot(alice(), Some("2025-03-26"), Some("default"), Some(0));
    let second = with_snapshot(alice(), Some("2025-06-18"), Some("default"), Some(0));

    executor
        .execute_with_context(&capability, params.clone(), first.clone())
        .await
        .unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    executor
        .execute_with_context(&capability, params.clone(), first)
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "hit control: the first revision must be cached"
    );
    executor
        .execute_with_context(&capability, params, second)
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "a second classified revision must miss"
    );
}

/// Two routing profiles must not share an inner entry.
#[tokio::test]
async fn cache_4_executor_two_profiles_do_not_share_an_entry() {
    let (mut executor, capability, hits) = cacheable_counting_executor().await;
    executor = executor.with_policy_epoch(Arc::new(std::sync::atomic::AtomicU64::new(0)));
    let params = serde_json::json!({});
    let first = with_snapshot(
        alice(),
        Some(crate::protocol::PROTOCOL_VERSION),
        Some("research"),
        Some(0),
    );
    let second = with_snapshot(
        alice(),
        Some(crate::protocol::PROTOCOL_VERSION),
        Some("coding"),
        Some(0),
    );

    executor
        .execute_with_context(&capability, params.clone(), first.clone())
        .await
        .unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    executor
        .execute_with_context(&capability, params.clone(), first)
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "hit control: the first profile must be cached"
    );
    executor
        .execute_with_context(&capability, params, second)
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "a second routing profile must miss"
    );
}

/// Unknown revision skips inner cache. A later known-revision call still hits
/// the entry primed under that revision.
#[tokio::test]
async fn cache_4_executor_unknown_revision_skips_cache() {
    let (mut executor, capability, hits) = cacheable_counting_executor().await;
    executor = executor.with_policy_epoch(Arc::new(std::sync::atomic::AtomicU64::new(0)));
    let params = serde_json::json!({});
    let known = with_snapshot(
        alice(),
        Some(crate::protocol::PROTOCOL_VERSION),
        Some("default"),
        Some(0),
    );
    let unknown = with_snapshot(alice(), None, Some("default"), Some(0));
    let unsupported = with_snapshot(alice(), Some("not-a-revision"), Some("default"), Some(0));

    executor
        .execute_with_context(&capability, params.clone(), known.clone())
        .await
        .unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    executor
        .execute_with_context(&capability, params.clone(), unknown)
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "unknown revision must not read the known entry"
    );
    executor
        .execute_with_context(&capability, params.clone(), unsupported)
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        3,
        "unsupported revision must bypass, not share the known key"
    );
    executor
        .execute_with_context(&capability, params, known)
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        3,
        "the known entry must still be live after unknown-revision misses"
    );
}

/// Already-resolved outer `cache_binding` partitions the inner key. Two
/// bindings with the same principal must not share an entry, so a grant or
/// token revision that changed the outer binding cannot be served from inner.
#[tokio::test]
async fn cache_4_executor_two_bindings_do_not_share_an_entry() {
    let (mut executor, capability, hits) = cacheable_counting_executor().await;
    executor = executor.with_policy_epoch(Arc::new(std::sync::atomic::AtomicU64::new(0)));
    let params = serde_json::json!({});
    let snapshot = || {
        with_snapshot(
            alice(),
            Some(crate::protocol::PROTOCOL_VERSION),
            Some("default"),
            Some(0),
        )
    };
    let first = with_binding(snapshot(), "binding-rev-1");
    let second = with_binding(snapshot(), "binding-rev-2");

    executor
        .execute_with_context(&capability, params.clone(), first.clone())
        .await
        .unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    executor
        .execute_with_context(&capability, params.clone(), first)
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "hit control: the first binding must be cached"
    );
    executor
        .execute_with_context(&capability, params, second)
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "a second already-resolved cache_binding must miss"
    );
}

/// CACHE.4e inner — a modern-era caller must be able to HIT the inner cache.
/// `MODERN_VERSIONS` is deliberately absent from `SUPPORTED_VERSIONS`
/// (`src/protocol/mod.rs`), so a helper built on the latter alone took the
/// `revision?` bypass for every modern request: the inner cache never stored
/// and never served on that path, while the outer one cached under the same
/// revision. The padded spelling below is the control that the widened set
/// is still an exact set.
#[tokio::test]
async fn cache_4_executor_modern_revision_hits_the_inner_cache() {
    let (mut executor, capability, hits) = cacheable_counting_executor().await;
    executor = executor.with_policy_epoch(Arc::new(std::sync::atomic::AtomicU64::new(0)));
    let params = serde_json::json!({});
    let modern_revision = crate::protocol::meta::MODERN_VERSIONS[0];
    let modern = with_snapshot(alice(), Some(modern_revision), Some("default"), Some(0));
    let padded = with_snapshot(alice(), Some(" 2026-07-28 "), Some("default"), Some(0));

    executor
        .execute_with_context(&capability, params.clone(), modern.clone())
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "first modern call dispatches"
    );
    executor
        .execute_with_context(&capability, params.clone(), modern.clone())
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "a modern-era caller must be served from the inner cache"
    );
    executor
        .execute_with_context(&capability, params.clone(), padded.clone())
        .await
        .unwrap();
    executor
        .execute_with_context(&capability, params.clone(), padded)
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        3,
        "a whitespace-padded spelling must bypass, not resolve onto the bucket"
    );
    executor
        .execute_with_context(&capability, params, modern)
        .await
        .unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        3,
        "the modern entry must still be live"
    );
}

/// MIK-7814: only a process provider keys its cache on the whole definition.
/// A cacheable REST call, hit or miss, never computes a fingerprint; the
/// process-provider tests in `backend_pin_tests` show the counter does move.
#[tokio::test]
async fn a_rest_cacheable_call_never_computes_a_fingerprint() {
    use crate::capability::definition::FINGERPRINTS;
    let (executor, capability, hits) = cacheable_counting_executor().await;
    let before = FINGERPRINTS.with(std::cell::Cell::get);
    for _ in 0..2 {
        executor
            .execute_with_context(&capability, serde_json::json!({}), alice())
            .await
            .unwrap();
    }
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the second call is a hit");
    assert_eq!(
        FINGERPRINTS.with(std::cell::Cell::get) - before,
        0,
        "a REST call must not pay for a fingerprint"
    );
}
