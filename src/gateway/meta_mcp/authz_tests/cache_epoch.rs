// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! CACHE.4b and 4e: policy epoch and revision buckets in the response cache.

use super::*;

// ===========================================================================
// CACHE.4b — policy epoch at the grant-store writer (4.f.1) and the
// in-flight bump between read-key and write-key (4.g).
//
// Plan: docs/design/2026-09-06-cache4-policy-epoch-test-plan.md.
// The caller stays AUTHORIZED across the grant mutation: a revocation is
// decided above the cache, so a denying swap would go green without an
// epoch anywhere. The observable is the backend call counter, never body
// text (the counted backend returns a constant).
// ===========================================================================

fn still_authorized_grants() -> crate::identity_grants::LocalIdentityGrantStore {
    use crate::identity_grants::{
        GrantAgent, GrantScope, GrantSubject, IdentityGrant, LocalIdentityGrantStore,
    };
    let subject = GrantSubject::new("test-authority", "user-still-allowed", None);
    LocalIdentityGrantStore::from_grants([IdentityGrant {
        grant_id: "grant-still-authorized".to_string(),
        subject,
        agent: GrantAgent::Any,
        capability: "unrelated".to_string(),
        tool: None,
        scope: GrantScope::Execute,
        owner: None,
        expires_at: None,
        revoked_at: None,
        provenance: "cache-4b-test".to_string(),
        reason: "adds a permission; does not revoke the caller".to_string(),
    }])
}

/// CACHE.4b / 4.f.1 — a grant-store mutation that leaves the caller
/// authorized must strand the prior cache entry. The swapped store adds a
/// permission; it does not revoke. Dispatch after the swap is the
/// falsifier; an error is the wrong green.
#[tokio::test]
async fn authz_cache_4b_a_grant_change_strands_the_prior_entry() {
    let (registry, calls) = counted_backend("alpha");
    let cache = Arc::new(crate::cache::ResponseCache::new());
    let meta = MetaMcp::with_features(
        registry,
        Some(Arc::clone(&cache)),
        None,
        None,
        Duration::from_secs(300),
    );

    let primed = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await;
    assert!(primed.is_ok(), "priming call must succeed: {primed:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the backend was called once"
    );

    let hit = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await;
    assert!(hit.is_ok(), "hit control must succeed: {hit:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the cache must be live — if this dispatches, the miss half below \
         proves nothing"
    );

    meta.set_identity_grants(still_authorized_grants());

    assert_eq!(
        cache.stats().size,
        1,
        "stranding leaves the prior entry in the map; ResponseCache::clear() \
         would drop it, which is the racy alternative this change refuses"
    );

    let after = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await;
    assert!(
        after.is_ok(),
        "the swapped grants must leave the caller authorized, not fail the \
         invoke: {after:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a post-bump invoke under still-authorized grants must miss and \
         dispatch; a hit here means the epoch was not mixed into the key"
    );
}

/// Transport that advances the handler's policy epoch once, on its first
/// backend call — the one interleave a test can drive through the production
/// path, sitting between the read-side key and the write-side key.
struct EpochBumpingTransport {
    calls: Arc<AtomicUsize>,
    epoch: Arc<AtomicU64>,
    bumped: AtomicBool,
    result: Value,
}

#[async_trait::async_trait]
impl Transport for EpochBumpingTransport {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        assert_eq!(method, "tools/call");
        if !self.bumped.swap(true, Ordering::SeqCst) {
            self.epoch.fetch_add(1, Ordering::Release);
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            self.result.clone(),
        ))
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// CACHE.4b / 4.g — read and write keys share the pre-dispatch epoch.
///
/// Three invokes, no priming: a primed entry is hit before the bump fires.
/// Invoke 1 dispatches and bumps mid-call; invoke 2 must dispatch because
/// the first write landed under the pre-bump epoch; invoke 3 must hit
/// (count stays 2), or the first two only proved the backend ran twice.
#[tokio::test]
async fn authz_cache_4b_read_and_write_keys_share_the_pre_dispatch_epoch() {
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "alpha",
        crate::config::BackendConfig::r2_off(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let _ = registry.register(Arc::clone(&backend));
    let meta = MetaMcp::with_features(
        registry,
        Some(Arc::new(crate::cache::ResponseCache::new())),
        None,
        None,
        Duration::from_secs(300),
    );
    backend.set_transport_for_test(Arc::new(EpochBumpingTransport {
        calls: Arc::clone(&calls),
        epoch: Arc::clone(&meta.policy_epoch),
        bumped: AtomicBool::new(false),
        result: json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
    }));

    let first = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await;
    assert!(first.is_ok(), "first invoke must dispatch: {first:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the backend was called once"
    );

    let second = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await;
    assert!(second.is_ok(), "second invoke must succeed: {second:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the first write must have landed under the pre-bump epoch, so a \
         post-bump reader cannot retrieve it — re-reading the epoch at the \
         write site would serve this call from cache"
    );

    let third = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await;
    assert!(third.is_ok(), "third invoke must succeed: {third:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a third call under the still-bumped epoch must hit; without this, \
         an implementation that writes nothing dispatches twice and passes"
    );
}

/// CACHE.4e production plumbing — two classified revisions do not share an
/// entry. Hit control: the first revision's second call stays at 1.
#[tokio::test]
async fn authz_cache_4e_two_revisions_do_not_share_an_entry() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::with_features(
        registry,
        Some(Arc::new(crate::cache::ResponseCache::new())),
        None,
        None,
        Duration::from_secs(300),
    );
    let mut first = ctx(&AllowAll);
    first.protocol_revision = Some("2025-03-26");
    let mut second = ctx(&AllowAll);
    second.protocol_revision = Some("2025-06-18");

    meta.invoke_tool(&invoke_args("alpha", "read"), None, &first)
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    meta.invoke_tool(&invoke_args("alpha", "read"), None, &first)
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "hit control: the first revision must be cached"
    );
    meta.invoke_tool(&invoke_args("alpha", "read"), None, &second)
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a second classified revision must miss"
    );
}

/// Unknown revision skips the response cache only. A later known-revision
/// call still hits the entry primed under that revision.
#[tokio::test]
async fn authz_cache_4e_unknown_revision_skips_cache_not_all_caching() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::with_features(
        registry,
        Some(Arc::new(crate::cache::ResponseCache::new())),
        None,
        None,
        Duration::from_secs(300),
    );
    let known = ctx(&AllowAll);
    let mut unknown = ctx(&AllowAll);
    unknown.protocol_revision = None;

    meta.invoke_tool(&invoke_args("alpha", "read"), None, &known)
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    meta.invoke_tool(&invoke_args("alpha", "read"), None, &unknown)
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "unknown revision must not read the known entry"
    );
    meta.invoke_tool(&invoke_args("alpha", "read"), None, &known)
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the known entry must still be live after an unknown-revision miss"
    );
}

/// CACHE.4b / 4.f.2 — `LiveConfig::set` bumps the shared epoch so a subsequent
/// invoke misses. Hit control before the set.
#[tokio::test]
async fn authz_cache_4b_live_config_set_strands_the_prior_entry() {
    let (registry, calls) = counted_backend("alpha");
    let cache = Arc::new(crate::cache::ResponseCache::new());
    let meta = MetaMcp::with_features(
        registry,
        Some(Arc::clone(&cache)),
        None,
        None,
        Duration::from_secs(300),
    );
    let live = crate::config_reload::LiveConfig::new(crate::config::Config::default())
        .with_policy_epoch(Arc::clone(&meta.policy_epoch));

    meta.invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await
        .unwrap();
    meta.invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1, "hit control");

    live.set(crate::config::Config::default());
    assert_eq!(cache.stats().size, 1, "set strands, it does not clear");

    meta.invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a post-set invoke must miss"
    );
}

/// CACHE.4 outer — the shipped default (no identity propagation, no OIDC) must
/// still isolate two callers. Their only principal is the `GrantSubject` the
/// router derives from trusted headers / mTLS / an OAuth agent, so a key that
/// ignored it served one caller's body to the other. Hit control first: the
/// same principal twice must stay at one dispatch, or a miss below would be
/// explained equally well by a cache that never stores.
#[tokio::test]
async fn authz_cache_4_two_grant_subjects_do_not_share_an_outer_entry() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::with_features(
        registry,
        Some(Arc::new(crate::cache::ResponseCache::new())),
        None,
        None,
        Duration::from_secs(300),
    );
    let subject = |name: &'static str| {
        Some(crate::identity_grants::GrantSubject::new(
            "cloudflare_access",
            name,
            None,
        ))
    };
    let alice = MetaMcpCallerContext {
        grant_subject: subject("alice"),
        ..ctx(&AllowAll)
    };
    let alice_again = MetaMcpCallerContext {
        grant_subject: subject("alice"),
        ..ctx(&AllowAll)
    };
    let bob = MetaMcpCallerContext {
        grant_subject: subject("bob"),
        ..ctx(&AllowAll)
    };

    meta.invoke_tool(&invoke_args("alpha", "read"), None, &alice)
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1, "alice primes the cache");
    meta.invoke_tool(&invoke_args("alpha", "read"), None, &alice_again)
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "hit control: the same principal must be served from cache"
    );
    meta.invoke_tool(&invoke_args("alpha", "read"), None, &bob)
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a second principal must not be served alice's body"
    );
}

/// A revision spelling the gateway never served names no bucket at all: it is
/// not trimmed onto the canonical one, and it gets no bucket of its own.
#[tokio::test]
async fn authz_cache_4e_whitespace_padded_revision_is_not_a_bucket() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::with_features(
        registry,
        Some(Arc::new(crate::cache::ResponseCache::new())),
        None,
        None,
        Duration::from_secs(300),
    );
    let known = ctx(&AllowAll);
    let mut padded = ctx(&AllowAll);
    padded.protocol_revision = Some(" 2025-11-25 ");

    meta.invoke_tool(&invoke_args("alpha", "read"), None, &known)
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    meta.invoke_tool(&invoke_args("alpha", "read"), None, &known)
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1, "hit control");
    meta.invoke_tool(&invoke_args("alpha", "read"), None, &padded)
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a padded spelling must not read the canonical entry"
    );
    meta.invoke_tool(&invoke_args("alpha", "read"), None, &padded)
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "and must not have stored a bucket of its own"
    );
    meta.invoke_tool(&invoke_args("alpha", "read"), None, &known)
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "the canonical entry must still be live"
    );
}
