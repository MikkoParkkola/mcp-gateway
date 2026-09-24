// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A0: who the response cache and the retry key belong to.
//!
//! An authenticated caller is never pooled with another: it keys on its own
//! principal, or — when no arm can name it — it gets no key at all. Only an
//! anonymous caller shares the one pooled namespace.
//!
//! T8/T8b build the context in-process because HTTP cannot produce an
//! authenticated caller with no principal: every `AuthenticatedClient` the
//! auth middleware builds carries a credential digest.

use super::{
    Authentication, CachePrincipal, caller_cache_principal, idempotency_key_for,
    retry_identity_suffix,
};
use crate::identity_grants::GrantSubject;

fn authenticated(credential_principal: Option<&str>) -> CachePrincipal {
    caller_cache_principal(
        None,
        None,
        None,
        credential_principal,
        Authentication::Authenticated,
    )
}

/// T10. The `cred:` arm keeps its own tag and length prefix, so a credential
/// digest cannot collide with another digest, nor with a binding, OIDC actor
/// or grant subject spelled the same way (extends the #760 forged-suffix pins).
#[test]
fn cache_principal_tags_cannot_collide() {
    let digest = "abc123def456";
    let cred = authenticated(Some(digest));
    let other = authenticated(Some("0123456789ab"));
    assert!(
        matches!(cred, CachePrincipal::Caller(_)),
        "an authenticated caller with a credential digest must resolve to a \
         principal of its own, got {cred:?}"
    );
    assert_ne!(cred, other, "two API keys must not share one principal");

    let subject = GrantSubject::new(digest, digest, None);
    let spelled = [
        caller_cache_principal(Some(digest), None, None, None, Authentication::Anonymous),
        caller_cache_principal(None, None, Some(&subject), None, Authentication::Anonymous),
    ];
    for forged in &spelled {
        assert_ne!(&cred, forged, "cred: collided with another tag's spelling");
    }
    // A binding whose text IS the cred principal's own spelling still differs.
    if let CachePrincipal::Caller(spelling) = &cred {
        let forged =
            caller_cache_principal(Some(spelling), None, None, None, Authentication::Anonymous);
        assert_ne!(
            cred, forged,
            "a binding spelled as a cred: principal collided"
        );
    }
}

/// T11, the inversion of `retry_identity_suffix_pools_callers_with_no_principal`.
/// Anonymous callers pool; an authenticated caller no arm can name never does.
#[test]
fn an_authenticated_caller_with_no_principal_is_unresolved_and_gets_no_key() {
    let principal = authenticated(None);
    assert_eq!(principal, CachePrincipal::Unresolved);
    assert_eq!(
        retry_identity_suffix(&principal),
        None,
        "an unresolved principal must not fall back to the shared empty suffix"
    );
    let cache = std::sync::Arc::new(crate::idempotency::IdempotencyCache::new());
    assert_eq!(
        idempotency_key_for(Some("k"), "", &principal, Some(&cache), "meta"),
        None
    );
    // The explicit field decides, not the digest: an empty digest from an
    // authenticated caller is still not the anonymous pool.
    assert_eq!(authenticated(Some("")), CachePrincipal::Unresolved);
    // Anonymous keeps the shared namespace, even carrying a non-empty owner
    // (an auth-off task worker carries `AUTH_DISABLED_TASK_OWNER`).
    let anonymous = caller_cache_principal(
        None,
        None,
        None,
        Some("local:auth-disabled:tasks:v1"),
        Authentication::Anonymous,
    );
    assert_eq!(anonymous, CachePrincipal::Anonymous);
    assert_eq!(retry_identity_suffix(&anonymous).as_deref(), Some(""));
}

#[cfg(feature = "metrics")]
mod invoke_path {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use crate::gateway::authz::AllowAll;
    use crate::gateway::meta_mcp::authz_tests::{counted_backend, ctx, invoke_args};
    use crate::gateway::meta_mcp::{Authentication, MetaMcp, MetaMcpCallerContext};
    use crate::protocol::mrtr::RetryFields;
    use crate::security::message_signing::nonce_metrics_support::{Observed, observe};

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime")
    }

    /// Sum of one counter's increments whose labels include every `want` pair.
    fn counted(events: &[Observed], name: &str, want: &[(&str, &str)]) -> u64 {
        events
            .iter()
            .filter_map(|event| match event {
                Observed::CounterAdd(metric, labels, n)
                    if metric == name
                        && want
                            .iter()
                            .all(|(k, v)| labels.iter().any(|(lk, lv)| lk == k && lv == v)) =>
                {
                    Some(*n)
                }
                _ => None,
            })
            .sum()
    }

    fn unresolved<'a>(retry: &'a RetryFields) -> MetaMcpCallerContext<'a> {
        MetaMcpCallerContext {
            authentication: Authentication::Authenticated,
            credential_principal: None,
            api_key_name: None,
            retry,
            ..ctx(&AllowAll)
        }
    }

    fn cached_meta(
        registry: Arc<crate::backend::BackendRegistry>,
    ) -> (MetaMcp, Arc<crate::cache::ResponseCache>) {
        let cache = Arc::new(crate::cache::ResponseCache::new());
        let meta = MetaMcp::with_features(
            registry,
            Some(Arc::clone(&cache)),
            None,
            None,
            Duration::from_secs(300),
        );
        (meta, cache)
    }

    /// T9, and the control for T8: anonymous callers keep the shared
    /// namespace (D4), and this fixture DOES cache, so a bypass below is the
    /// principal's doing. In-process because over HTTP an auth-off modern
    /// call must carry a key, and keyed admission then refuses it for want of
    /// a verified execution principal before the cache is reached.
    #[test]
    fn anonymous_callers_keep_shared_namespace() {
        let (registry, calls) = counted_backend("alpha");
        let (meta, cache) = cached_meta(registry);
        let caller = ctx(&AllowAll);
        runtime().block_on(async {
            for _ in 0..2 {
                meta.invoke_tool(&invoke_args("alpha", "read"), None, &caller)
                    .await
                    .expect("an allowed call succeeds");
            }
        });
        assert_eq!(calls.load(Ordering::SeqCst), 1, "the second call must hit");
        assert_eq!(cache.stats().size, 1);
    }

    /// T8. Authenticated, no digest, no binding, no OIDC, no grant subject:
    /// both calls reach the backend and nothing is written to the cache.
    #[test]
    fn authenticated_caller_with_no_principal_bypasses_cache() {
        let (registry, calls) = counted_backend("alpha");
        let (meta, cache) = cached_meta(registry);
        let retry = RetryFields::default();
        let caller = unresolved(&retry);
        let ((), events) = observe(|| {
            runtime().block_on(async {
                for _ in 0..2 {
                    meta.invoke_tool(&invoke_args("alpha", "read"), None, &caller)
                        .await
                        .expect("the call proceeds without the cache");
                }
            });
        });
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "an unresolved caller was served a pooled cache entry"
        );
        assert_eq!(
            counted(
                &events,
                "mcp_cache_bypass_total",
                &[("reason", "unresolved_principal")]
            ),
            2
        );
        assert_eq!(
            cache.stats().size,
            0,
            "an unresolved caller wrote to the shared namespace"
        );
    }

    /// T8b. The same caller with one idempotency key sent twice: no shared
    /// key space is read or written, so both calls reach the backend.
    #[test]
    fn authenticated_caller_with_no_principal_skips_idempotency_guard() {
        let (registry, calls) = counted_backend("alpha");
        let retry = RetryFields {
            idempotency_key: Some("one-key".to_string()),
            ..RetryFields::default()
        };
        let caller = unresolved(&retry);
        let ((), events) = observe(|| {
            runtime().block_on(async {
                let mut meta = MetaMcp::new(registry);
                meta.enable_idempotency(
                    Arc::new(crate::idempotency::IdempotencyCache::new()),
                    Duration::from_secs(300),
                );
                for _ in 0..2 {
                    meta.invoke_tool(&invoke_args("alpha", "read"), None, &caller)
                        .await
                        .expect("the call proceeds without the guard");
                }
            });
        });
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the second call replayed from the shared, empty-suffix key space"
        );
        assert_eq!(
            counted(
                &events,
                "mcp_idempotency_guard_skipped_total",
                &[("reason", "unresolved_principal"), ("route", "meta")]
            ),
            2
        );
    }
}
