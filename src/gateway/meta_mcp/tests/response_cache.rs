// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Response cache partitioning and idempotent replay.

use super::*;

// ===========================================================================
// MIK-7213.CACHE.4 — the behavioural pairs.
//
// 4.b and 4.d assert that two keys DIFFER. That is a statement about
// `response_key` and nothing else: a key that differs is still worthless if
// the cache consults a different one. These two drive the live cache through
// `invoke_tool` and count backend calls, so what is asserted is that request B
// did not receive request A's entry.
//
// Each pair carries its own hit control. Without one, "the second call reached
// the backend" is satisfied by a cache that never stores anything, which is a
// broken cache rather than a correctly keyed one.
// ===========================================================================

/// A transport that answers with a body naming itself and counts how many
/// times it was actually asked. The count is the miss/hit evidence; the body
/// is the identity evidence — a call served from the wrong entry returns the
/// other backend's text, and only naming it catches that.
struct CountingTestTransport {
    body: &'static str,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for CountingTestTransport {
    async fn request(
        &self,
        method: &str,
        _params: Option<serde_json::Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        assert_eq!(method, "tools/call");
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({"content": [{"type": "text", "text": self.body}], "isError": false}),
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<serde_json::Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

fn counting_backend(
    name: &str,
    body: &'static str,
) -> (
    Arc<crate::backend::Backend>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    use crate::config::{BackendConfig, FailsafeConfig};

    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let backend = Arc::new(crate::backend::Backend::new(
        name,
        BackendConfig::r2_off(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let transport: Arc<dyn crate::transport::Transport> = Arc::new(CountingTestTransport {
        body,
        calls: Arc::clone(&calls),
    });
    backend.set_transport_for_test(transport);
    (backend, calls)
}

/// CACHE.4.a — same `{tool, arguments}`, two different `server` values.
#[tokio::test]
async fn ac_cache_4a_two_backends_do_not_share_one_cache_entry() {
    let registry = Arc::new(BackendRegistry::new());
    let (docs_a, calls_a) = counting_backend("docs_a", "BODY-FROM-A");
    let (docs_b, calls_b) = counting_backend("docs_b", "BODY-FROM-B");
    let _ = registry.register(docs_a);
    let _ = registry.register(docs_b);

    let meta = MetaMcp::with_features(
        registry,
        Some(Arc::new(crate::cache::ResponseCache::new())),
        None,
        None,
        Duration::from_secs(300),
    );
    let invoke = async |server: &str| {
        meta.invoke_tool(
            &json!({"server": server, "tool": "search", "arguments": {}}),
            Some("session-1"),
            &allow_all_ctx(),
        )
        .await
        .unwrap()
        .to_string()
    };

    // Hit control. The same call twice must reach the backend once — without
    // this, every assertion below is also satisfied by a cache that stores
    // nothing at all.
    let first = invoke("docs_a").await;
    let second = invoke("docs_a").await;
    assert_eq!(
        calls_a.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the second identical call must be served from the entry the first stored"
    );
    assert!(first.contains("BODY-FROM-A") && second.contains("BODY-FROM-A"));

    // Miss half. Only the server differs, so a shared entry can only come from
    // the server going unkeyed.
    let other = invoke("docs_b").await;
    assert_eq!(
        calls_b.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a call to a second backend was answered without ever asking it"
    );
    assert!(
        other.contains("BODY-FROM-B"),
        "docs_b was served another backend's body: {other}"
    );
    assert!(
        !other.contains("BODY-FROM-A"),
        "docs_b's reply carries docs_a's body: {other}"
    );
}

/// CACHE.4.e — same `{server, tool, arguments}`, two negotiated revisions.
///
/// The seam guard in `mik_7213_acs.rs` proves only that `KeyContext::digest`
/// reads the field. This one drives `invoke_tool`, so it fails if production
/// stops supplying the caller's negotiated revision as well as if the field
/// leaves the key. The `None` half pins the other production branch: an
/// unclassified revision must bypass the cache rather than name a bucket.
#[tokio::test]
async fn ac_cache_4e_two_protocol_revisions_do_not_share_one_cache_entry() {
    // Both revisions below must classify, or the "miss" half would pass for the
    // wrong reason: an unclassified revision bypasses the cache and the backend
    // is called twice regardless of how the key is built.
    for revision in ["2025-11-25", "2025-06-18"] {
        assert!(
            crate::protocol::meta::served_revision(revision).is_some(),
            "{revision} no longer classifies, so this test would stop exercising the cache key"
        );
    }
    let registry = Arc::new(BackendRegistry::new());
    let (docs, calls) = counting_backend("remote_docs", "SHARED-BODY");
    let _ = registry.register(docs);

    let meta = MetaMcp::with_features(
        registry,
        Some(Arc::new(crate::cache::ResponseCache::new())),
        None,
        None,
        Duration::from_secs(300),
    );
    let invoke = async |revision: Option<&str>| {
        let mut ctx = allow_all_ctx();
        ctx.protocol_revision = revision;
        meta.invoke_tool(
            &json!({"server": "remote_docs", "tool": "search", "arguments": {}}),
            Some("session-1"),
            &ctx,
        )
        .await
        .unwrap()
        .to_string()
    };
    let calls_now = || calls.load(std::sync::atomic::Ordering::SeqCst);

    // Hit control. Without it a cache that stores nothing satisfies the miss
    // half below.
    let _ = invoke(Some("2025-11-25")).await;
    let _ = invoke(Some("2025-11-25")).await;
    assert_eq!(
        calls_now(),
        1,
        "the second identical call must be served from the entry the first stored"
    );

    // Miss half. Only the negotiated revision differs, so a hit here can only
    // come from the revision going unkeyed — or from production passing a
    // constant instead of the caller's value.
    let _ = invoke(Some("2025-06-18")).await;
    assert_eq!(
        calls_now(),
        2,
        "a second protocol revision was served a body shaped for the first"
    );

    // Unclassified revision: neither get nor set, so both of these reach the
    // backend and neither leaves an entry the keyed callers could collide with.
    let _ = invoke(None).await;
    let _ = invoke(None).await;
    assert_eq!(
        calls_now(),
        4,
        "an unclassified revision must bypass the cache, not name a bucket"
    );
}

static CACHE_PRINCIPAL_ALICE: std::sync::LazyLock<crate::key_server::oidc::VerifiedIdentity> =
    std::sync::LazyLock::new(|| crate::key_server::oidc::VerifiedIdentity {
        subject: "alice".to_string(),
        email: "alice@example.test".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://idp.example.test".to_string(),
    });

static CACHE_PRINCIPAL_BOB: std::sync::LazyLock<crate::key_server::oidc::VerifiedIdentity> =
    std::sync::LazyLock::new(|| crate::key_server::oidc::VerifiedIdentity {
        subject: "bob".to_string(),
        email: "bob@example.test".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://idp.example.test".to_string(),
    });

/// CACHE.4.c — the two principals of 4.b, through the live cache.
///
/// Identity propagation is off, the shipped default, so nothing but the
/// verified subject separates these two callers. Both callers POPULATE: a
/// fixture where one fills the entry and the other only reads it proves
/// nothing about which key the write went to.
#[tokio::test]
async fn ac_cache_4c_two_principals_do_not_share_one_cache_entry() {
    let registry = Arc::new(BackendRegistry::new());
    let (docs, calls) = counting_backend("remote_docs", "SHARED-BODY");
    let _ = registry.register(docs);

    let meta = MetaMcp::with_features(
        registry,
        Some(Arc::new(crate::cache::ResponseCache::new())),
        None,
        None,
        Duration::from_secs(300),
    );
    let invoke = async |identity: &crate::key_server::oidc::VerifiedIdentity| {
        let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
            verified_identity: Some(identity),
            ..allow_all_ctx()
        };
        meta.invoke_tool(
            &json!({"server": "remote_docs", "tool": "search", "arguments": {}}),
            Some("session-1"),
            &caller,
        )
        .await
        .unwrap()
    };

    // Hit control, per principal: one caller twice reaches the backend once.
    invoke(&CACHE_PRINCIPAL_ALICE).await;
    invoke(&CACHE_PRINCIPAL_ALICE).await;
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the same caller repeating a call must be served from cache"
    );

    // Miss half. Every other input is equal by construction, so serving bob
    // from alice's entry is one caller reading another's body.
    invoke(&CACHE_PRINCIPAL_BOB).await;
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "a second authorization identity was served the first caller's cached body"
    );

    // And bob's own entry is now his: a third caller-scoped read hits.
    invoke(&CACHE_PRINCIPAL_BOB).await;
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "bob's own entry must serve his repeat call"
    );
}

// MIK-7272.SUB.4 — what wiring the cache actually buys. The response cache is
// deliberately left out: with one installed, a second identical call is served
// from it and this test would pass with the idempotency guard removed. The only
// thing that can keep the backend at one call here is the guard.
#[tokio::test]
async fn a_reissued_idempotency_key_is_served_from_the_stored_result() {
    let registry = Arc::new(BackendRegistry::new());
    let (payments, calls) = counting_backend("payments", "CHARGED-ONCE");
    let _ = registry.register(payments);

    let mut meta = MetaMcp::with_features(registry, None, None, None, Duration::from_secs(300));
    meta.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        crate::idempotency::CLEANUP_INTERVAL,
    );
    let retry = crate::protocol::mrtr::RetryFields {
        idempotency_key: Some("client-chosen-key".to_string()),
        ..Default::default()
    };
    let mut ctx = allow_all_ctx();
    ctx.retry = &retry;

    let invoke = async || {
        meta.invoke_tool(
            &json!({"server": "payments", "tool": "charge", "arguments": {"cents": 500}}),
            Some("session-1"),
            &ctx,
        )
        .await
        .expect("the charge must succeed")
        .to_string()
    };

    let first = invoke().await;
    let second = invoke().await;

    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the re-issued key must be served from what the first call stored; a \
         second dispatch is the duplicated side effect the key exists to prevent"
    );
    assert!(
        first.contains("CHARGED-ONCE") && second.contains("CHARGED-ONCE"),
        "both replies must carry the backend's own body, not an empty \
         placeholder: first={first}, second={second}"
    );
}
