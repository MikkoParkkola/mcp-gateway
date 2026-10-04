// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7334.CATALOGUE.1: per-identity tool catalogues.

use super::*;

// ── MIK-7334.CATALOGUE.1 ──────────────────────────────────────────────────
//
// A `session_mode = per_user` backend keeps one transport/session per caller
// identity (`PoolKey::PerUser`, `pool.rs`), and since MIK-7334.CATALOGUE.1 its
// metadata caches live on that same slot. What is fixed below is the OTHER
// half: a reader that presents no identity still resolves `PoolKey::Shared`
// and still shares one catalogue and one fetch with every other such reader.

/// A backend whose upstream answers `tools/list` differently per identity.
///
/// The production metadata path carries no identity, so the only faithful way
/// to model "this backend's catalogue depends on who is asking" is a transport
/// whose answer the test advances between callers — standing in for the
/// per-identity session each caller would own.
struct PerIdentityTools {
    responses: parking_lot::Mutex<Vec<JsonRpcResponse>>,
    requests: AtomicUsize,
    delay: Duration,
}

impl PerIdentityTools {
    fn new(tools_per_identity: &[&str], delay: Duration) -> Self {
        let responses = tools_per_identity
            .iter()
            .rev()
            .map(|name| {
                JsonRpcResponse::success_serialized(
                    RequestId::Number(1),
                    ToolsListResult {
                        tools: vec![sample_tool(name)],
                        next_cursor: None,
                    },
                )
            })
            .collect();
        Self {
            responses: parking_lot::Mutex::new(responses),
            requests: AtomicUsize::new(0),
            delay,
        }
    }
}

#[async_trait]
impl Transport for PerIdentityTools {
    async fn request(&self, method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        assert_eq!(method, "tools/list");
        self.requests.fetch_add(1, Ordering::SeqCst);
        sleep(self.delay).await;
        let next = self.responses.lock().pop();
        next.ok_or_else(|| Error::BackendUnavailable("no further identity".to_string()))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

fn per_user_backend(cache_ttl: Duration) -> Backend {
    use crate::identity_propagation::{
        IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
    };

    Backend::new(
        "test",
        BackendConfig {
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: "aud".to_string(),
                required: true,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..Default::default()
        },
        &crate::config::FailsafeConfig::default(),
        cache_ttl,
    )
}

/// GIVEN a `per_user` backend whose upstream would answer `tools/list`
/// differently per identity
/// WHEN two callers read its catalogue
/// THEN both are served the SAME single answer, because the metadata fetch
/// carries no identity at all.
///
/// `get_tools()` carries no binding, so `pool_key_for` resolves
/// `PoolKey::Shared` and both reads land on the canonical slot. One upstream
/// fetch serving both is the proof — `PerIdentityTools` errors on a second
/// fetch, so a second answer could not be served even if one were asked for.
///
/// SINCE MIK-7334.CATALOGUE.1 THIS IS A CONTROL, NOT A GAP. Per-identity
/// catalogues now exist, and this is what guarantees they were not bought by
/// degrading the identity-free path: the IDP.5 promise that a caller with no
/// binding sees byte-for-byte what it saw before. The per-identity side is
/// asserted in `gateway::meta_mcp::catalogue_per_caller_tests`.
#[tokio::test]
async fn per_user_metadata_fetch_is_identity_free_and_shared() {
    let backend = Arc::new(per_user_backend(Duration::from_secs(60)));
    let transport = Arc::new(PerIdentityTools::new(
        &["alpha_tool", "beta_tool"],
        Duration::from_millis(0),
    ));
    let transport_dyn: Arc<dyn Transport> = transport.clone();
    backend.set_transport_for_test(transport_dyn);

    let seen_by_a = backend.get_tools().await.expect("identity A read");
    let seen_by_b = backend.get_tools().await.expect("identity B read");

    let names = |tools: &[Tool]| -> Vec<String> { tools.iter().map(|t| t.name.clone()).collect() };
    assert_eq!(
        names(&seen_by_a),
        vec!["alpha_tool".to_string()],
        "the first read must be served the static-credential catalogue"
    );
    assert_eq!(
        names(&seen_by_b),
        names(&seen_by_a),
        "the catalogue is not identity-dependent, so every caller gets the same one"
    );
    assert_eq!(
        transport.requests.load(Ordering::SeqCst),
        1,
        "one identity-free upstream fetch backs every caller"
    );
    assert!(
        backend.has_cached_tools(),
        "a per_user backend's catalogue must be cached and discoverable, not blanked"
    );
}

/// GIVEN a per-identity backend whose catalogue fill is in flight
/// WHEN that identity's grant is revoked before the fill lands
/// THEN the revoked identity's catalogue must not be served afterwards.
///
/// `invalidate_tools_cache` is the only production hook that clears this cache,
/// and it clears an EMPTY list only — so a revocation that lands mid-fill
/// cannot evict the entry the fill is about to write.
#[tokio::test]
async fn revocation_during_a_fill_is_not_served_afterwards() {
    let backend = Arc::new(per_user_backend(Duration::from_secs(60)));
    let transport = Arc::new(PerIdentityTools::new(
        &["revoked_tool"],
        Duration::from_millis(50),
    ));
    let transport_dyn: Arc<dyn Transport> = transport.clone();
    backend.set_transport_for_test(transport_dyn);

    let filling = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.get_tools().await })
    };

    // Revocation lands while the fill is still on the wire.
    sleep(Duration::from_millis(10)).await;
    backend.invalidate_tools_cache();

    let _ = filling.await.expect("fill task");

    assert!(
        !backend
            .get_cached_tool_names()
            .contains(&"revoked_tool".to_string()),
        "the revoked identity's catalogue is still served from the cache"
    );
    assert!(
        backend.get_cached_tool("revoked_tool").is_none(),
        "a revoked identity's tool schema is still resolvable"
    );
}

/// GIVEN the same backend and the same in-flight fill
/// WHEN NO revocation lands while it is on the wire
/// THEN the fill IS served afterwards.
///
/// THE ADMITTED-CASE CONTROL for
/// [`revocation_during_a_fill_is_not_served_afterwards`], whose assertions are
/// both absences and so hold against a gateway that caches nothing at all —
/// load-bearing evidence for the revocation half of MIK-7334.CATALOGUE.1.
/// Identical to it but for the `invalidate_tools_cache` call, so the two differ
/// by exactly the mechanism under test.
#[tokio::test]
async fn a_fill_that_is_not_revoked_mid_flight_is_served_afterwards() {
    let backend = Arc::new(per_user_backend(Duration::from_secs(60)));
    let transport = Arc::new(PerIdentityTools::new(
        &["kept_tool"],
        Duration::from_millis(50),
    ));
    let transport_dyn: Arc<dyn Transport> = transport.clone();
    backend.set_transport_for_test(transport_dyn);

    let filling = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.get_tools().await })
    };

    // The revoking case invalidates here; this one does not.
    sleep(Duration::from_millis(10)).await;

    let _ = filling.await.expect("fill task");

    assert!(
        backend
            .get_cached_tool_names()
            .contains(&"kept_tool".to_string()),
        "an un-revoked fill was dropped, so the revoking case above proves only \
         that this cache never serves anything"
    );
    assert!(
        backend.get_cached_tool("kept_tool").is_some(),
        "an un-revoked fill's tool schema is not resolvable"
    );
}
