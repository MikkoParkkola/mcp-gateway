// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend whose shared tool cache was never filled must still become
//! discoverable. Split out for the file-size ceiling.
//!
//! Discovery reads the tool cache and nothing else, and only warm-start
//! prefetches it. A backend left out of a non-empty `meta_mcp.warm_start`, or
//! one whose warm-start gave up, has a never-populated cache, which every
//! collector skipped. Every other fixture in this file warms in arrange
//! precisely so it does not depend on this behaviour; these are deliberately
//! cold, which is the whole point.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

const COLD_BACKEND: &str = "coldstorage_hub";
const COLD_QUERY: &str = "execute_sql_postgres";
const COLD_TOOLS: &[(&str, &str)] = &[
    (
        COLD_QUERY,
        "Run a read-only SELECT against a configured Postgres connection",
    ),
    ("note_read", "read a note"),
];

/// A registered-ready backend over `transport`, cache never filled.
fn cold_backend(
    name: &str,
    transport: Arc<dyn crate::transport::Transport>,
) -> Arc<crate::backend::Backend> {
    cold_backend_with(name, crate::config::BackendConfig::default(), transport)
}

/// [`cold_backend`] under `config`.
fn cold_backend_with(
    name: &str,
    config: crate::config::BackendConfig,
    transport: Arc<dyn crate::transport::Transport>,
) -> Arc<crate::backend::Backend> {
    let backend = Arc::new(crate::backend::Backend::new(
        name,
        config,
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(transport);
    assert!(
        !backend.cached_tools_known(),
        "fixture must start COLD - warming it here is what hides the bug"
    );
    backend
}

/// A gateway with `backend` as its only backend and no restrictions.
fn meta_over(backend: &Arc<crate::backend::Backend>) -> MetaMcp {
    let registry = registry_with_default(
        "open",
        RoutingProfileConfig {
            description: "no backend or tool restrictions".to_string(),
            ..Default::default()
        },
    );
    let backends = Arc::new(BackendRegistry::new());
    assert!(
        backends.register(Arc::clone(backend)),
        "fixture backend failed to register"
    );
    MetaMcp::with_features(
        backends,
        None,
        None,
        Some(Arc::new(SearchRanker::new())),
        Duration::from_secs(60),
    )
    .with_code_mode(false)
    .with_profile_registry(registry)
}

/// A cold backend whose `tools/list` answers with [`COLD_TOOLS`].
fn listing_backend() -> Arc<crate::backend::Backend> {
    let payload: Vec<Value> = COLD_TOOLS
        .iter()
        .map(|(n, d)| json!({ "name": n, "description": d, "inputSchema": { "type": "object" } }))
        .collect();
    cold_backend(
        COLD_BACKEND,
        Arc::new(ToolsListTestTransport {
            tools: json!(payload),
        }),
    )
}

/// Whether `backend`'s shared cache fills within 5 s.
async fn fills(backend: &crate::backend::Backend) -> bool {
    tokio::time::timeout(Duration::from_secs(5), async {
        while backend.get_cached_tools_snapshot().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok()
}

#[tokio::test]
async fn a_cold_backend_becomes_discoverable_after_a_search_fills_it() {
    let backend = listing_backend();
    let meta = meta_over(&backend);

    // First query: the cache is empty, so nothing can be returned yet, and
    // this query does not wait for the fill. It is what asks for one.
    let first = meta
        .search_tools_anon(&json!({ "query": COLD_QUERY }), None)
        .await
        .unwrap();
    assert!(
        tool_names(&first).is_empty(),
        "a cold cache yields no match on the first query"
    );

    assert!(
        fills(&backend).await,
        "search must fill a cold backend's tool cache in the background; \
         without the fix nothing ever fills it and the backend stays unsearchable"
    );

    let second = meta
        .search_tools_anon(&json!({ "query": COLD_QUERY }), None)
        .await
        .unwrap();
    assert_eq!(
        tool_names(&second),
        vec![COLD_QUERY.to_string()],
        "a cold backend must be discoverable once its cache is filled"
    );
}

/// MIK-7962.COLD.1: the SEP-1821 filtered `tools/list` reads the cache
/// directly. A cold backend it skips must be filled behind the read, as
/// discovery does, or a client that only ever lists never sees its tools.
#[cfg(feature = "spec-preview")]
#[tokio::test]
async fn a_filtered_tools_list_fills_a_cold_backend() {
    let backend = listing_backend();
    let meta = meta_over(&backend);
    let listed = |id| {
        let response = meta.handle_tools_list_filtered(
            crate::protocol::RequestId::Number(id),
            COLD_QUERY,
            None,
            crate::gateway::meta_mcp::InvokeScope::allow_all(
                crate::gateway::router::CallerStanding::Admin,
            ),
        );
        let wire = serde_json::to_value(&response).expect("a response serializes");
        wire["result"]["tools"]
            .as_array()
            .expect("a tools array")
            .iter()
            .map(|t| t["name"].as_str().unwrap_or_default().to_owned())
            .collect::<Vec<_>>()
    };
    assert!(listed(1).is_empty(), "nothing is cached on the first read");
    assert!(
        fills(&backend).await,
        "a filtered tools/list must ask for a cold backend's tools"
    );
    assert_eq!(
        listed(2),
        vec![COLD_QUERY.to_string()],
        "served once filled"
    );
}

/// MIK-7962.COLD.1: `gateway_list_servers` counts the cache directly; a cold
/// backend it reports with `tools_known: false` must be filled behind it.
#[tokio::test]
async fn list_servers_fills_a_cold_backend() {
    let backend = listing_backend();
    let meta = meta_over(&backend);
    let listed = meta
        .list_servers(&crate::gateway::meta_mcp::anonymous_caller(), None)
        .await
        .expect("list_servers succeeds");
    assert_eq!(listed["servers"][0]["tools_known"], false, "{listed}");
    assert!(
        fills(&backend).await,
        "list_servers must ask for a cold backend's tools"
    );
    let listed = meta
        .list_servers(&crate::gateway::meta_mcp::anonymous_caller(), None)
        .await
        .expect("list_servers succeeds");
    assert_eq!(
        listed["servers"][0]["tools_count"],
        COLD_TOOLS.len(),
        "counted once filled: {listed}"
    );
}

/// A backend that answers every request with a transport error, counting them.
struct DeadTransport {
    requests: AtomicUsize,
}

#[async_trait::async_trait]
impl crate::transport::Transport for DeadTransport {
    async fn request(
        &self,
        _method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        Err(crate::Error::Transport("connection refused".to_string()))
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

/// The fill a search asks for must not become a `tools/list` per search
/// against a backend that is down: single-flight joins concurrent fills, and
/// the failed fill's cooldown fast-fails the rest without reaching the wire.
#[tokio::test]
async fn a_dead_cold_backend_is_asked_once_across_a_burst_of_searches() {
    let wire = Arc::new(DeadTransport {
        requests: AtomicUsize::new(0),
    });
    let backend = cold_backend(
        COLD_BACKEND,
        Arc::clone(&wire) as Arc<dyn crate::transport::Transport>,
    );
    let meta = meta_over(&backend);

    for _ in 0..5 {
        let response = meta
            .search_tools_anon(&json!({ "query": COLD_QUERY }), None)
            .await
            .unwrap();
        assert!(tool_names(&response).is_empty(), "nothing to serve");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let asked = tokio::time::timeout(Duration::from_secs(5), async {
        while wire.requests.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        asked.is_ok(),
        "search never asked the cold backend for its tools"
    );
    // Room for any straggling fill to reach the wire before counting.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        wire.requests.load(Ordering::SeqCst),
        1,
        "a dead backend must get one tools/list per cooldown, not one per search"
    );
}

/// MIK-7962: the fill behind a cache read goes over the identity-free shared
/// transport, so it must never ask a backend whose catalogue needs a caller's
/// identity (`required` propagation) or one the multi-user guard isolates (a
/// gateway-held OAuth login, INV-2). Credentialed discovery fills those.
#[tokio::test]
async fn a_cache_read_never_fills_an_identity_bound_backend() {
    use crate::config::{BackendConfig, OAuthConfig};
    use crate::identity_propagation::{
        IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
    };

    let required = BackendConfig {
        identity_propagation: Some(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: "ledger".to_string(),
            required: true,
            session_mode: SessionMode::PerUser,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
        ..Default::default()
    };
    let gateway_login = BackendConfig {
        oauth: Some(OAuthConfig {
            enabled: true,
            shared_account: false,
            scopes: vec![],
            client_id: None,
            client_secret: None,
            callback_host: None,
            callback_port: None,
            callback_path: None,
            token_refresh_buffer_secs: 300,
        }),
        ..Default::default()
    };
    for (label, config, multi_user) in [
        ("required identity", required, false),
        ("isolated gateway login", gateway_login, true),
    ] {
        let wire = Arc::new(DeadTransport {
            requests: AtomicUsize::new(0),
        });
        let backend = cold_backend_with(
            COLD_BACKEND,
            config,
            Arc::clone(&wire) as Arc<dyn crate::transport::Transport>,
        );
        let meta = meta_over(&backend);
        meta.set_multi_user(multi_user);

        #[cfg(feature = "spec-preview")]
        let _ = meta.handle_tools_list_filtered(
            crate::protocol::RequestId::Number(1),
            COLD_QUERY,
            None,
            crate::gateway::meta_mcp::InvokeScope::allow_all(
                crate::gateway::router::CallerStanding::Admin,
            ),
        );
        meta.list_servers(&crate::gateway::meta_mcp::anonymous_caller(), None)
            .await
            .expect("list_servers succeeds");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            wire.requests.load(Ordering::SeqCst),
            0,
            "{label}: a cache read sent the shared transport a request"
        );
    }
}

/// Admits no backend; every tool decision would pass, so only admission
/// can keep a backend out.
#[cfg(feature = "spec-preview")]
struct NoBackends;

#[cfg(feature = "spec-preview")]
impl crate::gateway::authz::ToolAuthorizer for NoBackends {
    fn decide<'a>(
        &'a self,
        _target: crate::gateway::authz::ToolTarget<'a>,
    ) -> crate::gateway::authz::Decision<'a> {
        crate::gateway::authz::Decision::of(Ok(()))
    }
    fn admits_backend(&self, _server: &str) -> bool {
        false
    }
    fn transport(&self) -> crate::gateway::authz::Transport {
        crate::gateway::authz::Transport::Test
    }
    fn caller_name(&self) -> Option<&str> {
        None
    }
    fn quota_principal(&self) -> Option<&crate::gateway::auth::QuotaPrincipal> {
        None
    }
}

/// MIK-7962: a filtered `tools/list` from a caller whose scope admits no
/// backend must not ask a cold backend for its tools on that caller's behalf.
#[cfg(feature = "spec-preview")]
#[tokio::test]
async fn a_filtered_tools_list_never_fills_a_backend_the_caller_may_not_see() {
    let wire = Arc::new(DeadTransport {
        requests: AtomicUsize::new(0),
    });
    let backend = cold_backend(
        COLD_BACKEND,
        Arc::clone(&wire) as Arc<dyn crate::transport::Transport>,
    );
    let meta = meta_over(&backend);
    let scope = crate::gateway::meta_mcp::InvokeScope {
        authorizer: &NoBackends,
        is_admin: false,
        api_key_name: None,
        agent_id: None,
        grant_subject: None,
    };
    let _ = meta.handle_tools_list_filtered(
        crate::protocol::RequestId::Number(1),
        COLD_QUERY,
        None,
        scope,
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        wire.requests.load(Ordering::SeqCst),
        0,
        "a backend the caller may not see was asked for its tools"
    );
}
