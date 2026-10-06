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
    use crate::backend::Backend;
    use crate::config::{BackendConfig, FailsafeConfig};

    let backend = Arc::new(Backend::new(
        name,
        BackendConfig::default(),
        &FailsafeConfig::default(),
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
    let _ = meta.handle_tools_list_filtered(
        crate::protocol::RequestId::Number(1),
        COLD_QUERY,
        None,
        crate::gateway::meta_mcp::InvokeScope::allow_all(
            crate::gateway::router::CallerStanding::Admin,
        ),
    );
    assert!(
        fills(&backend).await,
        "a filtered tools/list must ask for a cold backend's tools"
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
