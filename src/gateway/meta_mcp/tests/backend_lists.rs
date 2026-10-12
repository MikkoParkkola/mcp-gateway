// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Prompt and resource aggregation, and grant-scoped cache entries.

use super::*;

/// How long the hung mock sleeps: past every bound below, so it never answers.
const HUNG: Duration = Duration::from_secs(600);
/// The backend's own per-call timeout: past the hang guard, so only the
/// aggregation timeout can end a list inside it.
const BACKEND_TIMEOUT: Duration = Duration::from_secs(120);
/// The tree's hang bound, and under `MetaMcp`'s own 10 s aggregation default:
/// a list that fell back to that default instead of the configured 100 ms or
/// 1 s fails here too, not only one that waited for the backend. Still 5x
/// the longest configured window, so a loaded runner has room (MIK-8222).
const HANG_GUARD: Duration = Duration::from_secs(5);

// ============================================================================
// Prompts/resources aggregation: parallel fan-out + per-backend timeout
// ============================================================================

/// A minimal streamable-http MCP backend for testing aggregation.
///
/// Responds to `initialize` and to a single configured method (`prompts/list`
/// or `resources/list`) with a configurable payload and latency. Latency is
/// applied before responding so a backend that "hangs" is one whose sleep
/// exceeds the aggregation fetch timeout.
struct MockMcpBackend {
    /// The method this backend answers (`prompts/list` or `resources/list`).
    method: &'static str,
    /// JSON array to return for `method`.
    payload: serde_json::Value,
    /// Sleep before responding, per page.
    delay: std::time::Duration,
    /// How many `nextCursor` pages the list spans; each carries `payload`.
    pages: usize,
    /// The `cursor` of every `method` request, in order (`None` for page 1).
    cursors: std::sync::Arc<std::sync::Mutex<Vec<Option<String>>>>,
}

async fn start_mock(backend: MockMcpBackend) -> String {
    use axum::Json;
    use axum::Router;
    use axum::extract::State;
    use axum::routing::post;

    #[derive(Clone)]
    struct S {
        backend: std::sync::Arc<MockMcpBackend>,
        seen: std::sync::Arc<AtomicUsize>,
    }

    async fn handle(
        State(s): State<S>,
        Json(req): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        let method = req["method"].as_str().unwrap_or("");
        let resp = match method {
            "initialize" => serde_json::json!({
                "jsonrpc": "2.0",
                "id": req["id"],
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {
                        "tools": {"listChanged": true},
                        "prompts": {"listChanged": true},
                        "resources": {"listChanged": true},
                    },
                    "serverInfo": {"name": "mock", "version": "0.1.0"},
                }
            }),
            m if m == s.backend.method => {
                s.seen.fetch_add(1, Ordering::SeqCst);
                let cursor = req["params"]["cursor"].as_str().map(str::to_owned);
                s.backend.cursors.lock().unwrap().push(cursor.clone());
                // Page n (1-based) is asked for with cursor "n"; the first page
                // carries no cursor. A cursor this mock never issued is refused,
                // so a drain that sent a wrong one cannot pass as page 1.
                let page = match cursor.as_deref().map(str::parse::<usize>) {
                    None => 1,
                    Some(Ok(n)) if (2..=s.backend.pages).contains(&n) => n,
                    Some(_) => {
                        return Json(serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": req["id"],
                            "error": { "code": -32602, "message": "cursor not issued" },
                        }));
                    }
                };
                if !s.backend.delay.is_zero() {
                    tokio::time::sleep(s.backend.delay).await;
                }
                // A multi-page list names each page's entries apart, so no
                // merge or dedup can make two pages read as one.
                let mut items = s.backend.payload.clone();
                if s.backend.pages > 1 {
                    for item in items.as_array_mut().into_iter().flatten() {
                        for key in ["name", "uri"] {
                            if let Some(v) = item[key].as_str() {
                                item[key] = serde_json::json!(format!("{v}-p{page}"));
                            }
                        }
                    }
                }
                let mut result = serde_json::json!({ "prompts": items, "resources": items });
                if page < s.backend.pages {
                    result["nextCursor"] = serde_json::json!((page + 1).to_string());
                }
                serde_json::json!({ "jsonrpc": "2.0", "id": req["id"], "result": result })
            }
            _ => serde_json::json!({
                "jsonrpc": "2.0",
                "id": req["id"],
                "error": { "code": -32601, "message": "Method not found" },
            }),
        };
        Json(resp)
    }

    let state = S {
        backend: std::sync::Arc::new(backend),
        seen: std::sync::Arc::new(AtomicUsize::new(0)),
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route("/mcp", post(handle)).with_state(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}/mcp")
}

#[tokio::test]
async fn prompts_list_includes_backend_prompts() {
    let url = start_mock(MockMcpBackend {
        method: "prompts/list",
        payload: serde_json::json!([{ "name": "greet", "description": "say hi" }]),
        delay: Duration::ZERO,
        pages: 1,
        cursors: Arc::default(),
    })
    .await;
    let meta = meta_with_backend(&url, Duration::from_secs(5));

    let resp = meta
        .handle_prompts_list(RequestId::Number(1), None, None, None)
        .await;
    let prompts = resp.result.unwrap()["prompts"].as_array().unwrap().clone();
    let names: Vec<&str> = prompts
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"gateway/gateway-discover"),
        "meta prompts kept"
    );
    assert!(names.contains(&"mock/greet"), "backend prompt namespaced");
}

/// One page's latency in the paged rows: under the backend's timeout alone,
/// over it for two pages together.
// timing-oracle: vs 4.5 s backend timeout (MIK-8285)
const PAGE_DELAY: Duration = Duration::from_secs(3);
/// The paged backend's own per-call timeout: 1.5 pages, so each page clears it
/// by 1.5 s and the two-page drain (6 s) exceeds it while staying 4 s under
/// the 10 s whole-fetch default.
// timing-oracle: vs 10 s whole-fetch default (MIK-8285)
const PAGED_BACKEND_TIMEOUT: Duration = Duration::from_millis(4500);

#[tokio::test]
async fn prompts_list_skips_hung_backend_within_timeout() {
    let url = start_mock(MockMcpBackend {
        method: "prompts/list",
        payload: serde_json::json!([]),
        delay: HUNG,
        pages: 1,
        cursors: Arc::default(),
    })
    .await;
    // The backend's own timeout outlasts the hang guard, so a list that waited
    // for it instead of the 100 ms aggregation timeout fails the guard: the
    // oracle is that the list answers at all (MIK-8222).
    let meta = meta_with_backend_timeout(&url, Duration::from_millis(100), BACKEND_TIMEOUT);

    let resp = tokio::time::timeout(
        HANG_GUARD,
        meta.handle_prompts_list(RequestId::Number(1), None, None, None),
    )
    .await
    .expect("must skip the hung backend at the aggregation timeout, not at the backend's own");

    assert!(
        resp.error.is_none(),
        "list still succeeds: {:?}",
        resp.error
    );
    // Only the gateway meta-prompts remain.
    let result = resp.result.unwrap();
    let prompts = result["prompts"].as_array().unwrap();
    assert_eq!(prompts.len(), 2);
}

#[tokio::test]
async fn resources_list_skips_hung_backend_within_timeout() {
    let url = start_mock(MockMcpBackend {
        method: "resources/list",
        payload: serde_json::json!([]),
        delay: HUNG,
        pages: 1,
        cursors: Arc::default(),
    })
    .await;
    // The backend's own timeout outlasts the hang guard, so a list that waited
    // for it instead of the 100 ms aggregation timeout fails the guard: the
    // oracle is that the list answers at all (MIK-8222).
    let meta = meta_with_backend_timeout(&url, Duration::from_millis(100), BACKEND_TIMEOUT);

    let resp = tokio::time::timeout(
        HANG_GUARD,
        meta.handle_resources_list(RequestId::Number(1), None, None, None),
    )
    .await
    .expect("must skip the hung backend at the aggregation timeout, not at the backend's own");

    assert!(
        resp.error.is_none(),
        "list still succeeds: {:?}",
        resp.error
    );
}

#[tokio::test]
async fn resources_list_includes_backend_resources() {
    let url = start_mock(MockMcpBackend {
        method: "resources/list",
        payload: serde_json::json!([{ "uri": "mock://a", "name": "A" }]),
        delay: Duration::ZERO,
        pages: 1,
        cursors: Arc::default(),
    })
    .await;
    let meta = meta_with_backend(&url, Duration::from_secs(5));

    let resp = meta
        .handle_resources_list(RequestId::Number(1), None, None, None)
        .await;
    let resources = resp.result.unwrap()["resources"]
        .as_array()
        .unwrap()
        .clone();
    let uris: Vec<&str> = resources
        .iter()
        .map(|r| r["uri"].as_str().unwrap())
        .collect();
    assert!(uris.contains(&"mock://a"), "backend resource included");
}

// ============================================================================
// In-process list upstreams on a paused clock (MIK-8360)
// ============================================================================

/// An in-process upstream for one list method: no socket and no client
/// timeout, so on a paused clock every wait in a row is virtual and load
/// cannot move it (MIK-8360).
struct ListWire {
    /// The method this upstream answers (`prompts/list` or `resources/list`).
    method: &'static str,
    /// What each page carries; a multi-page list names each page's entries
    /// apart, as [`MockMcpBackend`] does.
    payload: serde_json::Value,
    /// How many `nextCursor` pages the list spans.
    pages: usize,
    /// A tokio sleep before each page: virtual on a paused clock.
    delay: Duration,
    /// Never answers.
    hung: bool,
    /// The `cursor` of every request, in order (`None` for page 1).
    cursors: Arc<std::sync::Mutex<Vec<Option<String>>>>,
}

impl ListWire {
    fn answering(method: &'static str, payload: serde_json::Value) -> Self {
        Self {
            method,
            payload,
            pages: 1,
            delay: Duration::ZERO,
            hung: false,
            cursors: Arc::default(),
        }
    }

    fn hung(method: &'static str) -> Self {
        Self {
            hung: true,
            ..Self::answering(method, serde_json::json!([]))
        }
    }
}

#[async_trait::async_trait]
impl crate::transport::Transport for ListWire {
    async fn request(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        self.request_with_headers(
            method,
            params,
            &[],
            None,
            crate::transport::ResendPermission::Denied,
        )
        .await
    }

    async fn request_with_headers(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
        _extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
        _resend: crate::transport::ResendPermission,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        if method != self.method {
            return Err(crate::Error::BackendUnavailable(format!(
                "this upstream answers {} only, not {method}",
                self.method
            )));
        }
        if self.hung {
            return std::future::pending().await;
        }
        let cursor = params
            .as_ref()
            .and_then(|p| p["cursor"].as_str())
            .map(str::to_owned);
        self.cursors.lock().unwrap().push(cursor.clone());
        let page = cursor
            .as_deref()
            .map_or(1, |c| c.parse().expect("an issued cursor"));
        tokio::time::sleep(self.delay).await;
        let mut items = self.payload.clone();
        if self.pages > 1 {
            for item in items.as_array_mut().into_iter().flatten() {
                for key in ["name", "uri"] {
                    if let Some(v) = item[key].as_str() {
                        item[key] = serde_json::json!(format!("{v}-p{page}"));
                    }
                }
            }
        }
        let mut result = serde_json::json!({ "prompts": items, "resources": items });
        if page < self.pages {
            result["nextCursor"] = serde_json::json!((page + 1).to_string());
        }
        Ok(crate::protocol::JsonRpcResponse::success(
            RequestId::Number(1),
            result,
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

/// A backend named `name` whose shared slot is `wire`, with `timeout` as its
/// per-call setting. The URL is never dialled.
fn wired(name: &str, wire: ListWire, timeout: Duration) -> Arc<crate::backend::Backend> {
    use crate::config::{BackendConfig, TransportConfig};
    let backend = Arc::new(crate::backend::Backend::new(
        name,
        BackendConfig {
            enabled: true,
            transport: TransportConfig::Http {
                http_url: "http://127.0.0.1:9/mcp".to_string(),
                streamable_http: Some(true),
                protocol_version: None,
            },
            timeout,
            ..BackendConfig::default()
        },
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(wire));
    backend
}

/// Real-time bound on a whole paused-clock row: only a true hang reaches it.
const ROW_HANG_BOUND: Duration = Duration::from_secs(300);

/// [`crate::test_wait::watched_row`] under [`ROW_HANG_BOUND`].
fn paused<F>(row: impl FnOnce() -> F + Send + 'static)
where
    F: std::future::Future<Output = ()>,
{
    crate::test_wait::watched_row(
        ROW_HANG_BOUND,
        "the list never answered: a fetch waited without a bound",
        row,
    );
}

/// Fast + two hung backends (MIK-8360): the fast backend's prompts return
/// within ONE aggregation window although the hung ones never answer. On a
/// paused clock with in-process upstreams, the fast fetch completes with no
/// timer and the hung fetches end at their timeout once every task is idle,
/// so the window is virtual and load cannot move it. Two hung backends make a
/// serial fan-out take two windows whatever the registry order.
#[test]
fn prompts_list_fast_backend_not_stalled_by_hung_ones() {
    paused(|| async {
        tokio::time::pause();
        let window = Duration::from_secs(1);
        let registry = Arc::new(BackendRegistry::new());
        let fast = ListWire::answering(
            "prompts/list",
            serde_json::json!([{ "name": "quick", "description": "fast" }]),
        );
        for backend in [
            wired("fast", fast, BACKEND_TIMEOUT),
            wired("hung1", ListWire::hung("prompts/list"), BACKEND_TIMEOUT),
            wired("hung2", ListWire::hung("prompts/list"), BACKEND_TIMEOUT),
        ] {
            assert!(
                backend
                    .pooled_transport_for_test(&crate::backend::PoolKey::Shared)
                    .is_some_and(|t| t.is_connected()),
                "the in-process upstream is the slot's connected transport"
            );
            assert!(registry.register(backend), "fixture registration");
        }
        let meta = MetaMcp::new(registry).with_prompts_resources_fetch_timeout(window);

        let started = tokio::time::Instant::now();
        let resp = meta
            .handle_prompts_list(RequestId::Number(1), None, None, None)
            .await;
        let took = started.elapsed();

        assert!(
            took >= window && took < window * 2,
            "the hung backends end at one shared window, in parallel: took {took:?}"
        );
        assert!(
            resp.error.is_none(),
            "list still succeeds: {:?}",
            resp.error
        );
        let result = resp.result.unwrap();
        let names: Vec<&str> = result["prompts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p["name"].as_str())
            .collect();
        assert!(
            names.contains(&"gateway/gateway-discover"),
            "meta prompts kept"
        );
        assert!(
            names.contains(&"fast/quick"),
            "fast backend's prompt returned"
        );
        assert!(
            !names.iter().any(|n| n.starts_with("hung")),
            "the hung backends were skipped: {names:?}"
        );
    });
}

/// MIK-8285 FETCHTO.3, on a paused clock (MIK-8360): the whole-fetch bound
/// is the unset 10 s default, not the backend's `timeout`. A cold cache
/// drains two pages that each answer within the backend's timeout but
/// together take longer, and both pages' entries are listed. Reading A
/// (min(backend timeout, 10 s) for the whole fetch) would cut this backend at
/// 4.5 s. The page delays are virtual, so the margins cannot be lost to load.
fn drains_pages_whose_total_exceeds_the_backend_timeout(
    method: &'static str,
    payload: serde_json::Value,
    key: &'static str,
    expected: [&'static str; 2],
) {
    paused(move || async move {
        tokio::time::pause();
        let unset = crate::config::MetaMcpConfig::default().prompts_resources_fetch_timeout;
        assert_eq!(
            unset,
            Duration::from_secs(10),
            "the row's whole-fetch default"
        );
        let wire = ListWire {
            pages: 2,
            delay: PAGE_DELAY,
            ..ListWire::answering(method, payload)
        };
        let cursors = Arc::clone(&wire.cursors);
        let registry = Arc::new(BackendRegistry::new());
        assert!(
            registry.register(wired("mock", wire, PAGED_BACKEND_TIMEOUT)),
            "fixture registration"
        );
        let meta = MetaMcp::new(registry).with_prompts_resources_fetch_timeout(unset);

        let resp = if method == "prompts/list" {
            meta.handle_prompts_list(RequestId::Number(1), None, None, None)
                .await
        } else {
            meta.handle_resources_list(RequestId::Number(1), None, None, None)
                .await
        };
        let field = if method == "prompts/list" {
            "prompts"
        } else {
            "resources"
        };
        let result = resp.result.unwrap();
        let mut listed: Vec<&str> = result[field]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p[key].as_str())
            .filter(|n| n.starts_with("mock"))
            .collect();
        listed.sort_unstable();
        assert_eq!(listed, expected, "both pages, once each");
        assert_eq!(
            *cursors.lock().unwrap(),
            [None, Some("2".to_owned())],
            "page 1 without a cursor, then page 2 by its cursor"
        );
    });
}

#[test]
fn prompts_list_drains_pages_whose_total_exceeds_the_backend_timeout() {
    drains_pages_whose_total_exceeds_the_backend_timeout(
        "prompts/list",
        serde_json::json!([{ "name": "greet", "description": "say hi" }]),
        "name",
        ["mock/greet-p1", "mock/greet-p2"],
    );
}

/// The resources family, which has its own aggregation site.
#[test]
fn resources_list_drains_pages_whose_total_exceeds_the_backend_timeout() {
    drains_pages_whose_total_exceeds_the_backend_timeout(
        "resources/list",
        serde_json::json!([{ "uri": "mock://a", "name": "A" }]),
        "uri",
        ["mock://a-p1", "mock://a-p2"],
    );
}

// ===========================================================================
// MIK-7213.CACHE.4 — a refused caller is refused on a cache hit.
//
// The response cache is read before dispatch. An authorization gate placed
// inside dispatch therefore decides nothing on a hit: the entry is returned
// above it. Staging the entry rather than filling it from a first call keeps
// the backend, and its network, out of the case — what is under test is the
// ORDER of the grant check against the cache read, and nothing else.
// ===========================================================================

/// A capability whose grant admits exactly one agent, a gateway with a
/// response cache, and that cache already holding the answer.
///
/// Returns the gateway and the body staged under the key the invoke path
/// derives, so a test can assert on the body by identity rather than by shape.
async fn meta_with_staged_cache_entry(dir: &tempfile::TempDir) -> (MetaMcp, String) {
    use crate::capability::{CapabilityBackend, CapabilityExecutor};
    use crate::identity_grants::{
        GrantScope, GrantSubject, IdentityGrant, LocalIdentityGrantStore,
    };

    let subject = GrantSubject::new("cloudflare_access", "user-123", None);
    let grant = IdentityGrant {
        grant_id: "grant-user-123-calendar".to_string(),
        subject: subject.clone(),
        agent: mtls_agent("agent-1"),
        capability: "calendar_read".to_string(),
        tool: Some("calendar_read".to_string()),
        scope: GrantScope::Execute,
        owner: Some(subject),
        expires_at: Some(chrono::Utc::now() + crate::duration_bound::delta!(minutes, 5)),
        revoked_at: None,
        provenance: "unit-test".to_string(),
        reason: "prove a cache hit does not outrank the grant".to_string(),
    };

    crate::gateway::test_helpers::write_owner_only(
        dir.path().join("calendar_read.yaml"),
        r#"
fulcrum: "1.0"
name: calendar_read
description: Read a personal calendar
schema:
  input:
    type: object
    properties: {}
  output:
    type: object
    properties:
      ok:
        type: boolean
metadata:
  read_only: true
  exposure: personal
  identity_owner:
    authority: cloudflare_access
    subject: user-123
providers:
  primary:
    service: rest
    config:
      base_url: "https://example.invalid"
      path: /calendar
      method: GET
"#,
    )
    .unwrap();

    let cap_backend = Arc::new(CapabilityBackend::new(
        "personal_caps",
        Arc::new(CapabilityExecutor::new()),
    ));
    cap_backend
        .load_from_directory(dir.path().to_str().unwrap())
        .await
        .unwrap();

    let cache = Arc::new(crate::cache::ResponseCache::new());
    let meta = MetaMcp::with_features(
        Arc::new(BackendRegistry::new()),
        Some(Arc::clone(&cache)),
        None,
        None,
        Duration::from_secs(300),
    )
    .with_identity_grants(LocalIdentityGrantStore::from_grants(vec![grant]));
    meta.set_capabilities(cap_backend);

    // Derived through the same helper the read site uses, with the same inputs
    // that call produces: a key computed a second way would stage an entry no
    // read ever looks for, and the case would pass without proving anything.
    let profile = meta.active_profile(Some("session-1"));
    // The staged entry has to carry the principal the assertions' caller keys
    // on. With no identity propagation and no OIDC, that is the caller's own
    // `GrantSubject` — the same one `grant_ctx` builds — namespaced by the
    // one production helper rather than a second spelling of it here.
    let staged_subject =
        crate::identity_grants::GrantSubject::new("cloudflare_access", "user-123", None);
    let anon = super::Authentication::Anonymous;
    let staged_principal =
        super::support::caller_cache_principal(None, None, Some(&staged_subject), None, anon);
    let key = super::support::response_cache_key_for(
        "personal_caps",
        "calendar_read",
        &json!({}),
        &crate::projection::projection_key_suffix(meta.projection_mode, Some("session-1")),
        &staged_principal,
        &crate::protocol::mrtr::NO_RETRY,
        crate::cache::KeyContext {
            routing_profile: &profile.name,
            protocol_revision: Some(crate::protocol::PROTOCOL_VERSION),
            policy_epoch: 0,
        },
    )
    .expect("a resolved principal has a key");
    let body = "STAGED-CACHED-CALENDAR-BODY";
    assert!(
        cache.set(
            &key,
            json!({"content": [{"type": "text", "text": body}], "isError": false}),
            Duration::from_secs(300),
        ),
        "the staged entry must be accepted, or the control below proves nothing"
    );
    (meta, body.to_string())
}

fn grant_ctx(agent_id: &'static str) -> crate::gateway::meta_mcp::MetaMcpCallerContext<'static> {
    crate::gateway::meta_mcp::MetaMcpCallerContext {
        agent_id: Some(crate::security::ProvenAgentId::for_test(
            agent_id,
            crate::security::ProofSource::MutualTls,
        )),
        agent_declared: None,
        grant_subject: Some(crate::identity_grants::GrantSubject::new(
            "cloudflare_access",
            "user-123",
            None,
        )),
        ..allow_all_ctx()
    }
}

#[tokio::test]
async fn a_cached_entry_is_live_for_the_agent_the_grant_admits() {
    // The control for the case below. Without it, a denial there is equally
    // explained by a key nothing reads, which is the failure mode a staged
    // fixture invites.
    let dir = tempfile::TempDir::new().unwrap();
    let (meta, body) = meta_with_staged_cache_entry(&dir).await;
    let result = meta
        .invoke_tool(
            &json!({"server": "personal_caps", "tool": "calendar_read", "arguments": {}}),
            Some("session-1"),
            &grant_ctx("agent-1"),
        )
        .await
        .unwrap();
    assert!(
        serde_json::to_string(&result).unwrap().contains(&body),
        "the staged entry must be served to the admitted agent, or the key is \
         wrong and the denial case proves nothing: {result:#}"
    );
}

#[tokio::test]
async fn a_denied_agent_is_not_served_the_cached_body() {
    let dir = tempfile::TempDir::new().unwrap();
    let (meta, body) = meta_with_staged_cache_entry(&dir).await;
    let result = meta
        .invoke_tool(
            &json!({"server": "personal_caps", "tool": "calendar_read", "arguments": {}}),
            Some("session-1"),
            &grant_ctx("agent-2"),
        )
        .await;

    // A refusal, not a body. The grant is now decided beside the authorizer's
    // own refusal, so it carries the authorizer's shape: an error the caller
    // cannot mistake for an answer, rather than a result envelope.
    let err = result.expect_err("a refused caller must not receive a result");
    let text = err.to_string();
    assert!(
        !text.contains(&body),
        "an agent the grant refuses was handed the cached answer: {text}"
    );
    assert!(text.contains("Identity grant denied"), "{text}");
}
