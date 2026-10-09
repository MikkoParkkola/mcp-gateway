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
    /// Sleep before responding.
    delay: std::time::Duration,
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
                if !s.backend.delay.is_zero() {
                    tokio::time::sleep(s.backend.delay).await;
                }
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": req["id"],
                    "result": { "prompts": s.backend.payload, "resources": s.backend.payload },
                })
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

#[tokio::test]
async fn prompts_list_skips_hung_backend_within_timeout() {
    let url = start_mock(MockMcpBackend {
        method: "prompts/list",
        payload: serde_json::json!([]),
        delay: HUNG,
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

/// Fast + hung backends: the fast backend's prompts must be returned within a
/// single aggregation timeout even though the hung backend never answers.
#[tokio::test]
async fn prompts_list_fast_backend_not_stalled_by_hung_one() {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, TransportConfig};

    let fast = start_mock(MockMcpBackend {
        method: "prompts/list",
        payload: serde_json::json!([{ "name": "quick", "description": "fast" }]),
        delay: Duration::ZERO,
    })
    .await;
    let hung = start_mock(MockMcpBackend {
        method: "prompts/list",
        payload: serde_json::json!([]),
        delay: HUNG,
    })
    .await;

    let registry = Arc::new(BackendRegistry::new());
    for (name, url) in [("fast", fast), ("hung", hung)] {
        let config = BackendConfig {
            description: String::new(),
            enabled: true,
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            stop_when_idle_for: None,
            max_frame_bytes: None,
            timeout: BACKEND_TIMEOUT,
            ..BackendConfig::default()
        };
        let backend = Arc::new(Backend::new(
            name,
            config,
            &crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        ));
        let _ = registry.register(backend);
    }

    let meta = MetaMcp::new(registry).with_prompts_resources_fetch_timeout(Duration::from_secs(1));

    // The hung backend's own timeout outlasts the hang guard, so a list held
    // by it fails the guard instead of passing slowly (MIK-8222).
    let resp = tokio::time::timeout(
        HANG_GUARD,
        meta.handle_prompts_list(RequestId::Number(1), None, None, None),
    )
    .await
    .expect("the fast result returns at the aggregation timeout, not the hung backend's own");

    assert!(
        resp.error.is_none(),
        "list still succeeds: {:?}",
        resp.error
    );
    // Both the gateway meta-prompts AND the fast backend's prompt are present;
    // the hung backend was skipped within the bound.
    let result = resp.result.unwrap();
    let prompts = result["prompts"].as_array().unwrap();
    let names: Vec<&str> = prompts
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"gateway/gateway-discover"),
        "meta prompts kept"
    );
    assert!(
        names.contains(&"fast/quick"),
        "fast backend's prompt returned"
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
