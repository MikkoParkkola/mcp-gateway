// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Issue #555 / A3 — a caller is shown a tool, a backend or a count only if it
//! could invoke it (list = invoke).
//!
//! Every cell drives the HTTP router, so the scope under test is the one the
//! auth middleware attached to the request and the verdict is the one the
//! production wiring reaches. Cells written against a new signature would fail
//! to compile, which proves nothing; these compile against the code they
//! indict and fail on an assertion.
//!
//! Fixture: MCP backends `alpha` (`alpha_read`, `alpha_write`) and `beta`
//! (`beta_tool`), all surfaced and cache-warm; capability backend `caps` with
//! `cap_open` (chains to `cap_hidden`), `cap_hidden` and `cap_granted`
//! (personal, owned by and granted to API-key subject `u1`). The global tool
//! policy denies `alpha:alpha_write`.

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

use super::{create_router, test_router_app_state_with_auth};
use crate::backend::Backend;
use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::config::{ApiKeyConfig, AuthConfig, BackendConfig, FailsafeConfig, SurfacedToolConfig};
use crate::gateway::test_helpers::MetaMcp;
use crate::identity_grants::{
    GrantAgent, GrantScope, GrantSubject, IdentityGrant, LocalIdentityGrantStore,
};
use crate::protocol::{JsonRpcResponse, RequestId};

mod backend_scope;
mod direct_route;
mod guide;
mod meta_tools;
mod residuals;

/// Every backend tool the fixture configures, as `(server, tool)`.
pub(super) const CATALOGUE: &[(&str, &str)] = &[
    ("alpha", "alpha_read"),
    ("alpha", "alpha_write"),
    ("beta", "beta_tool"),
    ("caps", "cap_open"),
    ("caps", "cap_hidden"),
    ("caps", "cap_granted"),
];

/// A backend upstream serving a fixed catalogue. `tools/call` on a listed tool
/// answers with text; on anything else it answers "unknown tool" as a JSON-RPC
/// error, which is what an MCP server does for a name it does not have.
pub(super) struct Upstream {
    tools: Vec<&'static str>,
    pub(super) calls: parking_lot::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Upstream {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        match method {
            "tools/list" => Ok(JsonRpcResponse::success(
                id,
                json!({ "tools": self.tools.iter().map(|t| tool_json(t)).collect::<Vec<_>>() }),
            )),
            "tools/call" => {
                let name = params
                    .as_ref()
                    .and_then(|p| p.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                self.calls.lock().push(name.clone());
                if self.tools.contains(&name.as_str()) {
                    Ok(JsonRpcResponse::success(
                        id,
                        json!({ "content": [{ "type": "text", "text": "ok" }] }),
                    ))
                } else {
                    Ok(JsonRpcResponse::error(
                        Some(id),
                        -32602,
                        format!("unknown tool: {name}"),
                    ))
                }
            }
            _ => Ok(JsonRpcResponse::success(id, json!({}))),
        }
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

pub(super) fn tool_json(name: &str) -> Value {
    json!({
        "name": name,
        "description": format!("The {name} tool."),
        "inputSchema": { "type": "object", "properties": { "q": { "type": "string" } } }
    })
}

/// One capability definition file. `extra` is appended under `metadata:`.
fn capability_yaml(name: &str, extra: &str) -> String {
    format!(
        "name: {name}\ndescription: The {name} capability.\nmetadata:\n  category: search\n{extra}\
         providers:\n  primary:\n    service: rest\n    config:\n      base_url: https://example.invalid\n      path: /{name}\n"
    )
}

async fn capability_backend() -> (Arc<CapabilityBackend>, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().expect("capability dir");
    let files = [
        ("cap_open", "  chains_with: [cap_hidden]\n".to_string()),
        ("cap_hidden", String::new()),
        (
            "cap_granted",
            "  exposure: personal\n  identity_owner:\n    authority: api_key\n    subject: u1\n    label: u1\n"
                .to_string(),
        ),
    ];
    for (name, extra) in files {
        std::fs::write(
            dir.path().join(format!("{name}.yaml")),
            capability_yaml(name, &extra),
        )
        .expect("write capability");
    }
    let backend = Arc::new(CapabilityBackend::new(
        "caps",
        Arc::new(CapabilityExecutor::new()),
    ));
    let loaded = backend
        .load_from_directory(dir.path().to_str().expect("utf-8 path"))
        .await
        .expect("load capabilities");
    assert_eq!(loaded, 3, "every fixture capability must load");
    (backend, dir)
}

fn grant_to_u1() -> IdentityGrant {
    IdentityGrant {
        grant_id: "g-u1".to_string(),
        subject: GrantSubject::new("api_key", "u1", Some("u1".to_string())),
        agent: GrantAgent::Any,
        capability: "cap_granted".to_string(),
        tool: None,
        scope: GrantScope::Execute,
        owner: None,
        expires_at: None,
        revoked_at: None,
        provenance: "fixture".to_string(),
        reason: "A3 listing-scope cell".to_string(),
    }
}

pub(super) fn key(name: &str, backends: &[&str]) -> ApiKeyConfig {
    ApiKeyConfig {
        key: name.to_string(),
        name: name.to_string(),
        rate_limit: 0,
        backends: backends.iter().map(|b| (*b).to_string()).collect(),
        allowed_tools: None,
        denied_tools: None,
        admin: false,
    }
}

fn denying(name: &str, denied: &[&str]) -> ApiKeyConfig {
    ApiKeyConfig {
        denied_tools: Some(denied.iter().map(|t| (*t).to_string()).collect()),
        ..key(name, &["*"])
    }
}

/// The API keys every keyed cell draws from. A key's name is also its bearer
/// token and, for identity grants, its subject.
fn keys() -> Vec<ApiKeyConfig> {
    vec![
        key("alpha-key", &["alpha", "caps"]),
        key("alpha-only", &["alpha"]),
        key("both-key", &["alpha", "beta", "caps"]),
        ApiKeyConfig {
            allowed_tools: Some(vec!["alpha_read".to_string()]),
            ..key("read-key", &["*"])
        },
        denying("nowrite-key", &["alpha_write"]),
        denying("nohidden-key", &["cap_hidden"]),
        denying("nocapopen-key", &["cap_open"]),
        key("open-key", &["*"]),
        key("bare-key", &[]),
        key("u1", &["*"]),
        key("u2", &["*"]),
        ApiKeyConfig {
            admin: true,
            ..key("admin-key", &["*"])
        },
    ]
}

/// Whether the fixture gateway authenticates callers.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Auth {
    /// Bearer keys from [`keys`]; a request without one is refused.
    Keys,
    /// Auth off: every caller is anonymous.
    Off,
}

pub(super) struct Fixture {
    pub(super) router: axum::Router,
    pub(super) state: Arc<crate::gateway::router::AppState>,
    pub(super) store: tempfile::TempDir,
    pub(super) caps: tempfile::TempDir,
}

/// Build the fixture gateway. `tune` edits the Meta-MCP before it is frozen
/// into the state, for the cells that need one more knob.
pub(super) async fn fixture_with(auth: Auth, tune: impl FnOnce(MetaMcp) -> MetaMcp) -> Fixture {
    let config = AuthConfig {
        enabled: auth == Auth::Keys,
        api_keys: if auth == Auth::Keys {
            keys()
        } else {
            Vec::new()
        },
        ..Default::default()
    };
    let (mut state, store) = test_router_app_state_with_auth(&config).await;
    let registry = Arc::clone(&state.backends);
    for (name, tools) in [
        ("alpha", vec!["alpha_read", "alpha_write"]),
        ("beta", vec!["beta_tool"]),
    ] {
        let backend = Arc::new(Backend::new(
            name,
            BackendConfig::default(),
            &FailsafeConfig::default(),
            Duration::from_secs(300),
        ));
        backend.set_transport_for_test(Arc::new(Upstream {
            tools,
            calls: parking_lot::Mutex::new(Vec::new()),
        }) as Arc<dyn crate::transport::Transport>);
        backend
            .get_tools_shared()
            .await
            .expect("warm the tool cache");
        assert!(registry.register(backend), "fixture registration");
    }
    let surfaced = CATALOGUE
        .iter()
        .filter(|(_, tool)| *tool != "cap_hidden")
        .map(|(server, tool)| SurfacedToolConfig {
            server: (*server).to_string(),
            tool: (*tool).to_string(),
        })
        .collect();
    let meta = tune(MetaMcp::new(registry).with_surfaced_tools(surfaced));
    let (caps, caps_dir) = capability_backend().await;
    meta.set_capabilities(caps);
    meta.set_identity_grants(LocalIdentityGrantStore::from_grants([grant_to_u1()]));
    let state_mut = Arc::get_mut(&mut state).expect("state is uniquely owned here");
    state_mut.meta_mcp = Arc::new(meta);
    state_mut.tool_policy = Arc::new(crate::security::ToolPolicy::from_config(
        &crate::security::ToolPolicyConfig {
            enabled: true,
            deny: vec!["alpha:alpha_write".to_string()],
            use_default_deny: false,
            ..Default::default()
        },
    ));
    Fixture {
        router: create_router(Arc::clone(&state)),
        state,
        store,
        caps: caps_dir,
    }
}

pub(super) async fn fixture(auth: Auth) -> Fixture {
    fixture_with(auth, |meta| meta).await
}

/// POST one JSON-RPC request to `uri` as `key` (anonymous when `None`).
pub(super) async fn post(
    router: &axum::Router,
    uri: &str,
    key: Option<&str>,
    method: &str,
    params: Value,
) -> (StatusCode, Value) {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(key) = key {
        builder = builder.header("authorization", format!("Bearer {key}"));
    }
    let request = builder
        .body(axum::body::Body::from(
            json!({ "jsonrpc": "2.0", "id": 5, "method": method, "params": params }).to_string(),
        ))
        .expect("request");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// A method on the meta route.
pub(super) async fn rpc(
    router: &axum::Router,
    key: Option<&str>,
    method: &str,
    params: Value,
) -> Value {
    post(router, "/mcp", key, method, params).await.1
}

/// `tools/call` of `name` on the meta route.
pub(super) async fn call_tool(
    router: &axum::Router,
    key: Option<&str>,
    name: &str,
    args: Value,
) -> Value {
    rpc(
        router,
        key,
        "tools/call",
        json!({ "name": name, "arguments": args }),
    )
    .await
}

/// The names `tools/list` served.
pub(super) async fn listed(router: &axum::Router, key: Option<&str>) -> Vec<String> {
    let body = rpc(router, key, "tools/list", json!({})).await;
    body["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list must succeed: {body}"))
        .iter()
        .filter_map(|t| t["name"].as_str().map(str::to_string))
        .collect()
}

/// Whether a call answer is a refusal of the kind list = invoke is about: an
/// authorization refusal or an unknown-tool answer. A failure after the gate
/// admitted the call (an upstream or executor error) is not one.
pub(super) fn refused(body: &Value) -> bool {
    let code = body["error"]["code"].as_i64();
    let text = body.to_string();
    matches!(code, Some(-32003 | -32004 | -32601 | -32600))
        || text.contains("not authorized")
        || text.contains("Identity grant denied")
        || text.contains("Unknown tool")
        || text.contains("blocked by")
        || text.contains("not in the allowlist")
}

/// T1 (ported from #555): a backend outside the caller's scope is not listed.
#[tokio::test]
async fn tools_list_withholds_a_backend_the_caller_is_not_scoped_to() {
    let f = fixture(Auth::Keys).await;
    let names = listed(&f.router, Some("alpha-only")).await;
    assert!(
        names.iter().any(|n| n == "alpha_read"),
        "in-scope tool must stay: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n == "beta_tool"),
        "out-of-scope backend disclosed: {names:?}"
    );
}

/// T2 (positive control, green today): a caller scoped to both still sees
/// both, so T1 is a filter and not a blanket withholding.
#[tokio::test]
async fn tools_list_in_scope_caller_still_sees_its_tools() {
    let f = fixture(Auth::Keys).await;
    let names = listed(&f.router, Some("both-key")).await;
    for tool in ["alpha_read", "beta_tool", "cap_open"] {
        assert!(
            names.iter().any(|n| n == tool),
            "{tool} must be listed: {names:?}"
        );
    }
}

/// T3: the per-key tool scope decides listing as it decides invocation.
#[tokio::test]
async fn tools_list_honours_per_key_tool_scope() {
    let f = fixture(Auth::Keys).await;
    let names = listed(&f.router, Some("read-key")).await;
    assert!(names.iter().any(|n| n == "alpha_read"), "{names:?}");
    for tool in ["alpha_write", "beta_tool", "cap_open"] {
        assert!(
            !names.iter().any(|n| n == tool),
            "{tool} outside the allowlist: {names:?}"
        );
    }
}

/// T4: a global policy denial is not listed, even to an anonymous caller.
#[tokio::test]
async fn tools_list_hides_global_policy_denials_from_anonymous() {
    let f = fixture(Auth::Off).await;
    let names = listed(&f.router, None).await;
    assert!(names.iter().any(|n| n == "alpha_read"), "{names:?}");
    assert!(
        !names.iter().any(|n| n == "alpha_write"),
        "policy denial listed: {names:?}"
    );
}

/// T5 (property): for every surfaced tool, listed ⇔ a direct-name call is not
/// refused. An invariant over the configured set, not a name list.
#[tokio::test]
async fn list_equals_invoke_surfaced() {
    for (auth, key) in [
        (Auth::Keys, Some("alpha-only")),
        (Auth::Keys, Some("admin-key")),
        (Auth::Keys, Some("u2")),
        (Auth::Off, None),
    ] {
        let f = fixture(auth).await;
        let names = listed(&f.router, key).await;
        for (_, tool) in CATALOGUE.iter().filter(|(_, t)| *t != "cap_hidden") {
            let answer = call_tool(&f.router, key, tool, json!({ "q": "x" })).await;
            let is_listed = names.iter().any(|n| n == tool);
            assert_eq!(
                is_listed,
                !refused(&answer),
                "{key:?}: '{tool}' listed={is_listed} but the call answered {answer}"
            );
        }
    }
}
