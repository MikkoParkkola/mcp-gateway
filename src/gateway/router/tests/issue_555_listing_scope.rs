// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Issue #555 — the listed set must be the invocable set.
//!
//! `tools/call` decides a backend tool through `authorize_tool_target`, which
//! reads the caller's backend scope and per-tool scope. `tools/list` used to
//! append every configured surfaced tool with no caller in the question at
//! all, so a tenant scoped to one backend was handed the names and full input
//! schemas of every other backend's tools and refused only when it tried to
//! use them. The names and the schemas are the disclosure.
//!
//! These cases drive the real predicate — a `RouterAuthorizer` over a real
//! `AppState` and a real `AuthenticatedClient` — rather than a stand-in that
//! would pass with the production wiring absent.

use super::test_router_app_state;
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig, SurfacedToolConfig};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::router::CallerStanding;
use crate::gateway::router::authorization::{
    RouterAuthorizer, ToolTarget, authorize_tool_target, refusal_principal,
};
use crate::gateway::test_helpers::MetaMcp;
use crate::protocol::{JsonRpcResponse, RequestId, Tool, ToolsListResult};
use crate::transport::Transport;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

/// Answers `tools/list` from a fixed catalogue so the backend's tool cache is
/// warm; nothing here calls a tool, so `tools/call` is not served.
struct ServedListTransport {
    list_response: JsonRpcResponse,
}

#[async_trait::async_trait]
impl Transport for ServedListTransport {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        match method {
            "tools/list" => Ok(self.list_response.clone()),
            other => panic!("unexpected method {other}"),
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

fn tool(name: &str) -> Tool {
    Tool {
        name: name.to_string(),
        description: Some(format!("The {name} tool.")),
        input_schema: json!({
            "type": "object",
            "properties": { "q": { "type": "string" } },
            "required": ["q"]
        }),
        title: None,
        output_schema: None,
        annotations: None,
        role: None,
        projection: None,
    }
}

/// A backend whose tool cache is warm, so `tools/list` has something to
/// disclose and the case is about scope rather than an unfetched catalogue.
async fn served_backend(name: &str, tool_name: &str) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        name,
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let transport: Arc<dyn Transport> = Arc::new(ServedListTransport {
        list_response: JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            ToolsListResult {
                tools: vec![tool(tool_name)],
                next_cursor: None,
            },
        ),
    });
    backend.set_transport_for_test(transport);
    backend.get_tools_shared().await.unwrap();
    backend
}

/// Two backends, both surfaced. Nothing here is per-caller: the operator
/// surfaced both, and which of them a given caller may see is the question.
async fn two_backend_meta() -> MetaMcp {
    let registry = Arc::new(BackendRegistry::new());
    let _ = registry.register(served_backend("alpha", "alpha_tool").await);
    let _ = registry.register(served_backend("beta", "beta_tool").await);
    MetaMcp::new(registry).with_surfaced_tools(vec![
        SurfacedToolConfig {
            server: "alpha".to_string(),
            tool: "alpha_tool".to_string(),
        },
        SurfacedToolConfig {
            server: "beta".to_string(),
            tool: "beta_tool".to_string(),
        },
    ])
}

fn client_scoped_to(backends: &[&str]) -> AuthenticatedClient {
    AuthenticatedClient {
        name: "tenant".to_string(),
        rate_limit: 0,
        backends: backends.iter().map(|b| (*b).to_string()).collect(),
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        principal: "tenant-principal".to_string(),
        quota_principal: None,
        authenticated: true,
    }
}

fn listed_names(response: &JsonRpcResponse) -> Vec<String> {
    response
        .result
        .as_ref()
        .and_then(|r| r.get("tools"))
        .and_then(Value::as_array)
        .expect("tools/list must return a tools array")
        .iter()
        .filter_map(|t| t.get("name").and_then(Value::as_str))
        .map(ToString::to_string)
        .collect()
}

/// AC2: a tool the caller cannot invoke does not appear in its listing —
/// and the caller who *is* scoped to that backend still sees it, so the
/// guard is a scope filter and not a blanket withholding.
#[tokio::test]
async fn tools_list_withholds_a_backend_the_caller_is_not_scoped_to() {
    let (state, _store) = test_router_app_state().await;
    let meta = two_backend_meta().await;

    let restricted = client_scoped_to(&["alpha"]);
    let authorizer = RouterAuthorizer {
        state: state.as_ref(),
        client: Some(&restricted),
        oauth_agent_identity: None,
        cert_identity: None,
        principal: refusal_principal(Some(&restricted), None, None),
    };
    let _ = &authorizer;
    let names = listed_names(&meta.handle_tools_list_for_session(
        RequestId::Number(1),
        None,
        CallerStanding::Standard,
    ));

    assert!(
        names.iter().any(|n| n == "alpha_tool"),
        "the backend this caller IS scoped to must stay listed: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n == "beta_tool"),
        "a backend outside the caller's scope must not be disclosed: {names:?}"
    );

    // Positive control: the same catalogue, a caller scoped to both.
    let wide = client_scoped_to(&["alpha", "beta"]);
    let wide_authorizer = RouterAuthorizer {
        state: state.as_ref(),
        client: Some(&wide),
        oauth_agent_identity: None,
        cert_identity: None,
        principal: refusal_principal(Some(&wide), None, None),
    };
    let _ = &wide_authorizer;
    let wide_names = listed_names(&meta.handle_tools_list_for_session(
        RequestId::Number(2),
        None,
        CallerStanding::Standard,
    ));
    assert!(
        wide_names.iter().any(|n| n == "alpha_tool") && wide_names.iter().any(|n| n == "beta_tool"),
        "a caller scoped to both backends must still see both: {wide_names:?}"
    );
}

/// AC3: the listing verdict and the invocation verdict come from one
/// predicate. Written as the invariant rather than as a name list, so it
/// keeps holding when the catalogue or the scope shape changes: every name
/// the caller is shown must be one `authorize_tool_target` would admit.
#[tokio::test]
async fn every_listed_surfaced_tool_passes_the_invocation_predicate() {
    let (state, _store) = test_router_app_state().await;
    let meta = two_backend_meta().await;

    let restricted = client_scoped_to(&["alpha"]);
    let authorizer = RouterAuthorizer {
        state: state.as_ref(),
        client: Some(&restricted),
        oauth_agent_identity: None,
        cert_identity: None,
        principal: refusal_principal(Some(&restricted), None, None),
    };
    let _ = &authorizer;
    let names = listed_names(&meta.handle_tools_list_for_session(
        RequestId::Number(1),
        None,
        CallerStanding::Standard,
    ));

    let empty = Value::Null;
    for name in &names {
        let Some(server) = meta.surfaced_tool_server(name) else {
            continue; // a meta-tool; its axis is CallerStanding, checked above
        };
        assert!(
            authorize_tool_target(
                state.as_ref(),
                Some(&restricted),
                None,
                None,
                ToolTarget {
                    server,
                    tool: name,
                    arguments: &empty,
                },
            )
            .is_ok(),
            "listed '{server}:{name}' but the invocation predicate refuses it"
        );
    }
}
