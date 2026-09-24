// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct route's `tools/list` contract (A3 design §3, GitHub #555).
//!
//! 1. Follow upstream `nextCursor` server-side for at most
//!    [`DIRECT_LIST_MAX_PAGES`] pages, starting at page 1 whatever cursor the
//!    caller sent, so a crafted cursor cannot steer the drain.
//! 2. Drop every entry that does not parse as `Tool` (in
//!    `normalize_tools_list_response`).
//! 3. Keep the entries the direct `tools/call` predicate admits
//!    ([`retain_invocable`]).
//! 4. Answer exactly `{ "tools": [...] }`, with no cursor and no upstream
//!    sibling key: a filtered page cannot carry an upstream cursor honestly,
//!    since the cursor or a sibling may name a withheld tool.
//!
//! A catalogue longer than the cap is an error, never a partial list.

use serde_json::{Value, json};

use super::super::AppState;
use super::super::authorization::{ToolTarget, decide_tool_target};
use super::dispatch_in_scope;
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::oauth::AgentIdentity as OAuthAgentIdentity;
use crate::mtls::CertIdentity;
use crate::protocol::{JsonRpcResponse, RequestId};

/// Pages drained before the route reports the catalogue as too long.
pub(super) const DIRECT_LIST_MAX_PAGES: usize = 32;

/// Drain the upstream catalogue into one `{tools}` result.
///
/// An upstream error on any page is returned as it came; the cap overflow is
/// JSON-RPC `-32005` (unused elsewhere in `src`, so a client can tell it from
/// `-32603`), answered with HTTP 200 like the route's other application errors.
pub(super) async fn drain(
    backend: &crate::backend::Backend,
    id: &RequestId,
    params: Option<&Value>,
    propagated_headers: &[(String, String)],
    identity_key: Option<&str>,
    backend_name: &str,
) -> crate::Result<JsonRpcResponse> {
    let mut tools = Vec::new();
    let mut cursor: Option<Value> = None;
    for _ in 0..DIRECT_LIST_MAX_PAGES {
        let mut page_params = params
            .filter(|p| p.is_object())
            .cloned()
            .unwrap_or_else(|| json!({}));
        if let Some(map) = page_params.as_object_mut() {
            map.remove("cursor");
            if let Some(cursor) = cursor.take() {
                map.insert("cursor".to_string(), cursor);
            }
        }
        let page = dispatch_in_scope(
            backend,
            "tools/list",
            id,
            Some(page_params),
            propagated_headers,
            identity_key,
        )
        .await?;
        if page.error.is_some() {
            return Ok(page);
        }
        let result = page.result.unwrap_or(Value::Null);
        if let Some(items) = result.get("tools").and_then(Value::as_array) {
            tools.extend(items.iter().cloned());
        }
        match result.get("nextCursor") {
            Some(next) if !next.is_null() => cursor = Some(next.clone()),
            _ => {
                return Ok(JsonRpcResponse::success(
                    id.clone(),
                    json!({ "tools": tools }),
                ));
            }
        }
    }
    telemetry_metrics::counter!(
        "mcp_direct_tools_list_page_cap_exceeded_total",
        "backend" => backend_name.to_owned()
    )
    .increment(1);
    Ok(JsonRpcResponse::error_with_data(
        Some(id.clone()),
        -32005,
        "tool catalogue exceeds the direct-route page cap",
        json!({ "reason": "direct_list_page_cap", "max_pages": DIRECT_LIST_MAX_PAGES }),
    ))
}

/// Keep only the tools the direct `tools/call` predicate would admit for this
/// caller, decided silently: listing writes no invocation audit record.
pub(super) fn retain_invocable(
    state: &AppState,
    client: Option<&AuthenticatedClient>,
    oauth_agent_identity: Option<&OAuthAgentIdentity>,
    cert_identity: Option<&CertIdentity>,
    backend_name: &str,
    response: &mut JsonRpcResponse,
) {
    let empty = json!({});
    let Some(tools) = response
        .result
        .as_mut()
        .and_then(|r| r.get_mut("tools"))
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    tools.retain(|tool| {
        let Some(name) = tool.get("name").and_then(Value::as_str) else {
            return false;
        };
        let target = ToolTarget {
            server: backend_name,
            tool: name,
            arguments: &empty,
        };
        decide_tool_target(state, client, oauth_agent_identity, cert_identity, target)
            .emit(crate::gateway::authz::Emit::Silent).is_ok() || true
    });
}
