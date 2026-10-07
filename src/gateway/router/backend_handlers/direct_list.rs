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
use crate::protocol::{JsonRpcResponse, RequestId, Tool};
use crate::trust::project_tool_descriptors_trust_cards;
use tracing::warn;

/// Pages drained before the route reports the catalogue as too long. Defined
/// from the one shared cap (MIK 7570 PAGING.1 design §2.C) so this route and
/// the backend metadata cache drain cannot fall out of step.
pub(super) const DIRECT_LIST_MAX_PAGES: usize = crate::backend::LIST_MAX_PAGES;

/// Drain the upstream catalogue into one `{tools}` result.
///
/// An upstream error on any page is returned as an error only, any `result`
/// beside it dropped; the cap overflow is
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
    // An unreadable list (see `readable_page`), or a page without a tools
    // array, says nothing about which tools exist: it is answered, judged as a
    // truncated listing (it clears no block on a name it did not show, #1441)
    // and never cached, since as a complete empty list it would refuse every
    // `tools/call` as absent.
    let mut unreadable = false;
    // The shortest valid freshness hint of any page: one stale page makes the
    // whole merged list as stale (MIK-8022). A missing or non-numeric hint
    // says nothing and cannot erase another page's. An unreadable page makes
    // the hint 0.
    let mut ttl: Option<u64> = None;
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
        let mut page = dispatch_in_scope(
            backend,
            "tools/list",
            id,
            Some(page_params),
            propagated_headers,
            identity_key,
        )
        .await?;
        if page.error.is_some() {
            // An error frame is forwarded as an error only: a `result` beside
            // it was never judged, so it must not reach the client (#1441).
            page.result = None;
            return Ok(page);
        }
        let readable = readable_page(page.result.as_ref());
        let result = page.result.unwrap_or(Value::Null);
        let items = result.get("tools").and_then(Value::as_array);
        unreadable |= !readable || items.is_none();
        if let Some(hint) = result.get("ttlMs").and_then(Value::as_u64) {
            ttl = Some(ttl.map_or(hint, |shortest| shortest.min(hint)));
        }
        tools.extend(items.into_iter().flatten().cloned());
        match result.get("nextCursor") {
            Some(next) if !next.is_null() => cursor = Some(next.clone()),
            _ => {
                // MIK-7570.SCHEMA.1: the slot `tools/call` is judged against.
                let credential = !propagated_headers.is_empty();
                let listing = if unreadable {
                    crate::backend::Listing::Truncated
                } else {
                    crate::backend::Listing::Complete
                };
                let withheld =
                    backend.remember_listed_tools_as(identity_key, credential, &tools, listing);
                // Dropped here, from the raw list this drain judged, not by a
                // later read of the backend's blocked set, which a concurrent
                // listing may change before the response is sent (#1441).
                tools.retain(|tool| {
                    tool.get("name")
                        .and_then(Value::as_str)
                        .is_none_or(|name| !withheld.contains(name))
                });
                let mut merged = json!({ "tools": tools });
                // A partial list is answered, never offered for caching: a
                // zero hint keeps the shaper from filling in its default.
                let ttl = if unreadable { Some(0) } else { ttl };
                if let Some(ttl) = ttl {
                    merged["ttlMs"] = json!(ttl);
                }
                return Ok(JsonRpcResponse::success(id.clone(), merged));
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

/// A page the metadata fill could read: a string `nextCursor` or none, and
/// `tools` an array, or absent on a page with a cursor. So the last page
/// carries the array.
fn readable_page(result: Option<&Value>) -> bool {
    result.is_some_and(|r| {
        let cursor = r.get("nextCursor").filter(|c| !c.is_null());
        cursor.is_none_or(Value::is_string)
            && match r.get("tools") {
                Some(tools) => tools.is_array(),
                None => r.is_object() && cursor.is_some(),
            }
    })
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
            .emit(crate::gateway::authz::Emit::Silent)
            .is_ok()
    });
}

/// Fill missing MCP tool annotation hints on direct backend `tools/list`
/// responses before returning them to clients.
pub(super) fn normalize_tools_list_response(
    backend: &crate::backend::Backend,
    response: &mut JsonRpcResponse,
) {
    let backend_name = backend.name.as_str();
    if response.error.is_some() {
        // Never forward an unjudged list beside an error (#1441).
        response.result = None;
        return;
    }

    let Some(result) = response.result.as_mut() else {
        return;
    };
    let Some(tools_value) = result.get_mut("tools") else {
        return;
    };

    let Some(items) = tools_value.as_array() else {
        warn!(backend = %backend_name, "Backend tools/list result is not an array");
        return;
    };

    // Element by element: one unparseable descriptor must not forward the
    // whole list verbatim (a bypass). It is dropped, since it cannot be judged
    // and would disclose a name the caller may not invoke (A3).
    let mut tools = Vec::with_capacity(items.len());
    for item in items {
        match serde_json::from_value::<Tool>(item.clone()) {
            Ok(tool) => tools.push(tool),
            Err(e) => {
                warn!(backend = %backend_name, error = %e, "Backend tools/list entry could not be normalized; dropped");
            }
        }
    }

    backend.prepare_judged_tools(&mut tools);

    let server_id = format!("backend:{backend_name}");
    let tools = project_tool_descriptors_trust_cards(&server_id, backend_name, &tools);

    // Rebuilt from an allowlist: `{ "tools": [...] }` and nothing else. An
    // upstream sibling key or cursor could name a withheld tool (A3). The
    // projected descriptors are already JSON values, so building the result
    // has no failure arm to fall through to the unjudged original.
    // The drain's freshness hint survives the rebuild, for the modern shaper
    // to cap (MIK-8022); a legacy delivery removes it again.
    let ttl = result.get("ttlMs").and_then(Value::as_u64);
    *result = crate::trust::tools_list_result_with_trust_cards(tools);
    if let (Some(ttl), Some(object)) = (ttl, result.as_object_mut()) {
        object.insert("ttlMs".to_string(), json!(ttl));
    }
}

#[cfg(test)]
mod tests {
    use super::readable_page;
    use serde_json::json;

    /// Review fold: each page shape the direct list may cache from. Mutants
    /// M38 (accept a non-array `tools`), M39 (accept a page with neither list
    /// nor cursor) and M44 (accept a mistyped cursor) redden it.
    #[test]
    fn only_a_result_object_with_an_array_or_no_tools_is_readable() {
        let rows = [
            (Some(json!({"tools": []})), true),
            (Some(json!({"tools": [{"name": "edit"}]})), true),
            (Some(json!({"nextCursor": "2"})), true),
            (Some(json!({})), false),
            (Some(json!({"nextCursor": null})), false),
            (Some(json!({"nextCursor": 2})), false),
            (Some(json!({"tools": [], "nextCursor": 2})), false),
            (Some(json!({"tools": [], "nextCursor": null})), true),
            (Some(json!({"tools": null, "nextCursor": "2"})), false),
            (Some(json!({"tools": null})), false),
            (Some(json!({"tools": "edit"})), false),
            (Some(json!("tools")), false),
            (Some(serde_json::Value::Null), false),
            (None, false),
        ];
        for (result, readable) in rows {
            assert_eq!(readable_page(result.as_ref()), readable, "{result:?}");
        }
    }
}
