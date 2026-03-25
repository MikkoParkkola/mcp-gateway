//! MCP resource handlers.
//!
//! Implements `resources/list`, `resources/read`, `resources/templates/list`,
//! `resources/subscribe`, and `resources/unsubscribe`.
//!
//! Gateway-owned guide resources (URIs prefixed `gateway://`) are served
//! inline without hitting any backend, prepended to every `resources/list`
//! response so clients always have access to quickstart and routing docs.
//!
//! # Security
//!
//! Resource metadata (URI, title, description) returned by backend servers is
//! sanitized before being forwarded to the client.  A compromised or malicious
//! backend could embed prompt-injection strings, template markers (`{}`), or
//! control characters in these fields.  [`crate::security::sanitize_resource_metadata`]
//! escapes all such vectors before the data reaches the client prompt.

use std::sync::Arc;

use serde_json::{Value, json};
use tracing::warn;

use crate::protocol::{
    JsonRpcResponse, RequestId, Resource, ResourceContents, ResourceTemplate,
    ResourcesListResult, ResourcesTemplatesListResult,
};
use crate::security::sanitize_resource_metadata;

use super::MetaMcp;

// ============================================================================
// Gateway-owned guide resources (served inline — no backend required)
// ============================================================================

const URI_QUICKSTART: &str = "gateway://guides/quickstart";
const URI_ROUTING: &str = "gateway://guides/routing";

/// Metadata for all gateway-owned static guide resources.
///
/// Returned as the first entries in every `resources/list` response so LLM
/// clients discover the guides without a separate search step.
fn guide_resources() -> [Resource; 2] {
    [
        Resource {
            uri: URI_QUICKSTART.to_string(),
            name: "gateway-quickstart".to_string(),
            title: Some("Gateway Quickstart Guide".to_string()),
            description: Some(
                "Search-first pattern, gateway_invoke routing, and cost tracking explained."
                    .to_string(),
            ),
            mime_type: Some("text/plain".to_string()),
            size: None,
        },
        Resource {
            uri: URI_ROUTING.to_string(),
            name: "gateway-routing".to_string(),
            title: Some("Gateway Routing Guide".to_string()),
            description: Some(
                "Backend categories, composition chains, and routing profiles."
                    .to_string(),
            ),
            mime_type: Some("text/plain".to_string()),
            size: None,
        },
    ]
}

/// Content for the quickstart guide resource.
fn quickstart_content() -> String {
    "\
# MCP Gateway — Quickstart Guide

## Search-first pattern

Never guess a tool name. Always discover before invoking:

  1. gateway_search_tools(query=\"<keyword>\")
     Returns ranked matches with descriptions and scores.

  2. gateway_invoke(server=\"<server>\", tool=\"<tool>\", arguments={...})
     Routes through auth, rate-limit, caching, and failsafe middleware.

Example:

  gateway_search_tools(query=\"web search\")
  => [{\"server\": \"brave\", \"tool\": \"brave_web_search\", ...}]

  gateway_invoke(server=\"brave\", tool=\"brave_web_search\",
                 arguments={\"query\": \"Rust async runtimes\"})

## Cost tracking

Each gateway_invoke records spend automatically.
Query current session cost with:

  gateway_cost_report()

Query aggregate statistics (cache hit rate, token savings) with:

  gateway_get_stats()

## Discovery shortcuts

  gateway_list_servers()       — all backends with status and tool count
  gateway_list_tools(server=X) — tools on a specific backend
  gateway_search_tools(query=\"*\") — list all tools (use sparingly)
"
    .to_string()
}

/// Content for the routing guide resource.
fn routing_content() -> String {
    "\
# MCP Gateway — Routing Guide

## Backend categories

Tools are grouped by category in the routing instructions delivered at
initialize time.  Use the category name as a search keyword to narrow
results quickly.

Common categories and example tools:
  search       — brave_web_search, exa_search, reddit_search
  llm          — openrouter_generate, deepseek_generate, groq_generate
  productivity — notion_get_page, linear_get_issue, github_integration
  finance      — finnhub_quote, sec_edgar_filings, polygon_ohlcv
  media        — screenshot_url, audio_transcribe, audio_tts
  security     — virustotal_scan, shodan_host, urlscan_result

## Composition chains

Some tools declare downstream tools they commonly feed into.  These
\"chains_with\" hints appear in gateway_search_tools results and in the
routing instructions.  Follow them to build efficient multi-step pipelines
without extra search round-trips.

Example chain:
  linear_create_issue -> linear_get_issue -> linear_add_comment

## Routing profiles

A routing profile restricts the visible toolset to the current task,
reducing noise and accidental invocations of unrelated backends.

  gateway_list_profiles()          — see available profiles
  gateway_set_profile(profile=X)  — activate a profile for this session
  gateway_get_profile()            — show current active profile

## Kill switch and recovery

If a backend misbehaves you can stop routing to it immediately:
  gateway_kill_server(server=X)
  gateway_revive_server(server=X)  — re-enables and resets error budget
"
    .to_string()
}

/// Attempt to serve a gateway-owned guide resource by URI.
///
/// Returns `Some(JsonRpcResponse)` when the URI matches a known guide;
/// `None` when the URI belongs to a backend and should be routed normally.
fn try_serve_guide(id: RequestId, uri: &str) -> Option<JsonRpcResponse> {
    let text = match uri {
        URI_QUICKSTART => quickstart_content(),
        URI_ROUTING => routing_content(),
        _ => return None,
    };
    let contents = vec![ResourceContents::Text {
        uri: uri.to_string(),
        mime_type: Some("text/plain".to_string()),
        text,
    }];
    Some(JsonRpcResponse::success(
        id,
        json!({ "contents": contents }),
    ))
}

/// Apply metadata sanitization to a [`Resource`] returned by a backend.
///
/// On error (e.g. null byte in URI), the resource is dropped and a warning
/// is emitted rather than propagating the error or crashing the list handler.
fn sanitize_resource(r: Resource, backend: &str) -> Option<Resource> {
    match sanitize_resource_metadata(&r.uri, r.title.as_deref(), r.description.as_deref()) {
        Ok(clean) => Some(Resource {
            uri: clean.uri,
            name: r.name,
            title: clean.title,
            description: clean.description,
            mime_type: r.mime_type,
            size: r.size,
        }),
        Err(e) => {
            warn!(
                backend = %backend,
                uri = %r.uri,
                error = %e,
                "Dropping resource: metadata sanitization failed"
            );
            None
        }
    }
}

impl MetaMcp {
    /// Handle `resources/list` — gateway guide resources + aggregated backend resources.
    ///
    /// Gateway-owned guide resources (URIs prefixed `gateway://`) are prepended
    /// so clients always discover them first without depending on any backend.
    /// All backend resource metadata is sanitized to prevent prompt injection.
    ///
    /// # Panics
    ///
    /// Panics if `ResourcesListResult` fails to serialize to JSON, which cannot
    /// occur in practice as the type derives `Serialize` with no fallible fields.
    pub async fn handle_resources_list(
        &self,
        id: RequestId,
        _params: Option<&Value>,
    ) -> JsonRpcResponse {
        // Prepend gateway-owned guides (served inline, no backend required).
        let mut all_resources: Vec<Resource> = guide_resources().into();

        for backend in self.backends.all() {
            match backend.get_resources().await {
                Ok(resources) => {
                    for resource in resources {
                        if let Some(clean) = sanitize_resource(resource, &backend.name) {
                            all_resources.push(clean);
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        backend = %backend.name,
                        error = %e,
                        "Failed to fetch resources from backend"
                    );
                }
            }
        }

        let result = ResourcesListResult {
            resources: all_resources,
            next_cursor: None,
        };
        JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
    }

    /// Handle `resources/read` — gateway guide resources take priority, then backend routing.
    ///
    /// Gateway-owned `gateway://` URIs are served inline without forwarding to any
    /// backend.  All other URIs are routed to the backend that owns them.
    pub async fn handle_resources_read(
        &self,
        id: RequestId,
        params: Option<&Value>,
    ) -> JsonRpcResponse {
        let Some(uri) = params.and_then(|p| p.get("uri")).and_then(Value::as_str) else {
            return JsonRpcResponse::error(Some(id), -32602, "Missing 'uri' parameter");
        };

        // Gateway-owned guides are served inline — no backend round-trip.
        if let Some(response) = try_serve_guide(id.clone(), uri) {
            return response;
        }

        // Find which backend owns this resource URI
        let Some(backend) = self.find_resource_owner(uri).await else {
            return JsonRpcResponse::error(
                Some(id),
                -32002,
                format!("No backend found for resource URI: {uri}"),
            );
        };

        match backend
            .request("resources/read", Some(json!({ "uri": uri })))
            .await
        {
            Ok(resp) => {
                if let Some(error) = resp.error {
                    JsonRpcResponse::error(Some(id), error.code, error.message)
                } else {
                    JsonRpcResponse::success(id, resp.result.unwrap_or(json!({"contents": []})))
                }
            }
            Err(e) => JsonRpcResponse::error(Some(id), e.to_rpc_code(), e.to_string()),
        }
    }

    /// Handle `resources/templates/list` — aggregate templates from all backends.
    pub async fn handle_resources_templates_list(
        &self,
        id: RequestId,
        _params: Option<&Value>,
    ) -> JsonRpcResponse {
        let mut all_templates: Vec<ResourceTemplate> = Vec::new();

        for backend in self.backends.all() {
            match backend.get_resource_templates().await {
                Ok(templates) => {
                    all_templates.extend(templates);
                }
                Err(e) => {
                    warn!(
                        backend = %backend.name,
                        error = %e,
                        "Failed to fetch resource templates from backend"
                    );
                }
            }
        }

        let result = ResourcesTemplatesListResult {
            resource_templates: all_templates,
            next_cursor: None,
        };
        JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
    }

    /// Handle `resources/subscribe` — route to the backend that owns the URI.
    pub async fn handle_resources_subscribe(
        &self,
        id: RequestId,
        params: Option<&Value>,
    ) -> JsonRpcResponse {
        let Some(uri) = params.and_then(|p| p.get("uri")).and_then(Value::as_str) else {
            return JsonRpcResponse::error(Some(id), -32602, "Missing 'uri' parameter");
        };

        let Some(backend) = self.find_resource_owner(uri).await else {
            return JsonRpcResponse::error(
                Some(id),
                -32002,
                format!("No backend found for resource URI: {uri}"),
            );
        };

        match backend
            .request("resources/subscribe", Some(json!({ "uri": uri })))
            .await
        {
            Ok(resp) => {
                if let Some(error) = resp.error {
                    JsonRpcResponse::error(Some(id), error.code, error.message)
                } else {
                    JsonRpcResponse::success(id, resp.result.unwrap_or(json!({})))
                }
            }
            Err(e) => JsonRpcResponse::error(Some(id), e.to_rpc_code(), e.to_string()),
        }
    }

    /// Handle `resources/unsubscribe` — route to the backend that owns the URI.
    pub async fn handle_resources_unsubscribe(
        &self,
        id: RequestId,
        params: Option<&Value>,
    ) -> JsonRpcResponse {
        let Some(uri) = params.and_then(|p| p.get("uri")).and_then(Value::as_str) else {
            return JsonRpcResponse::error(Some(id), -32602, "Missing 'uri' parameter");
        };

        let Some(backend) = self.find_resource_owner(uri).await else {
            return JsonRpcResponse::error(
                Some(id),
                -32002,
                format!("No backend found for resource URI: {uri}"),
            );
        };

        match backend
            .request("resources/unsubscribe", Some(json!({ "uri": uri })))
            .await
        {
            Ok(resp) => {
                if let Some(error) = resp.error {
                    JsonRpcResponse::error(Some(id), error.code, error.message)
                } else {
                    JsonRpcResponse::success(id, resp.result.unwrap_or(json!({})))
                }
            }
            Err(e) => JsonRpcResponse::error(Some(id), e.to_rpc_code(), e.to_string()),
        }
    }

    /// Find which backend owns a given resource URI by checking cached resources.
    pub(super) async fn find_resource_owner(
        &self,
        uri: &str,
    ) -> Option<Arc<crate::backend::Backend>> {
        for backend in self.backends.all() {
            if let Ok(resources) = backend.get_resources().await
                && resources.iter().any(|r| r.uri == uri)
            {
                return Some(backend);
            }
        }
        None
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::RequestId;

    #[test]
    fn guide_resources_returns_exactly_two_entries() {
        // GIVEN/WHEN: calling guide_resources()
        // THEN: exactly 2 resources are returned
        let resources = guide_resources();
        assert_eq!(resources.len(), 2);
    }

    #[test]
    fn guide_resources_have_expected_uris() {
        // GIVEN/WHEN: calling guide_resources()
        // THEN: URIs match the quickstart and routing constants
        let resources = guide_resources();
        assert_eq!(resources[0].uri, URI_QUICKSTART);
        assert_eq!(resources[1].uri, URI_ROUTING);
    }

    #[test]
    fn guide_resources_have_plain_text_mime_type() {
        // GIVEN/WHEN: calling guide_resources()
        // THEN: both resources advertise text/plain MIME type
        for resource in guide_resources() {
            assert_eq!(
                resource.mime_type.as_deref(),
                Some("text/plain"),
                "resource {} must have text/plain MIME",
                resource.uri
            );
        }
    }

    #[test]
    fn try_serve_guide_returns_some_for_quickstart_uri() {
        // GIVEN: quickstart URI
        // WHEN: calling try_serve_guide
        // THEN: Some(response) is returned
        let id = RequestId::Number(1);
        let response = try_serve_guide(id, URI_QUICKSTART);
        assert!(response.is_some());
    }

    #[test]
    fn try_serve_guide_returns_some_for_routing_uri() {
        // GIVEN: routing URI
        // WHEN: calling try_serve_guide
        // THEN: Some(response) is returned
        let id = RequestId::Number(2);
        let response = try_serve_guide(id, URI_ROUTING);
        assert!(response.is_some());
    }

    #[test]
    fn try_serve_guide_returns_none_for_unknown_uri() {
        // GIVEN: an unknown URI
        // WHEN: calling try_serve_guide
        // THEN: None is returned (falls through to backend routing)
        let id = RequestId::Number(3);
        let response = try_serve_guide(id, "gateway://unknown/resource");
        assert!(response.is_none());
    }

    #[test]
    fn try_serve_guide_response_contains_contents_array() {
        // GIVEN: quickstart URI
        // WHEN: serving the guide
        // THEN: the result JSON has a non-empty "contents" array
        let id = RequestId::Number(4);
        let resp = try_serve_guide(id, URI_QUICKSTART).unwrap();
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert!(result["contents"].is_array());
        assert!(!result["contents"].as_array().unwrap().is_empty());
    }

    #[test]
    fn quickstart_content_mentions_search_first_pattern() {
        // GIVEN/WHEN: generating quickstart guide text
        // THEN: search-first keyword appears
        let content = quickstart_content();
        assert!(content.contains("gateway_search_tools"));
        assert!(content.contains("gateway_invoke"));
    }

    #[test]
    fn routing_content_mentions_backend_categories() {
        // GIVEN/WHEN: generating routing guide text
        // THEN: category keywords and profile commands appear
        let content = routing_content();
        assert!(content.contains("gateway_set_profile"));
        assert!(content.contains("gateway_list_profiles"));
        assert!(content.contains("chains_with"));
    }
}
