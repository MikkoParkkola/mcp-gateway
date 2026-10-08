// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `DELETE /mcp` session termination, and the retired `/sse` endpoint's answer.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::json;
use tracing::{debug, info};

use super::owner::request_session_owner;
use super::session_id_header;
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::outbound::{OutboundReply, gateway_reply};
use crate::gateway::router::AppState;
use crate::gateway::router::helpers::build_http_response;
use crate::gateway::session_id::session_fp;
use crate::protocol::JsonRpcResponse;

/// DELETE /mcp handler - Session termination
/// Per MCP spec 2025-03-26, clients SHOULD send DELETE to terminate session.
pub(in crate::gateway::router) async fn mcp_delete_handler(
    State(state): State<Arc<AppState>>,
    client: Option<axum::Extension<AuthenticatedClient>>,
    headers: HeaderMap,
    extensions: axum::http::Extensions,
) -> OutboundReply {
    let client = client.map(|axum::Extension(c)| c);
    // Public paths may reach this handler without a validated identity even
    // when authentication is enabled. Their shared anonymous owner is not a
    // credential, so refuse before inspecting any session identifier.
    if state.auth_config.enabled
        && !client
            .as_ref()
            .is_some_and(|c| c.authenticated && !c.principal.is_empty())
    {
        return gateway_reply(crate::gateway::middleware::bearer_unauthorized_response(
            "Session termination requires an authenticated credential.",
        ));
    }
    let session_id = session_id_header(&headers);
    let owner = match request_session_owner(&state, &headers, &extensions, client.as_ref()).await {
        Ok((_, owner)) => owner,
        Err(refusal) => return gateway_reply(refusal),
    };

    let removed = session_id.and_then(|id| state.multiplexer.remove_session_for(id, &owner));
    let status = match (session_id, removed) {
        (Some(id), Some(removed)) => {
            let session = removed.fp();
            info!(session_id = %session, "Session terminated by client");
            // The id is dead from here; what was keyed by it goes too.
            if let Some(ref lifecycle) = state.session_lifecycle {
                lifecycle.on_disconnect(id);
            }
            StatusCode::NO_CONTENT
        }
        (Some(id), None) => {
            let session = session_fp(id);
            debug!(session_id = %session, "No owned session for DELETE");
            StatusCode::NOT_FOUND
        }
        (None, _) => StatusCode::BAD_REQUEST,
    };
    gateway_reply(status)
}

/// Deprecated SSE endpoint handler - surfaces a clear error instead of silent 404
pub(in crate::gateway::router) async fn sse_deprecated_handler() -> impl IntoResponse {
    build_http_response(
        &JsonRpcResponse::error_with_data(
            None,
            -32600,
            "SSE transport is deprecated. Use Streamable HTTP (POST /mcp) instead.",
            json!({
                "migration": "In settings.json, change: \"type\": \"sse\" -> \"type\": \"http\" and \"url\": \"http://localhost:39400/sse\" -> \"url\": \"http://localhost:39400/mcp\"",
                "spec": "https://modelcontextprotocol.io/specification/2025-03-26/basic/transports#streamable-http"
            }),
        ),
        StatusCode::GONE,
    )
}
