// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The resource and prompt methods stdio serves.
//!
//! Forwarded with no API-key scope and no end-user identity: the process was
//! spawned by its one client, which holds whatever the operator holds. A
//! backend whose identity propagation is `required` is therefore refused here,
//! exactly as on an HTTP request that carries no verified identity.

use serde_json::Value;

use super::STDIO;
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::{JsonRpcResponse, RequestId};

/// Every method [`dispatch`] answers.
pub(super) const METHODS: [&str; 5] = [
    "prompts/list",
    "prompts/get",
    "resources/list",
    "resources/read",
    "resources/templates/list",
];

pub(super) async fn dispatch(
    meta: &MetaMcp,
    method: &str,
    id: RequestId,
    params: Option<&Value>,
) -> JsonRpcResponse {
    match method {
        "prompts/list" => meta.handle_prompts_list(id, params, None, None).await,
        "prompts/get" => meta.handle_prompts_get(id, params, None, None).await,
        "resources/list" => meta.handle_resources_list(id, params, None, None).await,
        "resources/read" => {
            meta.handle_resources_read(id, params, STDIO, None, None)
                .await
        }
        "resources/templates/list" => {
            meta.handle_resources_templates_list(id, params, None, None)
                .await
        }
        other => JsonRpcResponse::error(
            Some(id),
            -32601,
            format!("stdio: '{other}' is not a catalogue method"),
        ),
    }
}
