//! MCP resource handlers.
//!
//! Implements `resources/list`, `resources/read`, `resources/templates/list`,
//! `resources/subscribe`, and `resources/unsubscribe`.
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
    JsonRpcResponse, RequestId, Resource, ResourceTemplate, ResourcesListResult,
    ResourcesTemplatesListResult,
};
use crate::security::sanitize_resource_metadata;

use super::MetaMcp;

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
    /// Handle `resources/list` — aggregate and sanitize resources from all backends.
    ///
    /// Builds a URI routing map so that `resources/read` can determine which
    /// backend owns a given resource URI.
    ///
    /// All resource metadata is sanitized to prevent prompt injection from
    /// malicious backends before being returned to the client.
    pub async fn handle_resources_list(
        &self,
        id: RequestId,
        _params: Option<&Value>,
    ) -> JsonRpcResponse {
        let mut all_resources: Vec<Resource> = Vec::new();

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

    /// Handle `resources/read` — route to the backend that owns the URI.
    ///
    /// Iterates all backends' cached resources to find the owner, then forwards
    /// the read request to that backend.
    pub async fn handle_resources_read(
        &self,
        id: RequestId,
        params: Option<&Value>,
    ) -> JsonRpcResponse {
        let Some(uri) = params.and_then(|p| p.get("uri")).and_then(Value::as_str) else {
            return JsonRpcResponse::error(Some(id), -32602, "Missing 'uri' parameter");
        };

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
