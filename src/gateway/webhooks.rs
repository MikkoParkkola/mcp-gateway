//! Webhook receiver implementation
//!
//! Receives inbound webhooks from external services (Linear, GitHub, etc.),
//! validates HMAC signatures, transforms payloads, and routes as MCP notifications.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{MethodFilter, on},
};
use serde_json::{Value, json};
use tracing::{debug, error, info, warn};

use super::streaming::{NotificationMultiplexer, TaggedNotification};
use crate::capability::{CapabilityDefinition, WebhookDefinition};
use crate::config::WebhookConfig;
use crate::secrets::SecretResolver;

/// Webhook registry - maps paths to webhook definitions
#[derive(Debug, Clone)]
pub struct WebhookRegistry {
    /// Map of path -> (capability_name, webhook_name, definition)
    webhooks: HashMap<String, (String, String, WebhookDefinition)>,
    /// Global webhook configuration
    config: WebhookConfig,
}

impl WebhookRegistry {
    /// Create a new webhook registry
    #[must_use]
    pub fn new(config: WebhookConfig) -> Self {
        Self {
            webhooks: HashMap::new(),
            config,
        }
    }

    /// Register webhooks from a capability definition
    pub fn register_capability(&mut self, cap: &CapabilityDefinition) {
        for (webhook_name, webhook_def) in &cap.webhooks {
            let full_path = format!("{}{}", self.config.base_path, webhook_def.path);

            info!(
                capability = %cap.name,
                webhook = %webhook_name,
                path = %full_path,
                method = %webhook_def.method,
                "Registered webhook endpoint"
            );

            self.webhooks.insert(
                full_path,
                (cap.name.clone(), webhook_name.clone(), webhook_def.clone()),
            );
        }
    }

    /// Get webhook definition by path
    #[must_use]
    pub fn get(&self, path: &str) -> Option<&(String, String, WebhookDefinition)> {
        self.webhooks.get(path)
    }

    /// Create axum routes for all registered webhooks
    ///
    /// Takes ownership of the multiplexer Arc to satisfy Rust lifetime requirements
    /// for the async handlers that will be spawned.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn create_routes(&self, multiplexer: Arc<NotificationMultiplexer>) -> Router<()> {
        let mut router = Router::new();

        for (path, (cap_name, webhook_name, webhook_def)) in &self.webhooks {
            let state = WebhookHandlerState {
                multiplexer: Arc::clone(&multiplexer),
                capability_name: cap_name.clone(),
                webhook_name: webhook_name.clone(),
                definition: webhook_def.clone(),
                config: self.config.clone(),
            };

            // Determine HTTP method filter
            let method_filter = match webhook_def.method.to_uppercase().as_str() {
                "GET" => MethodFilter::GET,
                "POST" => MethodFilter::POST,
                "PUT" => MethodFilter::PUT,
                "PATCH" => MethodFilter::PATCH,
                "DELETE" => MethodFilter::DELETE,
                _ => MethodFilter::POST, // default to POST
            };

            debug!(path = %path, method = %webhook_def.method, "Adding webhook route");

            router = router.route(path, on(method_filter, webhook_handler).with_state(state));
        }

        router
    }
}

/// State for webhook handlers
#[derive(Clone)]
struct WebhookHandlerState {
    multiplexer: Arc<NotificationMultiplexer>,
    capability_name: String,
    webhook_name: String,
    definition: WebhookDefinition,
    config: WebhookConfig,
}

/// Webhook handler function
async fn webhook_handler(
    State(state): State<WebhookHandlerState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // Parse JSON from raw bytes (keep raw bytes for signature validation)
    let payload: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("Invalid JSON: {e}") })),
            );
        }
    };
    let request_id = uuid::Uuid::new_v4().to_string();

    info!(
        request_id = %request_id,
        capability = %state.capability_name,
        webhook = %state.webhook_name,
        body_len = body.len(),
        "Received webhook"
    );

    // Validate HMAC signature if required
    if state.config.require_signature || state.definition.secret.is_some() {
        if let Err(e) = validate_signature(&headers, &body, &state.definition) {
            warn!(
                request_id = %request_id,
                error = %e,
                "Webhook signature validation failed"
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "Invalid signature",
                    "request_id": request_id
                })),
            );
        }
    }

    // Transform payload to notification
    let notification = match transform_payload(&payload, &state) {
        Ok(notif) => notif,
        Err(e) => {
            error!(
                request_id = %request_id,
                error = %e,
                "Failed to transform webhook payload"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Transformation failed",
                    "request_id": request_id
                })),
            );
        }
    };

    // Send notification if enabled
    if state.definition.notify {
        state.multiplexer.broadcast(notification);
        debug!(request_id = %request_id, "Webhook notification broadcast");
    }

    (
        StatusCode::OK,
        Json(json!({
            "status": "received",
            "request_id": request_id
        })),
    )
}

/// Validate HMAC-SHA256 signature against raw request body bytes
fn validate_signature(
    headers: &HeaderMap,
    raw_body: &[u8],
    definition: &WebhookDefinition,
) -> Result<(), String> {
    let secret = match &definition.secret {
        Some(s) => {
            let resolver = SecretResolver::new();
            resolver.resolve(s).map_err(|e| e.to_string())?
        }
        None => return Err("No secret configured".to_string()),
    };

    let signature_header = match &definition.signature_header {
        Some(h) => h,
        None => return Err("No signature header configured".to_string()),
    };

    let signature_value = headers
        .get(signature_header)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| format!("Missing signature header: {signature_header}"))?;

    // Compute HMAC-SHA256 against raw body bytes (not re-serialized JSON)
    use hmac::Mac;
    use sha2::Sha256;

    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|e| format!("Invalid secret: {e}"))?;

    mac.update(raw_body);
    let computed = mac.finalize().into_bytes();
    let computed_hex = hex::encode(computed);

    // Compare signatures (handle different formats)
    // GitHub: sha256=<hex>
    // Linear: <hex>
    let expected = if let Some(stripped) = signature_value.strip_prefix("sha256=") {
        stripped
    } else {
        signature_value
    };

    if constant_time_eq(computed_hex.as_bytes(), expected.as_bytes()) {
        Ok(())
    } else {
        Err("Signature mismatch".to_string())
    }
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Transform webhook payload to MCP notification
fn transform_payload(
    payload: &Value,
    state: &WebhookHandlerState,
) -> Result<TaggedNotification, String> {
    let transform = &state.definition.transform;

    // Extract event type
    let event_type = if let Some(template) = &transform.event_type {
        extract_template_value(template, payload)?
    } else {
        format!("webhook.{}.{}", state.capability_name, state.webhook_name)
    };

    // Transform data fields
    let mut transformed_data = serde_json::Map::new();
    for (key, template) in &transform.data {
        if let Ok(value) = extract_template_value(template, payload) {
            transformed_data.insert(key.clone(), Value::String(value));
        } else {
            // If extraction fails, try to get the raw value at the path
            if let Some(value) = extract_json_path(template, payload) {
                transformed_data.insert(key.clone(), value.clone());
            }
        }
    }

    // If no transform data specified, use the entire payload
    let data = if transformed_data.is_empty() {
        payload.clone()
    } else {
        Value::Object(transformed_data)
    };

    Ok(TaggedNotification {
        source: state.capability_name.clone(),
        event_type,
        data,
        event_id: None,
    })
}

/// Extract value from template (supports {field.nested} syntax)
fn extract_template_value(template: &str, payload: &Value) -> Result<String, String> {
    let mut result = template.to_string();

    // Find all {field.path} patterns
    let re = regex::Regex::new(r"\{([^}]+)\}").map_err(|e| format!("Invalid regex: {e}"))?;

    for cap in re.captures_iter(template) {
        let path = &cap[1];
        if let Some(value) = extract_json_path(path, payload) {
            let value_str = match value {
                Value::String(s) => s.clone(),
                v => v.to_string(),
            };
            result = result.replace(&format!("{{{path}}}"), &value_str);
        } else {
            return Err(format!("Path not found: {path}"));
        }
    }

    Ok(result)
}

/// Extract value from JSON using dot-notation path (e.g., "data.issue.id")
fn extract_json_path<'a>(path: &str, payload: &'a Value) -> Option<&'a Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = payload;

    for part in parts {
        current = match current {
            Value::Object(map) => map.get(part)?,
            Value::Array(arr) => {
                let index: usize = part.parse().ok()?;
                arr.get(index)?
            }
            _ => return None,
        };
    }

    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_json_path() {
        let json = json!({
            "data": {
                "issue": {
                    "id": "123",
                    "title": "Bug fix"
                }
            },
            "action": "update"
        });

        assert_eq!(
            extract_json_path("data.issue.id", &json),
            Some(&Value::String("123".to_string()))
        );
        assert_eq!(
            extract_json_path("action", &json),
            Some(&Value::String("update".to_string()))
        );
        assert_eq!(extract_json_path("nonexistent", &json), None);
    }

    #[test]
    fn test_extract_template_value() {
        let json = json!({
            "data": { "id": "456" },
            "action": "created"
        });

        let result = extract_template_value("linear.issue.{action}", &json).unwrap();
        assert_eq!(result, "linear.issue.created");

        let result = extract_template_value("ID: {data.id}", &json).unwrap();
        assert_eq!(result, "ID: 456");
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }
}
