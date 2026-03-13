//! Webhook receiver implementation
//!
//! Receives inbound webhooks from external services (Linear, GitHub, etc.),
//! validates HMAC signatures, transforms payloads, and routes as MCP notifications.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{MethodFilter, on},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{debug, error, info, warn};

use hmac::Mac as _;
use sha2::Sha256;

use super::streaming::{NotificationMultiplexer, TaggedNotification};
use crate::capability::{CapabilityDefinition, WebhookDefinition};
use crate::config::WebhookConfig;
use crate::secrets::SecretResolver;

// ============================================================================
// Stats types
// ============================================================================

/// Per-endpoint delivery statistics (lock-free atomics).
#[derive(Debug, Default)]
pub struct EndpointStats {
    /// Total events received (any status)
    pub received: AtomicU64,
    /// Events successfully broadcast to at least one SSE session
    pub delivered: AtomicU64,
    /// Events that failed signature validation
    pub signature_failures: AtomicU64,
    /// Events that failed payload transformation
    pub transform_failures: AtomicU64,
    /// Unix timestamp (seconds) of the most recent received event
    pub last_received_at: AtomicU64,
}

impl EndpointStats {
    /// Snapshot all counters into a serializable struct.
    #[must_use]
    pub fn snapshot(&self) -> EndpointStatsSnapshot {
        let last_ts = self.last_received_at.load(Ordering::Relaxed);
        EndpointStatsSnapshot {
            received: self.received.load(Ordering::Relaxed),
            delivered: self.delivered.load(Ordering::Relaxed),
            signature_failures: self.signature_failures.load(Ordering::Relaxed),
            transform_failures: self.transform_failures.load(Ordering::Relaxed),
            last_received_at: if last_ts > 0 { Some(last_ts) } else { None },
        }
    }

    fn record_received(&self) {
        self.received.fetch_add(1, Ordering::Relaxed);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_received_at.store(ts, Ordering::Relaxed);
    }
}

/// Serializable snapshot of endpoint statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointStatsSnapshot {
    /// Total events received
    pub received: u64,
    /// Events broadcast to SSE clients
    pub delivered: u64,
    /// Signature validation failures
    pub signature_failures: u64,
    /// Payload transformation failures
    pub transform_failures: u64,
    /// Unix timestamp of last received event (`None` if never received)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_received_at: Option<u64>,
}

// ============================================================================
// Registry
// ============================================================================

/// Registered webhook endpoint info (for status reporting).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEndpointInfo {
    /// Full URL path (including base prefix)
    pub path: String,
    /// HTTP method
    pub method: String,
    /// Source capability name
    pub capability: String,
    /// Logical webhook name within the capability
    pub webhook_name: String,
    /// Whether HMAC validation is configured
    pub signature_required: bool,
    /// Whether notifications are broadcast to SSE clients
    pub notify: bool,
    /// Current delivery statistics
    pub stats: EndpointStatsSnapshot,
}

/// Webhook registry - maps paths to webhook definitions and per-endpoint stats.
#[derive(Debug)]
pub struct WebhookRegistry {
    /// Map of path -> (`capability_name`, `webhook_name`, definition, stats)
    webhooks: HashMap<String, (String, String, WebhookDefinition, Arc<EndpointStats>)>,
    /// Global webhook configuration
    config: WebhookConfig,
}

impl WebhookRegistry {
    /// Create a new webhook registry.
    #[must_use]
    pub fn new(config: WebhookConfig) -> Self {
        Self {
            webhooks: HashMap::new(),
            config,
        }
    }

    /// Register webhooks from a capability definition.
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
                (
                    cap.name.clone(),
                    webhook_name.clone(),
                    webhook_def.clone(),
                    Arc::new(EndpointStats::default()),
                ),
            );
        }
    }

    /// Get webhook definition and stats by path.
    #[must_use]
    pub fn get(
        &self,
        path: &str,
    ) -> Option<&(String, String, WebhookDefinition, Arc<EndpointStats>)> {
        self.webhooks.get(path)
    }

    /// Return status info for all registered endpoints, sorted by path.
    #[must_use]
    pub fn list_endpoints(&self) -> Vec<WebhookEndpointInfo> {
        let mut endpoints: Vec<WebhookEndpointInfo> = self
            .webhooks
            .iter()
            .map(|(path, (cap, name, def, stats))| WebhookEndpointInfo {
                path: path.clone(),
                method: def.method.clone(),
                capability: cap.clone(),
                webhook_name: name.clone(),
                signature_required: def.secret.is_some(),
                notify: def.notify,
                stats: stats.snapshot(),
            })
            .collect();
        endpoints.sort_by(|a, b| a.path.cmp(&b.path));
        endpoints
    }

    /// Total number of registered endpoints.
    #[must_use]
    pub fn endpoint_count(&self) -> usize {
        self.webhooks.len()
    }

    /// Create axum routes for all registered webhooks.
    ///
    /// Takes ownership of the multiplexer Arc to satisfy Rust lifetime requirements
    /// for the async handlers that will be spawned.
    #[must_use = "the returned Router must be merged into the application router"]
    #[allow(clippy::needless_pass_by_value)]
    pub fn create_routes(&self, multiplexer: Arc<NotificationMultiplexer>) -> Router<()> {
        let mut router = Router::new();

        for (path, (cap_name, webhook_name, webhook_def, stats)) in &self.webhooks {
            let state = WebhookHandlerState {
                multiplexer: Arc::clone(&multiplexer),
                capability_name: cap_name.clone(),
                webhook_name: webhook_name.clone(),
                definition: webhook_def.clone(),
                config: self.config.clone(),
                stats: Arc::clone(stats),
            };

            let method_filter = method_to_filter(&webhook_def.method);

            debug!(path = %path, method = %webhook_def.method, "Adding webhook route");

            router = router.route(path, on(method_filter, webhook_handler).with_state(state));
        }

        router
    }
}

// ============================================================================
// Handler
// ============================================================================

/// State for webhook handlers.
#[derive(Clone)]
struct WebhookHandlerState {
    multiplexer: Arc<NotificationMultiplexer>,
    capability_name: String,
    webhook_name: String,
    definition: WebhookDefinition,
    config: WebhookConfig,
    stats: Arc<EndpointStats>,
}

/// Map HTTP method string to axum `MethodFilter`.
///
/// Defaults to POST for unrecognised method strings.
fn method_to_filter(method: &str) -> MethodFilter {
    match method.to_uppercase().as_str() {
        "GET" => MethodFilter::GET,
        "PUT" => MethodFilter::PUT,
        "PATCH" => MethodFilter::PATCH,
        "DELETE" => MethodFilter::DELETE,
        _ => MethodFilter::POST, // POST and any unknown method
    }
}

/// Webhook handler function.
async fn webhook_handler(
    State(state): State<WebhookHandlerState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // Parse JSON from raw bytes (keep raw bytes for signature validation).
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

    state.stats.record_received();

    info!(
        request_id = %request_id,
        capability = %state.capability_name,
        webhook = %state.webhook_name,
        body_len = body.len(),
        "Received webhook"
    );

    // Validate HMAC signature if required.
    if (state.config.require_signature || state.definition.secret.is_some())
        && let Err(e) = validate_signature(&headers, &body, &state.definition)
    {
        state
            .stats
            .signature_failures
            .fetch_add(1, Ordering::Relaxed);
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

    // Transform payload to notification.
    let notification = match transform_payload(&payload, &state) {
        Ok(notif) => notif,
        Err(e) => {
            state
                .stats
                .transform_failures
                .fetch_add(1, Ordering::Relaxed);
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

    // Broadcast to SSE clients if enabled.
    let session_count = state.multiplexer.session_count();
    if state.definition.notify {
        state.multiplexer.broadcast(notification);
        state.stats.delivered.fetch_add(1, Ordering::Relaxed);
        debug!(
            request_id = %request_id,
            sessions = session_count,
            "Webhook notification broadcast"
        );
    }

    (
        StatusCode::OK,
        Json(json!({
            "status": "received",
            "request_id": request_id,
            "notified": state.definition.notify,
            "sessions": session_count
        })),
    )
}

// ============================================================================
// Signature validation
// ============================================================================

/// Validate HMAC-SHA256 signature against raw request body bytes.
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

    let Some(signature_header) = &definition.signature_header else {
        return Err("No signature header configured".to_string());
    };

    let signature_value = headers
        .get(signature_header)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| format!("Missing signature header: {signature_header}"))?;

    // Compute HMAC-SHA256 against raw body bytes (not re-serialized JSON).
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|e| format!("Invalid secret: {e}"))?;

    mac.update(raw_body);
    let computed = mac.finalize().into_bytes();
    let computed_hex = hex::encode(computed);

    // Compare signatures (handle different formats).
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

/// Constant-time comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ============================================================================
// Payload transformation
// ============================================================================

/// Transform webhook payload to MCP notification.
fn transform_payload(
    payload: &Value,
    state: &WebhookHandlerState,
) -> Result<TaggedNotification, String> {
    let transform = &state.definition.transform;

    // Extract event type.
    let event_type = if let Some(template) = &transform.event_type {
        extract_template_value(template, payload)?
    } else {
        format!("webhook.{}.{}", state.capability_name, state.webhook_name)
    };

    // Transform data fields.
    let mut transformed_data = serde_json::Map::new();
    for (key, template) in &transform.data {
        if let Ok(value) = extract_template_value(template, payload) {
            transformed_data.insert(key.clone(), Value::String(value));
        } else if let Some(value) = extract_json_path(template, payload) {
            // If string template extraction fails, try raw JSON path extraction.
            transformed_data.insert(key.clone(), value.clone());
        }
    }

    // If no transform data specified, use the entire payload.
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

/// Extract value from template (supports `{field.nested}` syntax).
fn extract_template_value(template: &str, payload: &Value) -> Result<String, String> {
    let mut result = template.to_string();

    // Find all {field.path} patterns.
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

/// Extract value from JSON using dot-notation path (e.g., "data.issue.id").
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests;
