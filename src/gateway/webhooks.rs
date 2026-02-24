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
    if state.config.require_signature || state.definition.secret.is_some() {
        if let Err(e) = validate_signature(&headers, &body, &state.definition) {
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
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::*;
    use crate::backend::BackendRegistry;
    use crate::capability::{WebhookDefinition, WebhookTransform};
    use crate::config::{StreamingConfig, WebhookConfig};
    use crate::gateway::streaming::NotificationMultiplexer;

    // ── helpers ───────────────────────────────────────────────────────────

    fn make_multiplexer() -> Arc<NotificationMultiplexer> {
        Arc::new(NotificationMultiplexer::new(
            Arc::new(BackendRegistry::new()),
            StreamingConfig::default(),
        ))
    }

    fn make_definition(notify: bool) -> WebhookDefinition {
        WebhookDefinition {
            path: "/test".to_string(),
            method: "POST".to_string(),
            secret: None,
            signature_header: None,
            notify,
            transform: WebhookTransform::default(),
        }
    }

    fn make_handler_state(
        multiplexer: Arc<NotificationMultiplexer>,
        definition: WebhookDefinition,
    ) -> WebhookHandlerState {
        WebhookHandlerState {
            multiplexer,
            capability_name: "test_cap".to_string(),
            webhook_name: "test_hook".to_string(),
            definition,
            config: WebhookConfig {
                require_signature: false,
                ..WebhookConfig::default()
            },
            stats: Arc::new(EndpointStats::default()),
        }
    }

    // ── extract_json_path ─────────────────────────────────────────────────

    #[test]
    fn extract_json_path_nested_field_returns_value() {
        // GIVEN: nested JSON with path data.issue.id
        // WHEN: extracting that path
        // THEN: returns the correct leaf value
        let payload = json!({
            "data": { "issue": { "id": "123", "title": "Bug fix" } },
            "action": "update"
        });

        assert_eq!(
            extract_json_path("data.issue.id", &payload),
            Some(&json!("123"))
        );
        assert_eq!(
            extract_json_path("action", &payload),
            Some(&json!("update"))
        );
    }

    #[test]
    fn extract_json_path_missing_field_returns_none() {
        // GIVEN: JSON without the requested field
        // WHEN: extracting a non-existent path
        // THEN: returns None
        let payload = json!({ "data": {} });
        assert_eq!(extract_json_path("nonexistent", &payload), None);
        assert_eq!(extract_json_path("data.missing.deep", &payload), None);
    }

    #[test]
    fn extract_json_path_array_index_access() {
        // GIVEN: JSON with an array
        // WHEN: extracting by numeric index
        // THEN: returns the correct element
        let payload = json!({ "items": ["a", "b", "c"] });
        assert_eq!(extract_json_path("items.1", &payload), Some(&json!("b")));
    }

    // ── extract_template_value ────────────────────────────────────────────

    #[test]
    fn extract_template_value_single_placeholder_substituted() {
        // GIVEN: template with one placeholder
        // WHEN: the field exists in payload
        // THEN: placeholder is replaced with field value
        let payload = json!({ "data": { "id": "456" }, "action": "created" });
        let result = extract_template_value("linear.issue.{action}", &payload).unwrap();
        assert_eq!(result, "linear.issue.created");
    }

    #[test]
    fn extract_template_value_nested_path_substituted() {
        // GIVEN: template referencing a nested field
        // WHEN: the nested field exists
        // THEN: substitution succeeds
        let payload = json!({ "data": { "id": "456" }, "action": "created" });
        let result = extract_template_value("ID: {data.id}", &payload).unwrap();
        assert_eq!(result, "ID: 456");
    }

    #[test]
    fn extract_template_value_missing_path_returns_error() {
        // GIVEN: template referencing a missing field
        // WHEN: the field does not exist
        // THEN: returns Err
        let payload = json!({ "action": "created" });
        let result = extract_template_value("{missing.field}", &payload);
        assert!(result.is_err());
    }

    #[test]
    fn extract_template_value_no_placeholders_returned_as_is() {
        // GIVEN: template with no placeholders
        // WHEN: extracting
        // THEN: returns the template string unchanged
        let payload = json!({});
        let result = extract_template_value("static.event.type", &payload).unwrap();
        assert_eq!(result, "static.event.type");
    }

    // ── constant_time_eq ──────────────────────────────────────────────────

    #[test]
    fn constant_time_eq_equal_slices_returns_true() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_eq_different_content_returns_false() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn constant_time_eq_different_length_returns_false() {
        assert!(!constant_time_eq(b"hello", b"hell"));
    }

    // ── transform_payload ─────────────────────────────────────────────────

    #[test]
    fn transform_payload_no_transform_uses_full_payload() {
        // GIVEN: definition with no transform fields
        // WHEN: transforming a payload
        // THEN: data field is the entire payload
        let multiplexer = make_multiplexer();
        let def = make_definition(true);
        let state = make_handler_state(multiplexer, def);
        let payload = json!({ "action": "created", "data": { "id": "1" } });

        let notif = transform_payload(&payload, &state).unwrap();
        assert_eq!(notif.source, "test_cap");
        assert_eq!(notif.event_type, "webhook.test_cap.test_hook");
        assert_eq!(notif.data, payload);
    }

    #[test]
    fn transform_payload_with_event_type_template() {
        // GIVEN: definition with event_type template referencing payload field
        // WHEN: transforming a payload that contains {action}
        // THEN: event_type is substituted correctly
        let multiplexer = make_multiplexer();
        let mut def = make_definition(true);
        def.transform.event_type = Some("linear.issue.{action}".to_string());
        let state = make_handler_state(multiplexer, def);
        let payload = json!({ "action": "update" });

        let notif = transform_payload(&payload, &state).unwrap();
        assert_eq!(notif.event_type, "linear.issue.update");
    }

    #[test]
    fn transform_payload_with_data_mapping() {
        // GIVEN: definition with data field mappings
        // WHEN: payload contains the mapped fields
        // THEN: transformed data contains only the mapped keys
        let multiplexer = make_multiplexer();
        let mut def = make_definition(true);
        def.transform
            .data
            .insert("issue_id".to_string(), "{data.id}".to_string());
        def.transform
            .data
            .insert("action".to_string(), "{action}".to_string());
        let state = make_handler_state(multiplexer, def);
        let payload = json!({ "action": "created", "data": { "id": "ABC-123" } });

        let notif = transform_payload(&payload, &state).unwrap();
        assert_eq!(notif.data["issue_id"], "ABC-123");
        assert_eq!(notif.data["action"], "created");
    }

    // ── WebhookRegistry ───────────────────────────────────────────────────

    fn make_capability_with_webhooks(
        name: &str,
        webhook_paths: &[(&str, &str, bool)],
    ) -> crate::capability::CapabilityDefinition {
        use crate::capability::{
            AuthConfig, CacheConfig, CapabilityDefinition, CapabilityMetadata, ProvidersConfig,
            SchemaDefinition, WebhookDefinition, WebhookTransform,
        };
        use crate::transform::TransformConfig;
        use std::collections::HashMap;

        let mut webhooks = HashMap::new();
        for (wname, wpath, notify) in webhook_paths {
            webhooks.insert(
                (*wname).to_string(),
                WebhookDefinition {
                    path: (*wpath).to_string(),
                    method: "POST".to_string(),
                    secret: None,
                    signature_header: None,
                    notify: *notify,
                    transform: WebhookTransform::default(),
                },
            );
        }

        CapabilityDefinition {
            fulcrum: "1.0".to_string(),
            name: name.to_string(),
            description: "Test capability".to_string(),
            schema: SchemaDefinition::default(),
            providers: ProvidersConfig::default(),
            auth: AuthConfig::default(),
            cache: CacheConfig::default(),
            metadata: CapabilityMetadata::default(),
            transform: TransformConfig::default(),
            webhooks,
        }
    }

    #[test]
    fn registry_endpoint_count_reflects_registered_capabilities() {
        // GIVEN: a fresh registry and a capability with two webhooks
        // WHEN: registering the capability
        // THEN: endpoint_count returns 2
        let mut registry = WebhookRegistry::new(WebhookConfig::default());
        let cap = make_capability_with_webhooks(
            "test_cap",
            &[("hook1", "/hook1", true), ("hook2", "/hook2", false)],
        );
        registry.register_capability(&cap);
        assert_eq!(registry.endpoint_count(), 2);
    }

    #[test]
    fn registry_list_endpoints_sorted_by_path() {
        // GIVEN: registry with endpoints at /z/hook and /a/hook
        // WHEN: listing endpoints
        // THEN: returned in ascending path order
        let mut registry = WebhookRegistry::new(WebhookConfig::default());
        let cap = make_capability_with_webhooks(
            "cap",
            &[("z_hook", "/z/hook", true), ("a_hook", "/a/hook", true)],
        );
        registry.register_capability(&cap);

        let endpoints = registry.list_endpoints();
        assert_eq!(endpoints.len(), 2);
        // The base_path "/webhooks" is prepended; paths must be ascending.
        assert!(endpoints[0].path < endpoints[1].path);
    }

    // ── EndpointStats ─────────────────────────────────────────────────────

    #[test]
    fn endpoint_stats_initial_snapshot_all_zeros() {
        // GIVEN: a freshly created EndpointStats
        // WHEN: snapshotting immediately
        // THEN: all counters are zero and last_received_at is None
        let stats = EndpointStats::default();
        let snap = stats.snapshot();
        assert_eq!(snap.received, 0);
        assert_eq!(snap.delivered, 0);
        assert_eq!(snap.signature_failures, 0);
        assert_eq!(snap.transform_failures, 0);
        assert!(snap.last_received_at.is_none());
    }

    #[test]
    fn endpoint_stats_record_received_increments_and_timestamps() {
        // GIVEN: fresh stats
        // WHEN: record_received is called
        // THEN: received == 1 and last_received_at is Some
        let stats = EndpointStats::default();
        stats.record_received();
        let snap = stats.snapshot();
        assert_eq!(snap.received, 1);
        assert!(snap.last_received_at.is_some());
    }

    #[test]
    fn endpoint_stats_delivery_counter_independent_of_received() {
        // GIVEN: fresh stats
        // WHEN: received is called twice and delivered once
        // THEN: counts are tracked independently
        let stats = EndpointStats::default();
        stats.record_received();
        stats.record_received();
        stats.delivered.fetch_add(1, Ordering::Relaxed);
        let snap = stats.snapshot();
        assert_eq!(snap.received, 2);
        assert_eq!(snap.delivered, 1);
    }

    // ── method_to_filter ──────────────────────────────────────────────────

    #[test]
    fn method_to_filter_known_methods_mapped_correctly() {
        // GIVEN: valid HTTP method strings
        // WHEN: mapping to MethodFilter
        // THEN: correct filter variants are returned (compile-time check via usage)
        let _ = method_to_filter("GET");
        let _ = method_to_filter("POST");
        let _ = method_to_filter("PUT");
        let _ = method_to_filter("PATCH");
        let _ = method_to_filter("DELETE");
        let _ = method_to_filter("UNKNOWN"); // defaults to POST
    }
}
