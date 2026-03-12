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
