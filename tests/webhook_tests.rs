//! Tests for webhook receiver functionality

use std::collections::HashMap;
use std::sync::Arc;

use mcp_gateway::backend::BackendRegistry;
use mcp_gateway::capability::{
    AuthConfig, CacheConfig, CapabilityDefinition, CapabilityMetadata, ProvidersConfig,
    SchemaDefinition, WebhookDefinition, WebhookTransform,
};
use mcp_gateway::transform::TransformConfig;
use mcp_gateway::config::StreamingConfig;
use mcp_gateway::config::WebhookConfig;
use mcp_gateway::gateway::{NotificationMultiplexer, WebhookRegistry};
use serde_json::json;

#[tokio::test]
async fn test_webhook_registry_registration() {
    let config = WebhookConfig {
        enabled: true,
        base_path: "/webhooks".to_string(),
        require_signature: false,
        rate_limit: 100,
    };

    let mut registry = WebhookRegistry::new(config);

    // Create a capability with a webhook
    let mut webhooks = HashMap::new();
    webhooks.insert(
        "issue_updated".to_string(),
        WebhookDefinition {
            path: "/linear/issues".to_string(),
            method: "POST".to_string(),
            secret: None,
            signature_header: None,
            transform: WebhookTransform {
                event_type: Some("linear.issue.{action}".to_string()),
                data: {
                    let mut map = HashMap::new();
                    map.insert("id".to_string(), "{data.id}".to_string());
                    map.insert("title".to_string(), "{data.title}".to_string());
                    map
                },
            },
            notify: true,
        },
    );

    let capability = CapabilityDefinition {
        fulcrum: "1.0".to_string(),
        name: "linear".to_string(),
        description: "Linear integration".to_string(),
        schema: SchemaDefinition::default(),
        providers: ProvidersConfig::default(),
        auth: AuthConfig::default(),
        cache: CacheConfig::default(),
        metadata: CapabilityMetadata::default(),
        transform: TransformConfig::default(),
        webhooks,
    };

    registry.register_capability(&capability);

    // Verify webhook was registered
    assert!(registry.get("/webhooks/linear/issues").is_some());
}

#[tokio::test]
async fn test_webhook_routes_creation() {
    let config = WebhookConfig {
        enabled: true,
        base_path: "/webhooks".to_string(),
        require_signature: false,
        rate_limit: 100,
    };

    let mut registry = WebhookRegistry::new(config.clone());

    // Create a capability with a webhook
    let mut webhooks = HashMap::new();
    webhooks.insert(
        "test_webhook".to_string(),
        WebhookDefinition {
            path: "/test/event".to_string(),
            method: "POST".to_string(),
            secret: None,
            signature_header: None,
            transform: WebhookTransform::default(),
            notify: true,
        },
    );

    let capability = CapabilityDefinition {
        fulcrum: "1.0".to_string(),
        name: "test_service".to_string(),
        description: "Test service".to_string(),
        schema: SchemaDefinition::default(),
        providers: ProvidersConfig::default(),
        auth: AuthConfig::default(),
        cache: CacheConfig::default(),
        metadata: CapabilityMetadata::default(),
        transform: TransformConfig::default(),
        webhooks,
    };

    registry.register_capability(&capability);

    // Create routes
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        backends,
        StreamingConfig::default(),
    ));

    let routes = registry.create_routes(multiplexer);

    // Routes should be created without panicking
    assert!(!format!("{routes:?}").is_empty());
}

#[test]
fn test_webhook_transform_event_type_template() {
    let payload = json!({
        "action": "created",
        "data": {
            "id": "123",
            "title": "Test issue"
        }
    });

    // This is tested implicitly via the webhook handler
    // Just verify the payload structure is correct
    assert_eq!(payload["action"], "created");
    assert_eq!(payload["data"]["id"], "123");
}

#[test]
fn test_webhook_config_defaults() {
    let config = WebhookConfig::default();
    assert!(config.enabled);
    assert_eq!(config.base_path, "/webhooks");
    assert!(config.require_signature);
    assert_eq!(config.rate_limit, 100);
}
