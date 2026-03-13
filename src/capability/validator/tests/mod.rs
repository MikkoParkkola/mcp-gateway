mod yaml_roundtrip;

use super::checks::extract_placeholders;
use super::*;
use crate::capability::{
    AuthConfig, CacheConfig, CapabilityDefinition, CapabilityMetadata, ProviderConfig,
    ProvidersConfig, RestConfig, SchemaDefinition,
};
use crate::transform::TransformConfig;
use serde_json::json;
use std::collections::HashMap;

// ── Builder helpers ───────────────────────────────────────────────────────────

pub(super) fn minimal_cap(name: &str) -> CapabilityDefinition {
    CapabilityDefinition {
        fulcrum: "1.0".to_string(),
        name: name.to_string(),
        description: "Does something useful.".to_string(),
        schema: SchemaDefinition::default(),
        providers: providers_with_base_url("https://api.example.com"),
        auth: AuthConfig::default(),
        cache: CacheConfig::default(),
        metadata: CapabilityMetadata::default(),
        transform: TransformConfig::default(),
        webhooks: HashMap::new(),
    }
}

pub(super) fn providers_with_base_url(base_url: &str) -> ProvidersConfig {
    let mut named = HashMap::new();
    named.insert(
        "primary".to_string(),
        ProviderConfig {
            service: "rest".to_string(),
            cost_per_call: 0.0,
            timeout: 30,
            config: RestConfig {
                base_url: base_url.to_string(),
                path: String::new(),
                ..RestConfig::default()
            },
        },
    );
    ProvidersConfig {
        named,
        fallback: vec![],
    }
}

pub(super) fn providers_with_path(base_url: &str, path: &str) -> ProvidersConfig {
    let mut named = HashMap::new();
    named.insert(
        "primary".to_string(),
        ProviderConfig {
            service: "rest".to_string(),
            cost_per_call: 0.0,
            timeout: 30,
            config: RestConfig {
                base_url: base_url.to_string(),
                path: path.to_string(),
                ..RestConfig::default()
            },
        },
    );
    ProvidersConfig {
        named,
        fallback: vec![],
    }
}

pub(super) fn with_input_schema(
    mut cap: CapabilityDefinition,
    schema: serde_json::Value,
) -> CapabilityDefinition {
    cap.schema.input = schema;
    cap
}

pub(super) fn errors_of(issues: &[Issue]) -> Vec<Issue> {
    issues
        .iter()
        .filter(|i| i.severity == IssueSeverity::Error)
        .cloned()
        .collect()
}

pub(super) fn warnings_of(issues: &[Issue]) -> Vec<Issue> {
    issues
        .iter()
        .filter(|i| i.severity == IssueSeverity::Warning)
        .cloned()
        .collect()
}

pub(super) fn has_code(issues: &[Issue], code: &str) -> bool {
    issues.iter().any(|i| i.code == code)
}

// ── CAP-001: name validation ──────────────────────────────────────────────────

#[test]
fn name_valid_passes() {
    // GIVEN: lowercase alphanumeric+underscore name
    // WHEN: validating
    // THEN: no issues
    let cap = minimal_cap("web_search_v2");
    let issues = validate_capability_definition(&cap, None);
    assert!(
        !has_code(&issues, "CAP-001"),
        "unexpected CAP-001: {:?}",
        issues
    );
}

#[test]
fn name_empty_is_error() {
    // GIVEN: empty name
    // WHEN: validating
    // THEN: CAP-001 error
    let cap = minimal_cap("");
    let issues = validate_capability_definition(&cap, None);
    assert!(
        has_code(&errors_of(&issues), "CAP-001"),
        "expected CAP-001 error"
    );
}

#[test]
fn name_with_uppercase_is_error() {
    // GIVEN: name contains uppercase letter
    // WHEN: validating
    // THEN: CAP-001 error
    let cap = minimal_cap("WebSearch");
    let issues = validate_capability_definition(&cap, None);
    assert!(
        has_code(&errors_of(&issues), "CAP-001"),
        "expected CAP-001 error"
    );
}

#[test]
fn name_with_hyphen_is_error() {
    // GIVEN: name contains hyphen
    // WHEN: validating
    // THEN: CAP-001 error
    let cap = minimal_cap("web-search");
    let issues = validate_capability_definition(&cap, None);
    assert!(
        has_code(&errors_of(&issues), "CAP-001"),
        "expected CAP-001 error"
    );
}

#[test]
fn name_with_space_is_error() {
    // GIVEN: name contains space
    // WHEN: validating
    // THEN: CAP-001 error
    let cap = minimal_cap("web search");
    let issues = validate_capability_definition(&cap, None);
    assert!(
        has_code(&errors_of(&issues), "CAP-001"),
        "expected CAP-001 error"
    );
}

// ── CAP-002: description validation ──────────────────────────────────────────

#[test]
fn description_valid_passes() {
    // GIVEN: non-empty short description
    // WHEN: validating
    // THEN: no CAP-002 issues
    let cap = minimal_cap("my_tool");
    let issues = validate_capability_definition(&cap, None);
    assert!(!has_code(&issues, "CAP-002"));
}

#[test]
fn description_empty_is_warning() {
    // GIVEN: empty description
    // WHEN: validating
    // THEN: CAP-002 warning
    let mut cap = minimal_cap("my_tool");
    cap.description = String::new();
    let issues = validate_capability_definition(&cap, None);
    assert!(
        has_code(&warnings_of(&issues), "CAP-002"),
        "expected CAP-002 warning"
    );
}

#[test]
fn description_over_500_chars_is_warning() {
    // GIVEN: description longer than 500 chars
    // WHEN: validating
    // THEN: CAP-002 warning
    let mut cap = minimal_cap("my_tool");
    cap.description = "x".repeat(501);
    let issues = validate_capability_definition(&cap, None);
    assert!(
        has_code(&warnings_of(&issues), "CAP-002"),
        "expected CAP-002 warning"
    );
}

#[test]
fn description_exactly_500_chars_passes() {
    // GIVEN: description exactly 500 chars
    // WHEN: validating
    // THEN: no CAP-002 warning
    let mut cap = minimal_cap("my_tool");
    cap.description = "x".repeat(500);
    let issues = validate_capability_definition(&cap, None);
    assert!(!has_code(&warnings_of(&issues), "CAP-002"));
}

// ── CAP-003: schema.input validation ─────────────────────────────────────────

#[test]
fn schema_input_object_type_passes() {
    // GIVEN: schema.input.type = "object"
    // WHEN: validating
    // THEN: no CAP-003 error
    let cap = with_input_schema(
        minimal_cap("my_tool"),
        json!({"type": "object", "properties": {"q": {"type": "string"}}}),
    );
    let issues = validate_capability_definition(&cap, None);
    assert!(!has_code(&errors_of(&issues), "CAP-003"));
}

#[test]
fn schema_input_wrong_type_is_error() {
    // GIVEN: schema.input.type = "array"
    // WHEN: validating
    // THEN: CAP-003 error
    let cap = with_input_schema(minimal_cap("my_tool"), json!({"type": "array"}));
    let issues = validate_capability_definition(&cap, None);
    assert!(
        has_code(&errors_of(&issues), "CAP-003"),
        "expected CAP-003 error"
    );
}

#[test]
fn schema_input_properties_as_array_is_error() {
    // GIVEN: properties is an array (wrong format)
    // WHEN: validating
    // THEN: CAP-003 error
    let cap = with_input_schema(
        minimal_cap("my_tool"),
        json!({"type": "object", "properties": [{"name": "q"}]}),
    );
    let issues = validate_capability_definition(&cap, None);
    assert!(
        has_code(&errors_of(&issues), "CAP-003"),
        "expected CAP-003 error"
    );
}

// ── CAP-005: provider validation ──────────────────────────────────────────────

#[test]
fn provider_with_base_url_passes() {
    // GIVEN: primary provider with valid base_url
    // WHEN: validating
    // THEN: no CAP-005 error
    let cap = minimal_cap("my_tool");
    let issues = validate_capability_definition(&cap, None);
    assert!(!has_code(&errors_of(&issues), "CAP-005"));
}

#[test]
fn no_providers_and_no_webhooks_is_error() {
    // GIVEN: capability with empty providers and no webhooks
    // WHEN: validating
    // THEN: CAP-005 error
    let mut cap = minimal_cap("my_tool");
    cap.providers = ProvidersConfig::default();
    let issues = validate_capability_definition(&cap, None);
    assert!(
        has_code(&errors_of(&issues), "CAP-005"),
        "expected CAP-005 error"
    );
}

#[test]
fn provider_missing_url_is_error() {
    // GIVEN: provider with both base_url and endpoint empty
    // WHEN: validating
    // THEN: CAP-005 error
    let mut named = HashMap::new();
    named.insert(
        "primary".to_string(),
        ProviderConfig {
            service: "rest".to_string(),
            cost_per_call: 0.0,
            timeout: 30,
            config: RestConfig::default(), // base_url and endpoint both empty
        },
    );
    let mut cap = minimal_cap("my_tool");
    cap.providers = ProvidersConfig {
        named,
        fallback: vec![],
    };
    let issues = validate_capability_definition(&cap, None);
    assert!(
        has_code(&errors_of(&issues), "CAP-005"),
        "expected CAP-005 error"
    );
}

// ── CAP-006: dangling placeholders ────────────────────────────────────────────

#[test]
fn placeholder_with_schema_property_passes() {
    // GIVEN: path has {id} and schema.input.properties contains "id"
    // WHEN: validating
    // THEN: no CAP-006 error
    let cap = with_input_schema(
        CapabilityDefinition {
            fulcrum: "1.0".to_string(),
            name: "get_item".to_string(),
            description: "Fetches an item.".to_string(),
            schema: SchemaDefinition::default(),
            providers: providers_with_path("https://api.example.com", "/v1/items/{id}"),
            auth: AuthConfig::default(),
            cache: CacheConfig::default(),
            metadata: CapabilityMetadata::default(),
            transform: TransformConfig::default(),
            webhooks: HashMap::new(),
        },
        json!({"type": "object", "properties": {"id": {"type": "string"}}}),
    );
    let issues = validate_capability_definition(&cap, None);
    assert!(
        !has_code(&errors_of(&issues), "CAP-006"),
        "unexpected CAP-006: {:?}",
        issues
    );
}

#[test]
fn placeholder_without_schema_property_is_error() {
    // GIVEN: path has {item_id} but schema.input has no such property
    // WHEN: validating
    // THEN: CAP-006 error
    let cap = with_input_schema(
        CapabilityDefinition {
            fulcrum: "1.0".to_string(),
            name: "get_item".to_string(),
            description: "Fetches an item.".to_string(),
            schema: SchemaDefinition::default(),
            providers: providers_with_path("https://api.example.com", "/v1/items/{item_id}"),
            auth: AuthConfig::default(),
            cache: CacheConfig::default(),
            metadata: CapabilityMetadata::default(),
            transform: TransformConfig::default(),
            webhooks: HashMap::new(),
        },
        json!({"type": "object", "properties": {"id": {"type": "string"}}}),
    );
    let issues = validate_capability_definition(&cap, None);
    assert!(
        has_code(&errors_of(&issues), "CAP-006"),
        "expected CAP-006 error"
    );
}

#[test]
fn env_placeholder_in_url_is_ignored() {
    // GIVEN: base_url contains {env.API_HOST} — a runtime env reference
    // WHEN: validating
    // THEN: no CAP-006 error (env refs are not schema params)
    let cap = with_input_schema(
        CapabilityDefinition {
            fulcrum: "1.0".to_string(),
            name: "my_tool".to_string(),
            description: "Uses env ref.".to_string(),
            schema: SchemaDefinition::default(),
            providers: providers_with_base_url("https://{env.API_HOST}/v1"),
            auth: AuthConfig::default(),
            cache: CacheConfig::default(),
            metadata: CapabilityMetadata::default(),
            transform: TransformConfig::default(),
            webhooks: HashMap::new(),
        },
        json!({"type": "object", "properties": {}}),
    );
    let issues = validate_capability_definition(&cap, None);
    assert!(
        !has_code(&errors_of(&issues), "CAP-006"),
        "unexpected CAP-006"
    );
}

// ── CAP-007: static_params overlap ───────────────────────────────────────────

#[test]
fn static_params_overlap_with_params_is_warning() {
    // GIVEN: static_params and params share a key "format"
    // WHEN: validating
    // THEN: CAP-007 warning
    let mut named = HashMap::new();
    named.insert(
        "primary".to_string(),
        ProviderConfig {
            service: "rest".to_string(),
            cost_per_call: 0.0,
            timeout: 30,
            config: RestConfig {
                base_url: "https://api.example.com".to_string(),
                params: {
                    let mut m = HashMap::new();
                    m.insert("format".to_string(), "json".to_string());
                    m
                },
                static_params: {
                    let mut m = HashMap::new();
                    m.insert(
                        "format".to_string(),
                        serde_json::Value::String("xml".to_string()),
                    );
                    m
                },
                ..RestConfig::default()
            },
        },
    );
    let mut cap = minimal_cap("my_tool");
    cap.providers = ProvidersConfig {
        named,
        fallback: vec![],
    };
    let issues = validate_capability_definition(&cap, None);
    assert!(
        has_code(&warnings_of(&issues), "CAP-007"),
        "expected CAP-007 warning"
    );
}

#[test]
fn static_params_no_overlap_passes() {
    // GIVEN: static_params and params have disjoint keys
    // WHEN: validating
    // THEN: no CAP-007 warning
    let mut named = HashMap::new();
    named.insert(
        "primary".to_string(),
        ProviderConfig {
            service: "rest".to_string(),
            cost_per_call: 0.0,
            timeout: 30,
            config: RestConfig {
                base_url: "https://api.example.com".to_string(),
                params: {
                    let mut m = HashMap::new();
                    m.insert("q".to_string(), "{query}".to_string());
                    m
                },
                static_params: {
                    let mut m = HashMap::new();
                    m.insert(
                        "format".to_string(),
                        serde_json::Value::String("json".to_string()),
                    );
                    m
                },
                ..RestConfig::default()
            },
        },
    );
    let mut cap = minimal_cap("my_tool");
    cap.providers = ProvidersConfig {
        named,
        fallback: vec![],
    };
    let issues = validate_capability_definition(&cap, None);
    assert!(!has_code(&warnings_of(&issues), "CAP-007"));
}

// ── CAP-008: URL validation ───────────────────────────────────────────────────

#[test]
fn invalid_base_url_is_error() {
    // GIVEN: base_url is not a valid URL
    // WHEN: validating
    // THEN: CAP-008 error
    let cap = minimal_cap("my_tool"); // uses "https://api.example.com" which is valid
    // Override with bad URL:
    let cap = CapabilityDefinition {
        providers: providers_with_base_url("not-a-url"),
        ..cap
    };
    let issues = validate_capability_definition(&cap, None);
    assert!(
        has_code(&errors_of(&issues), "CAP-008"),
        "expected CAP-008 error"
    );
}

#[test]
fn valid_https_url_passes() {
    // GIVEN: valid HTTPS base_url
    // WHEN: validating
    // THEN: no CAP-008 error
    let cap = minimal_cap("my_tool");
    let issues = validate_capability_definition(&cap, None);
    assert!(!has_code(&errors_of(&issues), "CAP-008"));
}

#[test]
fn path_without_leading_slash_is_warning() {
    // GIVEN: path does not start with '/'
    // WHEN: validating
    // THEN: CAP-008 warning
    let cap = with_input_schema(
        CapabilityDefinition {
            fulcrum: "1.0".to_string(),
            name: "my_tool".to_string(),
            description: "Tool.".to_string(),
            schema: SchemaDefinition::default(),
            providers: providers_with_path("https://api.example.com", "v1/items"),
            auth: AuthConfig::default(),
            cache: CacheConfig::default(),
            metadata: CapabilityMetadata::default(),
            transform: TransformConfig::default(),
            webhooks: HashMap::new(),
        },
        json!({"type": "object"}),
    );
    let issues = validate_capability_definition(&cap, None);
    assert!(
        has_code(&warnings_of(&issues), "CAP-008"),
        "expected CAP-008 warning"
    );
}

// ── CAP-009: duplicate names ──────────────────────────────────────────────────

#[test]
fn duplicate_capability_names_are_warned() {
    // GIVEN: two capabilities share the same name
    // WHEN: validate_capabilities is called
    // THEN: CAP-009 warning for the second file
    let caps = vec![
        (
            "capabilities/a/tool.yaml".to_string(),
            minimal_cap("my_tool"),
        ),
        (
            "capabilities/b/tool.yaml".to_string(),
            minimal_cap("my_tool"),
        ),
    ];
    let results = validate_capabilities(&caps);
    let second_issues = results
        .get("capabilities/b/tool.yaml")
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    assert!(
        has_code(second_issues, "CAP-009"),
        "expected CAP-009 warning: {:?}",
        second_issues
    );
}

#[test]
fn unique_capability_names_pass_duplicate_check() {
    // GIVEN: two capabilities with distinct names
    // WHEN: validate_capabilities is called
    // THEN: no CAP-009 warnings
    let caps = vec![
        (
            "capabilities/a/tool_a.yaml".to_string(),
            minimal_cap("tool_a"),
        ),
        (
            "capabilities/b/tool_b.yaml".to_string(),
            minimal_cap("tool_b"),
        ),
    ];
    let results = validate_capabilities(&caps);
    let all_issues: Vec<Issue> = results.into_values().flatten().collect();
    assert!(!has_code(&all_issues, "CAP-009"));
}

// ── extract_placeholders ──────────────────────────────────────────────────────

#[test]
fn extract_placeholders_finds_multiple() {
    let text = "/v1/{org}/{repo}/issues/{id}";
    let mut found: Vec<_> = extract_placeholders(text).collect();
    found.sort();
    assert_eq!(found, vec!["id", "org", "repo"]);
}

#[test]
fn extract_placeholders_empty_string() {
    let found: Vec<_> = extract_placeholders("").collect();
    assert!(found.is_empty());
}

#[test]
fn extract_placeholders_no_braces() {
    let found: Vec<_> = extract_placeholders("/v1/users").collect();
    assert!(found.is_empty());
}

#[test]
fn extract_placeholders_env_ref() {
    let found: Vec<_> = extract_placeholders("https://{env.API_HOST}/v1").collect();
    assert_eq!(found, vec!["env.API_HOST"]);
}
