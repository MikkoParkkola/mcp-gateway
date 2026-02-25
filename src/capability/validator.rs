//! Structural validator for capability YAML definitions.
//!
//! Catches schema format errors, malformed providers, dangling URL placeholders,
//! and other structural issues that cause silent runtime failures.
//!
//! # Design
//!
//! Validation is split into independent checks, each returning zero or more
//! [`Issue`] items.  A single pass collects all issues so the caller receives a
//! complete picture rather than stopping at the first error.
//!
//! Checks are categorised by [`IssueSeverity`]:
//! - `Error` — the capability **cannot** function correctly.
//! - `Warning` — the capability may function but has a structural smell.
//!
//! # Example
//!
//! ```rust
//! use mcp_gateway::capability::validator::{validate_capability_definition, IssueSeverity};
//! use mcp_gateway::capability::CapabilityDefinition;
//!
//! let yaml = r#"
//! name: my_tool
//! description: Does something useful.
//! providers:
//!   primary:
//!     config:
//!       base_url: https://api.example.com
//!       path: /v1/items/{id}
//! schema:
//!   input:
//!     type: object
//!     properties:
//!       id:
//!         type: string
//!         description: The item identifier
//! "#;
//!
//! let cap: CapabilityDefinition = serde_yaml::from_str(yaml).unwrap();
//! let issues = validate_capability_definition(&cap, None);
//! assert!(issues.iter().all(|i| i.severity == IssueSeverity::Warning));
//! ```

use std::collections::{HashMap, HashSet};

use super::{CapabilityDefinition, RestConfig};

// ── Public types ──────────────────────────────────────────────────────────────

/// Severity of a structural validation issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IssueSeverity {
    /// The capability cannot function correctly; it will be skipped at load time.
    Error,
    /// The capability may work but has a structural smell that should be fixed.
    Warning,
}

impl std::fmt::Display for IssueSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Error => f.write_str("ERROR"),
            Self::Warning => f.write_str("WARN"),
        }
    }
}

/// A single structural validation finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    /// Severity level.
    pub severity: IssueSeverity,
    /// Short code identifying the check (e.g. `"CAP-001"`).
    pub code: &'static str,
    /// Human-readable description of the issue.
    pub message: String,
    /// Optional YAML field path for context (e.g. `"schema.input"`).
    pub field: Option<&'static str>,
}

impl Issue {
    fn error(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: IssueSeverity::Error,
            code,
            message: message.into(),
            field: None,
        }
    }

    fn warning(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: IssueSeverity::Warning,
            code,
            message: message.into(),
            field: None,
        }
    }

    fn with_field(mut self, field: &'static str) -> Self {
        self.field = Some(field);
        self
    }
}

impl std::fmt::Display for Issue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(field) = self.field {
            write!(f, "[{}] {} ({}): {}", self.severity, self.code, field, self.message)
        } else {
            write!(f, "[{}] {}: {}", self.severity, self.code, self.message)
        }
    }
}

// ── Entry points ──────────────────────────────────────────────────────────────

/// Validate a single parsed capability definition.
///
/// `file_path` is used only in duplicate-detection messages; pass `None` when
/// validating in isolation (e.g., from `cap validate`).
///
/// Returns all [`Issue`]s found across every structural check.  An empty vec
/// means the definition is structurally sound.
#[must_use]
pub fn validate_capability_definition(
    cap: &CapabilityDefinition,
    file_path: Option<&str>,
) -> Vec<Issue> {
    let mut issues = Vec::new();

    check_name(&cap.name, &mut issues);
    check_description(&cap.description, &mut issues);
    check_schema_input(&cap.schema.input, &mut issues);
    check_schema_output(&cap.schema.output, &mut issues);
    check_providers(cap, &mut issues);

    if let Some(path) = file_path {
        check_path_label(path, &cap.name, &mut issues);
    }

    issues
}

/// Validate a set of capabilities loaded from one or more directories.
///
/// Runs per-capability checks on every definition and then cross-capability
/// duplicate-name detection.
///
/// Returns a map from capability name to its list of issues.  Only capabilities
/// that have at least one issue appear in the map.
#[must_use]
pub fn validate_capabilities(
    caps: &[(String, CapabilityDefinition)], // (file_path, definition)
) -> HashMap<String, Vec<Issue>> {
    let mut results: HashMap<String, Vec<Issue>> = HashMap::new();

    for (path, cap) in caps {
        let issues = validate_capability_definition(cap, Some(path));
        if !issues.is_empty() {
            results.insert(path.clone(), issues);
        }
    }

    // Cross-capability: duplicate name detection
    let duplicate_issues = check_duplicate_names(caps);
    for (path, issue) in duplicate_issues {
        results.entry(path).or_default().push(issue);
    }

    results
}

// ── Individual checks ─────────────────────────────────────────────────────────

/// CAP-001: name must be non-empty, lowercase, alphanumeric + underscores.
fn check_name(name: &str, issues: &mut Vec<Issue>) {
    if name.is_empty() {
        issues.push(
            Issue::error("CAP-001", "name is required").with_field("name"),
        );
        return;
    }

    let valid = name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if !valid {
        issues.push(Issue::error(
            "CAP-001",
            format!(
                "name '{name}' must be lowercase alphanumeric and underscores only (no spaces, hyphens, or uppercase)",
            ),
        ).with_field("name"));
    }
}

/// Maximum description length before issuing a CAP-002 warning.
const MAX_DESCRIPTION_LEN: usize = 500;

/// CAP-002: description must be non-empty and under 500 characters.
fn check_description(description: &str, issues: &mut Vec<Issue>) {
    if description.trim().is_empty() {
        issues.push(
            Issue::warning("CAP-002", "description is empty; add a meaningful description")
                .with_field("description"),
        );
        return;
    }

    if description.len() > MAX_DESCRIPTION_LEN {
        issues.push(Issue::warning(
            "CAP-002",
            format!(
                "description is {} characters; keep it under {MAX_DESCRIPTION_LEN} for readability",
                description.len()
            ),
        ).with_field("description"));
    }
}

/// CAP-003: schema.input must be a valid JSON Schema object with `type: object`
/// and a non-empty `properties` map.
fn check_schema_input(input: &serde_json::Value, issues: &mut Vec<Issue>) {
    if input.is_null() || *input == serde_json::Value::Object(serde_json::Map::default()) {
        // Empty schema is not an error for webhook-only capabilities, but worth warning.
        return;
    }

    if let Some(t) = input.get("type").and_then(|v| v.as_str()) {
        if t != "object" {
            issues.push(Issue::error(
                "CAP-003",
                format!("schema.input.type must be 'object', got '{t}'"),
            ).with_field("schema.input.type"));
        }
    } else if input.is_object() {
        // Tolerate missing type when the value is an object (some YAMLs omit it).
    }

    // Properties must be an object, not an array.
    if let Some(props) = input.get("properties") {
        if !props.is_object() {
            issues.push(Issue::error(
                "CAP-003",
                "schema.input.properties must be a YAML mapping (object), not an array",
            ).with_field("schema.input.properties"));
        }
    }
}

/// CAP-004: schema.output, if present, must be a valid JSON Schema object.
fn check_schema_output(output: &serde_json::Value, issues: &mut Vec<Issue>) {
    if output.is_null() {
        return;
    }

    if let Some(t) = output.get("type").and_then(|v| v.as_str()) {
        if t != "object" {
            issues.push(Issue::warning(
                "CAP-004",
                format!("schema.output.type should be 'object', got '{t}'"),
            ).with_field("schema.output.type"));
        }
    }

    if let Some(props) = output.get("properties") {
        if !props.is_object() {
            issues.push(Issue::error(
                "CAP-004",
                "schema.output.properties must be a YAML mapping (object), not an array",
            ).with_field("schema.output.properties"));
        }
    }
}

/// CAP-005: providers must use named entries (e.g. `primary:`), not a list.
/// Each provider must have `base_url` or `endpoint`.
/// CAP-006: All `{param}` placeholders in URL/path must exist in `schema.input.properties`.
/// CAP-007: `static_params` keys must not overlap with `params` keys.
/// CAP-008: `base_url` must be a valid URL; `path` must start with `'/'`.
fn check_providers(cap: &CapabilityDefinition, issues: &mut Vec<Issue>) {
    if cap.providers.is_empty() && cap.webhooks.is_empty() {
        issues.push(
            Issue::error("CAP-005", "at least one provider or webhook is required")
                .with_field("providers"),
        );
        return;
    }

    let schema_props = extract_input_property_names(&cap.schema.input);

    for (provider_name, provider) in &cap.providers.named {
        let ctx = format!("providers.{provider_name}");
        check_rest_config(&provider.config, &ctx, &schema_props, issues);
    }

    for (idx, provider) in cap.providers.fallback.iter().enumerate() {
        let ctx = format!("providers.fallback[{idx}]");
        check_rest_config(&provider.config, &ctx, &schema_props, issues);
    }
}

/// Validate a single `RestConfig` entry.
fn check_rest_config(
    config: &RestConfig,
    context: &str,
    schema_props: &HashSet<String>,
    issues: &mut Vec<Issue>,
) {
    let has_base_url = !config.base_url.is_empty();
    let has_endpoint = !config.endpoint.is_empty();
    let has_path = !config.path.is_empty();

    if !has_base_url && !has_endpoint {
        issues.push(Issue::error(
            "CAP-005",
            format!("{context}: provider must have 'base_url' or 'endpoint'"),
        ));
    }

    // CAP-008: base_url must parse as a valid URL.
    // Skip validation when URL contains template references (e.g. {env.VAR})
    // since these are resolved at runtime, not parse-time.
    let contains_template = |s: &str| s.contains('{');
    if has_base_url && !contains_template(&config.base_url) && url::Url::parse(&config.base_url).is_err() {
        issues.push(Issue::error(
            "CAP-008",
            format!("{context}: base_url '{}' is not a valid URL", config.base_url),
        ));
    }

    if has_endpoint && !contains_template(&config.endpoint) && url::Url::parse(&config.endpoint).is_err() {
        issues.push(Issue::error(
            "CAP-008",
            format!("{context}: endpoint '{}' is not a valid URL", config.endpoint),
        ));
    }

    // CAP-008: path must start with '/'.
    if has_path && !config.path.starts_with('/') {
        issues.push(Issue::warning(
            "CAP-008",
            format!("{context}: path '{}' should start with '/'", config.path),
        ));
    }

    // CAP-006: dangling placeholders.
    check_placeholders_in_text(&config.path, context, "path", schema_props, issues);
    check_placeholders_in_text(&config.base_url, context, "base_url", schema_props, issues);
    check_placeholders_in_text(&config.endpoint, context, "endpoint", schema_props, issues);

    for (key, value) in &config.params {
        check_placeholders_in_text(value, context, &format!("params.{key}"), schema_props, issues);
    }

    for (key, value) in &config.headers {
        check_placeholders_in_text(value, context, &format!("headers.{key}"), schema_props, issues);
    }

    // CAP-007: static_params must not overlap with params.
    let static_keys: HashSet<&str> = config.static_params.keys().map(String::as_str).collect();
    let param_keys: HashSet<&str> = config.params.keys().map(String::as_str).collect();
    for overlap in static_keys.intersection(&param_keys) {
        issues.push(Issue::warning(
            "CAP-007",
            format!("{context}: key '{overlap}' appears in both 'static_params' and 'params'; static_params will be overridden by caller"),
        ));
    }
}

/// Scan `text` for `{placeholder}` patterns and report any not in `schema_props`.
///
/// Skips `{env.VAR}` style references — those are not schema parameters.
fn check_placeholders_in_text(
    text: &str,
    context: &str,
    field: &str,
    schema_props: &HashSet<String>,
    issues: &mut Vec<Issue>,
) {
    for placeholder in extract_placeholders(text) {
        // System-resolved references are not schema parameters.
        // env.VAR — environment variable substitution
        // keychain.KEY — macOS Keychain lookup
        // oauth.PROVIDER — OAuth token injection
        // access_token / refresh_token — OAuth runtime injection
        // api_key — runtime API key injection
        const RUNTIME_PLACEHOLDERS: &[&str] = &[
            "access_token", "refresh_token", "api_key", "bearer_token", "auth_token",
        ];
        if placeholder.starts_with("env.")
            || placeholder.starts_with("keychain.")
            || placeholder.starts_with("oauth.")
            || RUNTIME_PLACEHOLDERS.contains(&placeholder.as_str())
        {
            continue;
        }

        if !schema_props.contains(&placeholder) {
            issues.push(Issue::error(
                "CAP-006",
                format!(
                    "{context}.{field}: placeholder '{{{placeholder}}}' has no matching entry in schema.input.properties"
                ),
            ));
        }
    }
}

/// CAP-009: Duplicate capability names across files.
///
/// Returns `(file_path, Issue)` pairs so callers can attach them to the right file.
fn check_duplicate_names(
    caps: &[(String, CapabilityDefinition)],
) -> Vec<(String, Issue)> {
    let mut seen: HashMap<&str, &str> = HashMap::new(); // name -> first_path
    let mut results = Vec::new();

    for (path, cap) in caps {
        if cap.name.is_empty() {
            continue;
        }
        match seen.get(cap.name.as_str()) {
            Some(&first_path) => {
                results.push((
                    path.clone(),
                    Issue::warning(
                        "CAP-009",
                        format!(
                            "capability name '{}' is also defined in '{}'; the last-loaded definition wins",
                            cap.name, first_path
                        ),
                    ).with_field("name"),
                ));
            }
            None => {
                seen.insert(&cap.name, path);
            }
        }
    }

    results
}

/// Warn when the file stem (sans extension) does not match the `name` field.
///
/// This is informational — mismatches lead to confusion but are not blocking.
fn check_path_label(file_path: &str, name: &str, issues: &mut Vec<Issue>) {
    let stem = std::path::Path::new(file_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    if !stem.is_empty() && !name.is_empty() && stem != name {
        issues.push(Issue::warning(
            "CAP-010",
            format!("file name '{stem}.yaml' does not match capability name '{name}'; rename the file to match"),
        ).with_field("name"));
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract all `{placeholder}` names from a string.
fn extract_placeholders(text: &str) -> impl Iterator<Item = String> + '_ {
    let mut out = Vec::new();
    let mut chars = text.char_indices().peekable();

    while let Some((i, ch)) = chars.next() {
        if ch == '{' {
            let start = i + 1;
            let mut end = start;
            for (j, c) in chars.by_ref() {
                if c == '}' {
                    end = j;
                    break;
                }
            }
            if end > start {
                out.push(text[start..end].to_string());
            }
        }
    }

    out.into_iter()
}

/// Collect all top-level property names from a JSON Schema input.
fn extract_input_property_names(input: &serde_json::Value) -> HashSet<String> {
    input
        .get("properties")
        .and_then(|p| p.as_object())
        .map(|props| props.keys().cloned().collect())
        .unwrap_or_default()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{
        AuthConfig, CacheConfig, CapabilityDefinition, CapabilityMetadata, ProvidersConfig,
        ProviderConfig, RestConfig, SchemaDefinition,
    };
    use crate::transform::TransformConfig;
    use serde_json::json;
    use std::collections::HashMap;

    // ── Builder helpers ───────────────────────────────────────────────────────

    fn minimal_cap(name: &str) -> CapabilityDefinition {
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

    fn providers_with_base_url(base_url: &str) -> ProvidersConfig {
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

    fn providers_with_path(base_url: &str, path: &str) -> ProvidersConfig {
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

    fn with_input_schema(mut cap: CapabilityDefinition, schema: serde_json::Value) -> CapabilityDefinition {
        cap.schema.input = schema;
        cap
    }

    fn errors_of(issues: &[Issue]) -> Vec<Issue> {
        issues.iter().filter(|i| i.severity == IssueSeverity::Error).cloned().collect()
    }

    fn warnings_of(issues: &[Issue]) -> Vec<Issue> {
        issues.iter().filter(|i| i.severity == IssueSeverity::Warning).cloned().collect()
    }

    fn has_code(issues: &[Issue], code: &str) -> bool {
        issues.iter().any(|i| i.code == code)
    }

    // ── CAP-001: name validation ──────────────────────────────────────────────

    #[test]
    fn name_valid_passes() {
        // GIVEN: lowercase alphanumeric+underscore name
        // WHEN: validating
        // THEN: no issues
        let cap = minimal_cap("web_search_v2");
        let issues = validate_capability_definition(&cap, None);
        assert!(!has_code(&issues, "CAP-001"), "unexpected CAP-001: {:?}", issues);
    }

    #[test]
    fn name_empty_is_error() {
        // GIVEN: empty name
        // WHEN: validating
        // THEN: CAP-001 error
        let cap = minimal_cap("");
        let issues = validate_capability_definition(&cap, None);
        assert!(has_code(&errors_of(&issues), "CAP-001"), "expected CAP-001 error");
    }

    #[test]
    fn name_with_uppercase_is_error() {
        // GIVEN: name contains uppercase letter
        // WHEN: validating
        // THEN: CAP-001 error
        let cap = minimal_cap("WebSearch");
        let issues = validate_capability_definition(&cap, None);
        assert!(has_code(&errors_of(&issues), "CAP-001"), "expected CAP-001 error");
    }

    #[test]
    fn name_with_hyphen_is_error() {
        // GIVEN: name contains hyphen
        // WHEN: validating
        // THEN: CAP-001 error
        let cap = minimal_cap("web-search");
        let issues = validate_capability_definition(&cap, None);
        assert!(has_code(&errors_of(&issues), "CAP-001"), "expected CAP-001 error");
    }

    #[test]
    fn name_with_space_is_error() {
        // GIVEN: name contains space
        // WHEN: validating
        // THEN: CAP-001 error
        let cap = minimal_cap("web search");
        let issues = validate_capability_definition(&cap, None);
        assert!(has_code(&errors_of(&issues), "CAP-001"), "expected CAP-001 error");
    }

    // ── CAP-002: description validation ──────────────────────────────────────

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
        assert!(has_code(&warnings_of(&issues), "CAP-002"), "expected CAP-002 warning");
    }

    #[test]
    fn description_over_500_chars_is_warning() {
        // GIVEN: description longer than 500 chars
        // WHEN: validating
        // THEN: CAP-002 warning
        let mut cap = minimal_cap("my_tool");
        cap.description = "x".repeat(501);
        let issues = validate_capability_definition(&cap, None);
        assert!(has_code(&warnings_of(&issues), "CAP-002"), "expected CAP-002 warning");
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

    // ── CAP-003: schema.input validation ─────────────────────────────────────

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
        assert!(has_code(&errors_of(&issues), "CAP-003"), "expected CAP-003 error");
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
        assert!(has_code(&errors_of(&issues), "CAP-003"), "expected CAP-003 error");
    }

    // ── CAP-005: provider validation ──────────────────────────────────────────

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
        assert!(has_code(&errors_of(&issues), "CAP-005"), "expected CAP-005 error");
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
        cap.providers = ProvidersConfig { named, fallback: vec![] };
        let issues = validate_capability_definition(&cap, None);
        assert!(has_code(&errors_of(&issues), "CAP-005"), "expected CAP-005 error");
    }

    // ── CAP-006: dangling placeholders ────────────────────────────────────────

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
        assert!(!has_code(&errors_of(&issues), "CAP-006"), "unexpected CAP-006: {:?}", issues);
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
        assert!(has_code(&errors_of(&issues), "CAP-006"), "expected CAP-006 error");
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
        assert!(!has_code(&errors_of(&issues), "CAP-006"), "unexpected CAP-006");
    }

    // ── CAP-007: static_params overlap ───────────────────────────────────────

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
                        m.insert("format".to_string(), serde_json::Value::String("xml".to_string()));
                        m
                    },
                    ..RestConfig::default()
                },
            },
        );
        let mut cap = minimal_cap("my_tool");
        cap.providers = ProvidersConfig { named, fallback: vec![] };
        let issues = validate_capability_definition(&cap, None);
        assert!(has_code(&warnings_of(&issues), "CAP-007"), "expected CAP-007 warning");
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
                        m.insert("format".to_string(), serde_json::Value::String("json".to_string()));
                        m
                    },
                    ..RestConfig::default()
                },
            },
        );
        let mut cap = minimal_cap("my_tool");
        cap.providers = ProvidersConfig { named, fallback: vec![] };
        let issues = validate_capability_definition(&cap, None);
        assert!(!has_code(&warnings_of(&issues), "CAP-007"));
    }

    // ── CAP-008: URL validation ───────────────────────────────────────────────

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
        assert!(has_code(&errors_of(&issues), "CAP-008"), "expected CAP-008 error");
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
        assert!(has_code(&warnings_of(&issues), "CAP-008"), "expected CAP-008 warning");
    }

    // ── CAP-009: duplicate names ──────────────────────────────────────────────

    #[test]
    fn duplicate_capability_names_are_warned() {
        // GIVEN: two capabilities share the same name
        // WHEN: validate_capabilities is called
        // THEN: CAP-009 warning for the second file
        let caps = vec![
            ("capabilities/a/tool.yaml".to_string(), minimal_cap("my_tool")),
            ("capabilities/b/tool.yaml".to_string(), minimal_cap("my_tool")),
        ];
        let results = validate_capabilities(&caps);
        let second_issues = results.get("capabilities/b/tool.yaml").map(Vec::as_slice).unwrap_or(&[]);
        assert!(has_code(second_issues, "CAP-009"), "expected CAP-009 warning: {:?}", second_issues);
    }

    #[test]
    fn unique_capability_names_pass_duplicate_check() {
        // GIVEN: two capabilities with distinct names
        // WHEN: validate_capabilities is called
        // THEN: no CAP-009 warnings
        let caps = vec![
            ("capabilities/a/tool_a.yaml".to_string(), minimal_cap("tool_a")),
            ("capabilities/b/tool_b.yaml".to_string(), minimal_cap("tool_b")),
        ];
        let results = validate_capabilities(&caps);
        let all_issues: Vec<Issue> = results.into_values().flatten().collect();
        assert!(!has_code(&all_issues, "CAP-009"));
    }

    // ── extract_placeholders ──────────────────────────────────────────────────

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

    // ── Full round-trip with YAML ──────────────────────────────────────────────

    #[test]
    fn valid_capability_yaml_passes_all_checks() {
        // GIVEN: a well-formed capability YAML string
        // WHEN: parsed and validated
        // THEN: no errors, at most informational warnings
        let yaml = r#"
fulcrum: "1.0"
name: brave_search
description: Search the web using Brave.
schema:
  input:
    type: object
    properties:
      query:
        type: string
        description: The search query
    required: [query]
providers:
  primary:
    service: rest
    config:
      base_url: https://api.search.brave.com
      path: /res/v1/web/search
      params:
        q: "{query}"
"#;
        let cap: CapabilityDefinition = serde_yaml::from_str(yaml).unwrap();
        let issues = validate_capability_definition(&cap, None);
        let errors: Vec<_> = errors_of(&issues);
        assert!(errors.is_empty(), "unexpected errors: {:?}", errors);
    }

    #[test]
    fn wrong_provider_format_yaml_is_detected() {
        // GIVEN: providers key contains an array instead of a named map
        // WHEN: parsed — serde handles gracefully — and validated
        // THEN: the structural validator catches the missing base_url/endpoint
        let yaml = r#"
name: broken_tool
description: Broken provider format.
providers:
  primary:
    service: rest
    config:
      base_url: ""
      path: /v1/search
"#;
        let cap: CapabilityDefinition = serde_yaml::from_str(yaml).unwrap();
        let issues = validate_capability_definition(&cap, None);
        assert!(has_code(&errors_of(&issues), "CAP-005"), "expected CAP-005: {:?}", issues);
    }

    #[test]
    fn missing_schema_placeholder_in_path_is_detected() {
        // GIVEN: path uses {missing_param} but schema has no such property
        // WHEN: validating
        // THEN: CAP-006 error
        let yaml = r#"
name: get_item
description: Get an item by ID.
schema:
  input:
    type: object
    properties:
      name:
        type: string
        description: Item name
providers:
  primary:
    service: rest
    config:
      base_url: https://api.example.com
      path: /v1/items/{item_id}
"#;
        let cap: CapabilityDefinition = serde_yaml::from_str(yaml).unwrap();
        let issues = validate_capability_definition(&cap, None);
        assert!(has_code(&errors_of(&issues), "CAP-006"), "expected CAP-006: {:?}", issues);
    }
}
