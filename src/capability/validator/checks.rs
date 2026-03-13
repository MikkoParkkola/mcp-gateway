//! Individual structural checks for capability definitions.
//!
//! Each `check_*` function appends zero or more [`Issue`]s to the provided
//! `issues` vec.  They are called by the public entry points in `mod.rs`.

use std::collections::{HashMap, HashSet};

use crate::capability::{CapabilityDefinition, RestConfig};

use super::Issue;

// ── CAP-001 ───────────────────────────────────────────────────────────────────

/// CAP-001: name must be non-empty, lowercase, alphanumeric + underscores.
pub(super) fn check_name(name: &str, issues: &mut Vec<Issue>) {
    if name.is_empty() {
        issues.push(Issue::error("CAP-001", "name is required").with_field("name"));
        return;
    }

    let valid = name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if !valid {
        issues.push(Issue::error(
            "CAP-001",
            format!(
                "name '{name}' must be lowercase alphanumeric and underscores only (no spaces, hyphens, or uppercase)",
            ),
        ).with_field("name"));
    }
}

// ── CAP-002 ───────────────────────────────────────────────────────────────────

/// Maximum description length before issuing a CAP-002 warning.
const MAX_DESCRIPTION_LEN: usize = 500;

/// CAP-002: description must be non-empty and under 500 characters.
pub(super) fn check_description(description: &str, issues: &mut Vec<Issue>) {
    if description.trim().is_empty() {
        issues.push(
            Issue::warning(
                "CAP-002",
                "description is empty; add a meaningful description",
            )
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

// ── CAP-003 ───────────────────────────────────────────────────────────────────

/// CAP-003: schema.input must be a valid JSON Schema object with `type: object`
/// and a non-empty `properties` map.
pub(super) fn check_schema_input(input: &serde_json::Value, issues: &mut Vec<Issue>) {
    if input.is_null() || *input == serde_json::Value::Object(serde_json::Map::default()) {
        // Empty schema is not an error for webhook-only capabilities, but worth warning.
        return;
    }

    if let Some(t) = input.get("type").and_then(|v| v.as_str()) {
        if t != "object" {
            issues.push(
                Issue::error(
                    "CAP-003",
                    format!("schema.input.type must be 'object', got '{t}'"),
                )
                .with_field("schema.input.type"),
            );
        }
    } else if input.is_object() {
        // Tolerate missing type when the value is an object (some YAMLs omit it).
    }

    // Properties must be an object, not an array.
    if let Some(props) = input.get("properties")
        && !props.is_object()
    {
        issues.push(
            Issue::error(
                "CAP-003",
                "schema.input.properties must be a YAML mapping (object), not an array",
            )
            .with_field("schema.input.properties"),
        );
    }
}

// ── CAP-004 ───────────────────────────────────────────────────────────────────

/// CAP-004: schema.output, if present, must be a valid JSON Schema object.
pub(super) fn check_schema_output(output: &serde_json::Value, issues: &mut Vec<Issue>) {
    if output.is_null() {
        return;
    }

    if let Some(t) = output.get("type").and_then(|v| v.as_str())
        && t != "object"
    {
        issues.push(
            Issue::warning(
                "CAP-004",
                format!("schema.output.type should be 'object', got '{t}'"),
            )
            .with_field("schema.output.type"),
        );
    }

    if let Some(props) = output.get("properties")
        && !props.is_object()
    {
        issues.push(
            Issue::error(
                "CAP-004",
                "schema.output.properties must be a YAML mapping (object), not an array",
            )
            .with_field("schema.output.properties"),
        );
    }
}

// ── CAP-005 / CAP-006 / CAP-007 / CAP-008 ────────────────────────────────────

/// CAP-005: providers must use named entries (e.g. `primary:`), not a list.
/// Each provider must have `base_url` or `endpoint`.
/// CAP-006: All `{param}` placeholders in URL/path must exist in `schema.input.properties`.
/// CAP-007: `static_params` keys must not overlap with `params` keys.
/// CAP-008: `base_url` must be a valid URL; `path` must start with `'/'`.
pub(super) fn check_providers(cap: &CapabilityDefinition, issues: &mut Vec<Issue>) {
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
        check_rest_config(
            &provider.config,
            &provider.service,
            &ctx,
            &schema_props,
            issues,
        );
    }

    for (idx, provider) in cap.providers.fallback.iter().enumerate() {
        let ctx = format!("providers.fallback[{idx}]");
        check_rest_config(
            &provider.config,
            &provider.service,
            &ctx,
            &schema_props,
            issues,
        );
    }
}

/// Service types that require a `base_url` or endpoint.
///
/// Non-REST services (cli, `local_binary`, `local_ml`, microfetch, etc.) use
/// other config fields (command, binary, handler) and should not be rejected
/// for missing URL fields.
const REST_LIKE_SERVICES: &[&str] = &["rest", "graphql"];

/// Returns true if this service type requires `base_url` or endpoint.
pub(super) fn service_requires_url(service: &str) -> bool {
    REST_LIKE_SERVICES.contains(&service)
}

/// Validate a single `RestConfig` entry.
fn check_rest_config(
    config: &RestConfig,
    service: &str,
    context: &str,
    schema_props: &HashSet<String>,
    issues: &mut Vec<Issue>,
) {
    let has_base_url = !config.base_url.is_empty();
    let has_endpoint = !config.endpoint.is_empty();
    let has_path = !config.path.is_empty();

    // CAP-005: Only require base_url/endpoint for REST-like services.
    // Non-REST services (cli, local_binary, local_ml, microfetch, folo, etc.)
    // use alternative config fields and don't need URLs.
    if !has_base_url && !has_endpoint && service_requires_url(service) {
        issues.push(Issue::error(
            "CAP-005",
            format!("{context}: provider must have 'base_url' or 'endpoint'"),
        ));
    }

    // CAP-008: base_url must parse as a valid URL.
    // Skip validation when URL contains template references (e.g. {env.VAR})
    // since these are resolved at runtime, not parse-time.
    let contains_template = |s: &str| s.contains('{');
    if has_base_url
        && !contains_template(&config.base_url)
        && url::Url::parse(&config.base_url).is_err()
    {
        issues.push(Issue::error(
            "CAP-008",
            format!(
                "{context}: base_url '{}' is not a valid URL",
                config.base_url
            ),
        ));
    }

    if has_endpoint
        && !contains_template(&config.endpoint)
        && url::Url::parse(&config.endpoint).is_err()
    {
        issues.push(Issue::error(
            "CAP-008",
            format!(
                "{context}: endpoint '{}' is not a valid URL",
                config.endpoint
            ),
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
        check_placeholders_in_text(
            value,
            context,
            &format!("params.{key}"),
            schema_props,
            issues,
        );
    }

    for (key, value) in &config.headers {
        check_placeholders_in_text(
            value,
            context,
            &format!("headers.{key}"),
            schema_props,
            issues,
        );
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

// ── CAP-006 placeholder helpers ───────────────────────────────────────────────

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
        // timestamp — computed auth timestamp
        // *_auth_header — computed HMAC/auth headers
        const RUNTIME_PLACEHOLDERS: &[&str] = &[
            "access_token",
            "refresh_token",
            "api_key",
            "bearer_token",
            "auth_token",
            "timestamp",
        ];
        if placeholder.starts_with("env.")
            || placeholder.starts_with("keychain.")
            || placeholder.starts_with("oauth.")
            || RUNTIME_PLACEHOLDERS.contains(&placeholder.as_str())
            // Computed auth headers (e.g. {podcast_index_auth_header})
            || placeholder.ends_with("_auth_header")
        {
            continue;
        }

        // Template expressions (e.g. {{input.wait ? 'wait' : ''}}) start with
        // '{' when the outer braces have already been stripped.  These are
        // evaluated at runtime, not simple schema references.
        if placeholder.starts_with('{') || placeholder.contains('?') {
            continue;
        }

        // Array-index access patterns like `symbols[0]` or `holdings[0].symbol`
        // reference a top-level schema property that is an array.  Extract the
        // root property name and validate that instead.
        let prop_name = if let Some(bracket_pos) = placeholder.find('[') {
            &placeholder[..bracket_pos]
        } else if let Some(dot_pos) = placeholder.find('.') {
            // Nested property access like `foo.bar` — check the root property.
            // (env/keychain/oauth prefixes are already handled above.)
            &placeholder[..dot_pos]
        } else {
            placeholder.as_str()
        };

        if !schema_props.contains(prop_name) {
            issues.push(Issue::error(
                "CAP-006",
                format!(
                    "{context}.{field}: placeholder '{{{placeholder}}}' has no matching entry in schema.input.properties"
                ),
            ));
        }
    }
}

// ── CAP-009 ───────────────────────────────────────────────────────────────────

/// CAP-009: Duplicate capability names across files.
///
/// Returns `(file_path, Issue)` pairs so callers can attach them to the right file.
pub(super) fn check_duplicate_names(
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

// ── CAP-010 ───────────────────────────────────────────────────────────────────

/// Warn when the file stem (sans extension) does not match the `name` field.
///
/// This is informational — mismatches lead to confusion but are not blocking.
pub(super) fn check_path_label(file_path: &str, name: &str, issues: &mut Vec<Issue>) {
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
pub(super) fn extract_placeholders(text: &str) -> impl Iterator<Item = String> + '_ {
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
pub(super) fn extract_input_property_names(input: &serde_json::Value) -> HashSet<String> {
    input
        .get("properties")
        .and_then(|p| p.as_object())
        .map(|props| props.keys().cloned().collect())
        .unwrap_or_default()
}
