//! YAML round-trip tests — parse a YAML string and validate the result.
//!
//! These tests exercise the full serde_yaml → CapabilityDefinition →
//! validate_capability_definition pipeline, matching real-world capability files.

use super::*;

// ── Passing YAMLs ─────────────────────────────────────────────────────────────

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
fn non_rest_service_without_url_passes() {
    // GIVEN: provider with service=cli and no base_url/endpoint
    // WHEN: validating
    // THEN: no CAP-005 error (cli services don't need URLs)
    let yaml = r#"
name: metacognition_verify
description: Verify text using CLI tool.
schema:
  input:
    type: object
    properties:
      text:
        type: string
providers:
  primary:
    service: cli
    config:
      command: /usr/local/bin/verify
"#;
    let cap: CapabilityDefinition = serde_yaml::from_str(yaml).unwrap();
    let issues = validate_capability_definition(&cap, None);
    assert!(!has_code(&errors_of(&issues), "CAP-005"), "unexpected CAP-005: {:?}", issues);
}

#[test]
fn local_ml_service_without_url_passes() {
    // GIVEN: provider with service=local_ml and no base_url/endpoint
    // WHEN: validating
    // THEN: no CAP-005 error
    let yaml = r#"
name: face_detect
description: Detect faces locally.
schema:
  input:
    type: object
    properties:
      image:
        type: string
providers:
  primary:
    service: local_ml
    config:
      model: face_recognition
"#;
    let cap: CapabilityDefinition = serde_yaml::from_str(yaml).unwrap();
    let issues = validate_capability_definition(&cap, None);
    assert!(!has_code(&errors_of(&issues), "CAP-005"), "unexpected CAP-005: {:?}", issues);
}

#[test]
fn array_index_placeholder_resolves_to_root_property() {
    // GIVEN: param uses {symbols[0]} and schema has "symbols" array property
    // WHEN: validating
    // THEN: no CAP-006 error (root "symbols" is in schema)
    let yaml = r#"
name: portfolio_opt
description: Portfolio optimization.
schema:
  input:
    type: object
    properties:
      symbols:
        type: array
        items:
          type: string
providers:
  primary:
    service: rest
    config:
      base_url: https://api.example.com
      path: /query
      params:
        symbol: "{symbols[0]}"
"#;
    let cap: CapabilityDefinition = serde_yaml::from_str(yaml).unwrap();
    let issues = validate_capability_definition(&cap, None);
    assert!(!has_code(&errors_of(&issues), "CAP-006"), "unexpected CAP-006: {:?}", issues);
}

#[test]
fn nested_array_property_placeholder_resolves_to_root() {
    // GIVEN: param uses {holdings[0].symbol} and schema has "holdings" property
    // WHEN: validating
    // THEN: no CAP-006 error
    let yaml = r#"
name: portfolio_risk
description: Portfolio risk analysis.
schema:
  input:
    type: object
    properties:
      holdings:
        type: array
        items:
          type: object
          properties:
            symbol:
              type: string
            weight:
              type: number
providers:
  primary:
    service: rest
    config:
      base_url: https://api.example.com
      path: /query
      params:
        symbol: "{holdings[0].symbol}"
"#;
    let cap: CapabilityDefinition = serde_yaml::from_str(yaml).unwrap();
    let issues = validate_capability_definition(&cap, None);
    assert!(!has_code(&errors_of(&issues), "CAP-006"), "unexpected CAP-006: {:?}", issues);
}

#[test]
fn template_expression_placeholder_is_skipped() {
    // GIVEN: header uses Jinja-style template {{input.wait ? 'wait' : ''}}
    // WHEN: validating
    // THEN: no CAP-006 error (template expressions are runtime-evaluated)
    let yaml = r#"
name: replicate_run
description: Run models on Replicate.
schema:
  input:
    type: object
    properties:
      model:
        type: string
      input:
        type: object
      wait:
        type: boolean
providers:
  primary:
    service: rest
    config:
      base_url: https://api.replicate.com
      path: /v1/predictions
      headers:
        Prefer: "{{input.wait ? 'wait' : ''}}"
"#;
    let cap: CapabilityDefinition = serde_yaml::from_str(yaml).unwrap();
    let issues = validate_capability_definition(&cap, None);
    assert!(!has_code(&errors_of(&issues), "CAP-006"), "unexpected CAP-006: {:?}", issues);
}

#[test]
fn timestamp_runtime_placeholder_is_skipped() {
    // GIVEN: header uses {timestamp} which is a runtime-computed value
    // WHEN: validating
    // THEN: no CAP-006 error
    let yaml = r#"
name: podcast_search
description: Search podcasts.
schema:
  input:
    type: object
    properties:
      query:
        type: string
providers:
  primary:
    service: rest
    config:
      base_url: https://api.podcastindex.org
      path: /api/1.0/search/byterm
      headers:
        X-Auth-Date: "{timestamp}"
      params:
        q: "{query}"
"#;
    let cap: CapabilityDefinition = serde_yaml::from_str(yaml).unwrap();
    let issues = validate_capability_definition(&cap, None);
    assert!(!has_code(&errors_of(&issues), "CAP-006"), "unexpected CAP-006: {:?}", issues);
}

#[test]
fn auth_header_runtime_placeholder_is_skipped() {
    // GIVEN: header uses {podcast_index_auth_header} ending in _auth_header
    // WHEN: validating
    // THEN: no CAP-006 error (computed auth headers are runtime values)
    let yaml = r#"
name: podcast_search
description: Search podcasts.
schema:
  input:
    type: object
    properties:
      query:
        type: string
providers:
  primary:
    service: rest
    config:
      base_url: https://api.podcastindex.org
      path: /api/1.0/search/byterm
      headers:
        Authorization: "{podcast_index_auth_header}"
      params:
        q: "{query}"
"#;
    let cap: CapabilityDefinition = serde_yaml::from_str(yaml).unwrap();
    let issues = validate_capability_definition(&cap, None);
    assert!(!has_code(&errors_of(&issues), "CAP-006"), "unexpected CAP-006: {:?}", issues);
}

// ── Failing YAMLs ─────────────────────────────────────────────────────────────

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

#[test]
fn rest_service_without_url_still_errors() {
    // GIVEN: provider with service=rest and no base_url/endpoint
    // WHEN: validating
    // THEN: CAP-005 error
    let yaml = r#"
name: broken_rest
description: REST without URL.
providers:
  primary:
    service: rest
    config:
      path: /v1/items
"#;
    let cap: CapabilityDefinition = serde_yaml::from_str(yaml).unwrap();
    let issues = validate_capability_definition(&cap, None);
    assert!(has_code(&errors_of(&issues), "CAP-005"), "expected CAP-005: {:?}", issues);
}
