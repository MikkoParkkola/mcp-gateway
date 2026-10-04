// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The response transform field and `TransformConfig::is_empty`.

use super::*;

// ── response_transform field ──────────────────────────────────────────────────

#[test]
fn response_transform_defaults_to_empty_when_absent_from_yaml() {
    // GIVEN: a capability YAML with no response_transform section
    let yaml = r"
name: my_tool
description: A tool
providers:
  primary:
    service: rest
    config:
      base_url: https://example.com
      path: /v1/test
";
    // WHEN: deserializing
    let cap: CapabilityDefinition = serde_yaml::from_str(yaml).unwrap();
    // THEN: response_transform is empty / noop
    assert!(cap.response_transform.project.is_empty());
    assert!(cap.response_transform.rename.is_empty());
    assert!(cap.response_transform.redact.is_empty());
    assert!(cap.response_transform.format.is_none());
    assert!(cap.response_transform.is_empty());
}

#[test]
fn response_transform_project_deserializes_from_yaml() {
    // GIVEN: a capability YAML with response_transform.project
    let yaml = r"
name: my_tool
description: A tool
providers:
  primary:
    service: rest
    config:
      base_url: https://example.com
      path: /v1/test
response_transform:
  project:
    - id
    - name
";
    // WHEN: deserializing
    let cap: CapabilityDefinition = serde_yaml::from_str(yaml).unwrap();
    // THEN: project fields are populated
    assert_eq!(cap.response_transform.project, vec!["id", "name"]);
    assert!(!cap.response_transform.is_empty());
}

#[test]
fn response_transform_redact_deserializes_from_yaml() {
    // GIVEN: a capability YAML with response_transform.redact
    let yaml = r"
name: my_tool
description: A tool
providers:
  primary:
    service: rest
    config:
      base_url: https://example.com
      path: /v1/test
response_transform:
  redact:
    - pattern: '\bsecret\b'
      replacement: '[REDACTED]'
";
    // WHEN: deserializing
    let cap: CapabilityDefinition = serde_yaml::from_str(yaml).unwrap();
    // THEN: redact rules are populated
    assert_eq!(cap.response_transform.redact.len(), 1);
    assert_eq!(cap.response_transform.redact[0].pattern, r"\bsecret\b");
    assert_eq!(cap.response_transform.redact[0].replacement, "[REDACTED]");
    assert!(!cap.response_transform.is_empty());
}

// ── TransformConfig::is_empty ─────────────────────────────────────────────────

#[test]
fn transform_config_is_empty_on_default() {
    // GIVEN: default TransformConfig
    // WHEN: checking is_empty
    // THEN: returns true
    assert!(crate::transform::TransformConfig::default().is_empty());
}

#[test]
fn transform_config_is_not_empty_when_project_set() {
    // GIVEN: TransformConfig with project fields
    let config = crate::transform::TransformConfig {
        project: vec!["id".to_string()],
        ..Default::default()
    };
    // WHEN: checking is_empty
    // THEN: returns false
    assert!(!config.is_empty());
}

#[test]
fn response_transform_skipped_in_serialization_when_empty() {
    // GIVEN: a capability with empty response_transform
    let cap = make_capability("test_tool", "Test", vec![]);
    // WHEN: serializing to YAML
    let yaml = serde_yaml::to_string(&cap).unwrap();
    // THEN: response_transform key is absent (skip_serializing_if)
    assert!(!yaml.contains("response_transform"));
}

#[test]
fn response_transform_included_in_serialization_when_non_empty() {
    // GIVEN: a capability with non-empty response_transform
    let mut cap = make_capability("test_tool", "Test", vec![]);
    cap.response_transform.project = vec!["id".to_string()];
    // WHEN: serializing to YAML
    let yaml = serde_yaml::to_string(&cap).unwrap();
    // THEN: response_transform key is present
    assert!(yaml.contains("response_transform"));
}
