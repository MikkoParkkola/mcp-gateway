// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use serde_json::json;

use super::*;
use crate::protocol::{Tool, ToolAnnotations};

fn tool_with_annotations(name: &str, annotations: Option<ToolAnnotations>) -> Tool {
    Tool {
        name: name.to_string(),
        title: None,
        description: Some(format!("{name} tool")),
        input_schema: json!({"type": "object", "properties": {"q": {"type": "string"}}}),
        output_schema: None,
        annotations,
        role: None,
        projection: None,
    }
}

#[test]
fn trust_card_from_tool_has_deterministic_cbom_digest() {
    let tool = tool_with_annotations("search_docs", None);

    let left = TrustCard::from_tool("server", &tool);
    let right = TrustCard::from_tool("server", &tool);

    assert_eq!(
        left.cbom.components[0].digest_sha256,
        right.cbom.components[0].digest_sha256
    );
    assert_eq!(left.cbom.schema_version, CBOM_SCHEMA_VERSION);
}

#[test]
fn trust_card_cbom_exposes_explicit_policy_surfaces() {
    let tool = tool_with_annotations(
        "search_docs",
        Some(ToolAnnotations {
            title: None,
            read_only_hint: Some(true),
            destructive_hint: Some(false),
            idempotent_hint: None,
            open_world_hint: Some(false),
        }),
    );

    let card = TrustCard::from_tool("server", &tool);

    assert_eq!(card.cbom.tools.len(), 1);
    assert_eq!(card.cbom.tools[0].name, "search_docs");
    assert_eq!(
        card.cbom.tools[0].input_schema_sha256,
        card.cbom.components[0].digest_sha256.clone().unwrap()
    );
    assert_eq!(card.cbom.annotations.len(), 1);
    assert_eq!(card.cbom.annotations[0].subject_name, "search_docs");
    assert_eq!(card.cbom.annotations[0].annotations.read_only, Some(true));
    assert!(
        card.cbom
            .provenance
            .iter()
            .any(|entry| entry.source_uri == "protocol.tools/list")
    );
}

#[test]
fn validator_warns_for_missing_publisher_license_and_source() {
    let tool = tool_with_annotations("search_docs", None);
    let card = TrustCard::from_tool("server", &tool);

    let report = TrustCardValidator::validate(&card);
    let codes = report
        .findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect::<Vec<_>>();

    assert_eq!(report.status, TrustEvaluationStatus::Warning);
    assert!(codes.contains(&"TRUST_PUBLISHER_MISSING"));
    assert!(codes.contains(&"TRUST_LICENSE_MISSING"));
    assert!(codes.contains(&"TRUST_SOURCE_MISSING"));
}

#[test]
fn assistant_groups_missing_fields_into_decisions() {
    let tool = tool_with_annotations("search_docs", None);
    let card = TrustCard::from_tool("server", &tool);

    let plan = TrustCardAssistant::plan(&card);

    assert_eq!(plan.schema_version, TRUST_CARD_ASSISTANT_SCHEMA_VERSION);
    assert_eq!(plan.finding_count, 5);
    assert!(
        plan.automation_actions
            .iter()
            .any(|action| action.action_id == "scan-package-metadata")
    );

    let source_prompt = plan
        .human_decisions
        .iter()
        .find(|prompt| prompt.prompt_id == "source-ownership")
        .unwrap();
    assert_eq!(
        source_prompt.fields,
        vec![
            "server.publisher".to_string(),
            "server.source_uri".to_string()
        ]
    );
    assert!(
        source_prompt
            .finding_codes
            .contains(&"TRUST_PUBLISHER_MISSING".to_string())
    );
    assert!(
        source_prompt
            .finding_codes
            .contains(&"TRUST_SOURCE_MISSING".to_string())
    );
    assert!(
        plan.human_decisions
            .iter()
            .any(|prompt| prompt.prompt_id == "license-review")
    );
}

#[test]
fn assistant_has_no_prompts_for_valid_card() {
    let tool = tool_with_annotations(
        "search_docs",
        Some(ToolAnnotations {
            title: None,
            read_only_hint: Some(true),
            destructive_hint: Some(false),
            idempotent_hint: None,
            open_world_hint: Some(false),
        }),
    );
    let mut card = TrustCard::from_tool("server", &tool);
    card.server.publisher = Some("Example Maintainers".to_string());
    card.server.license = Some("MIT".to_string());
    card.server.source_uri = Some("https://example.invalid/server".to_string());
    card.server.transport = TrustTransport::Http;
    card.server.risk_class = TrustRiskClass::Low;
    let card = card.with_validation();

    let plan = TrustCardAssistant::plan(&card);

    assert_eq!(card.evaluation_status, TrustEvaluationStatus::Passed);
    assert!(plan.human_decisions.is_empty());
    assert!(plan.automation_actions.is_empty());
}

#[test]
fn validator_fails_missing_server_name() {
    let tool = tool_with_annotations("search_docs", None);
    let mut card = TrustCard::from_tool("server", &tool);
    card.server.name.clear();

    let report = TrustCardValidator::validate(&card);

    assert_eq!(report.status, TrustEvaluationStatus::Failed);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "TRUST_SERVER_NAME")
    );
}

#[test]
fn destructive_open_world_tool_degrades_risk() {
    let tool = tool_with_annotations(
        "update_gmail_message",
        Some(ToolAnnotations {
            title: None,
            read_only_hint: Some(false),
            destructive_hint: Some(true),
            idempotent_hint: None,
            open_world_hint: Some(true),
        }),
    );

    let card = TrustCard::from_tool("gmail", &tool);

    assert_eq!(card.server.risk_class, TrustRiskClass::Medium);
    assert!(card.server.permissions.contains(&TrustPermission::Network));
    assert!(card.server.permissions.contains(&TrustPermission::Write));
    assert!(card.server.data_classes.contains(&TrustDataClass::Personal));
}

#[test]
fn capability_generation_infers_transport_and_auth_mode() {
    let capability: CapabilityDefinition = serde_yaml::from_str(
        "
name: weather_lookup
description: Read weather forecasts
providers:
  primary:
    service: rest
    config:
      base_url: https://example.invalid
auth:
  required: true
  type: oauth
schema:
  input:
    type: object
    properties:
      city:
        type: string
",
    )
    .unwrap();

    let card = TrustCard::from_capability(&capability).with_validation();

    assert_eq!(card.server.transport, TrustTransport::Http);
    assert_eq!(card.server.auth_mode, TrustAuthMode::OAuth);
    assert_eq!(card.evaluation_status, TrustEvaluationStatus::Warning);
    assert_eq!(card.cbom.components.len(), 1);
    assert_eq!(card.cbom.tools.len(), 1);
    assert_eq!(card.cbom.dependencies.len(), 1);
    assert_eq!(card.cbom.dependencies[0].name, "weather_lookup");
    assert!(
        card.cbom
            .provenance
            .iter()
            .any(|entry| entry.subject_name == "weather_lookup")
    );
}

#[test]
fn old_tool_without_annotations_still_generates_card() {
    let tool = tool_with_annotations("plain_tool", None);

    let card = TrustCard::from_tool("legacy", &tool).with_validation();

    assert_eq!(card.server.name, "legacy");
    assert_eq!(card.cbom.components[0].kind, CbomComponentKind::Tool);
    assert_eq!(card.server.permissions, vec![TrustPermission::Unknown]);
}
