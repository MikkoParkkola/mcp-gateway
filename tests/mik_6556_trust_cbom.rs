use std::{fs, path::Path};

use mcp_gateway::{
    protocol::{Prompt, PromptArgument, Resource, Tool, ToolAnnotations},
    trust::{generator, schema::TrustCard},
};
use serde_json::json;

#[test]
fn mik_6556_schema_facade_and_generator_emit_explicit_cbom_fields() {
    let tool = Tool {
        name: "search_docs".to_string(),
        title: None,
        description: Some("Search docs".to_string()),
        input_schema: json!({"type": "object", "properties": {"q": {"type": "string"}}}),
        output_schema: None,
        annotations: Some(ToolAnnotations {
            title: None,
            read_only_hint: Some(true),
            destructive_hint: Some(false),
            idempotent_hint: None,
            open_world_hint: Some(false),
        }),
        role: None,
        projection: None,
    };

    let card: TrustCard = generator::trust_card_from_tool("docs", &tool);
    let body = serde_json::to_value(&card).expect("TrustCard serializes");

    assert_eq!(body["schema_version"], "trust_card.v1");
    assert_eq!(body["cbom"]["schema_version"], "cbom.v1");
    assert_eq!(body["cbom"]["tools"][0]["name"], "search_docs");
    assert_eq!(
        body["cbom"]["annotations"][0]["annotations"]["read_only"],
        true
    );
    assert_eq!(
        body["cbom"]["provenance"][0]["source_uri"],
        "protocol.tools/list"
    );
    assert!(body["cbom"]["prompts"].as_array().is_some());
    assert!(body["cbom"]["resources"].as_array().is_some());
    assert!(body["cbom"]["dependencies"].as_array().is_some());
    assert_eq!(
        body["cbom"]["components"][0]["digest_sha256"],
        body["cbom"]["tools"][0]["input_schema_sha256"]
    );
}

#[test]
fn mik_6556_live_metadata_generator_captures_prompts_resources_and_is_deterministic() {
    let search_tool = Tool {
        name: "search_docs".to_string(),
        title: None,
        description: Some("Search docs".to_string()),
        input_schema: json!({"type": "object", "properties": {"q": {"type": "string"}}}),
        output_schema: None,
        annotations: Some(ToolAnnotations {
            title: None,
            read_only_hint: Some(true),
            destructive_hint: Some(false),
            idempotent_hint: None,
            open_world_hint: Some(false),
        }),
        role: None,
        projection: None,
    };
    let write_tool = Tool {
        name: "write_docs".to_string(),
        title: None,
        description: Some("Write docs".to_string()),
        input_schema: json!({"type": "object", "properties": {"body": {"type": "string"}}}),
        output_schema: Some(json!({"type": "object", "properties": {"ok": {"type": "boolean"}}})),
        annotations: Some(ToolAnnotations {
            title: None,
            read_only_hint: Some(false),
            destructive_hint: Some(true),
            idempotent_hint: None,
            open_world_hint: Some(false),
        }),
        role: None,
        projection: None,
    };
    let prompt = Prompt {
        name: "summarize".to_string(),
        title: Some("Summarize".to_string()),
        description: None,
        arguments: vec![PromptArgument {
            name: "topic".to_string(),
            description: Some("Topic".to_string()),
            required: true,
        }],
    };
    let resource = Resource {
        uri: "docs://handbook".to_string(),
        name: "handbook".to_string(),
        title: Some("Handbook".to_string()),
        description: Some("Internal handbook".to_string()),
        mime_type: Some("text/markdown".to_string()),
        size: Some(2048),
    };

    let left = generator::trust_card_from_live_metadata(
        "docs",
        &[write_tool.clone(), search_tool.clone()],
        std::slice::from_ref(&prompt),
        std::slice::from_ref(&resource),
    );
    let right = generator::trust_card_from_live_metadata(
        "docs",
        &[search_tool, write_tool],
        std::slice::from_ref(&prompt),
        std::slice::from_ref(&resource),
    );

    let left_json = serde_json::to_value(&left).expect("left TrustCard serializes");
    let right_json = serde_json::to_value(&right).expect("right TrustCard serializes");

    assert_eq!(left_json, right_json);
    assert_eq!(
        left_json["server"]["signature_evidence"][0]["kind"],
        "protocol_metadata"
    );
    assert_eq!(left_json["cbom"]["prompts"][0]["name"], "summarize");
    assert!(
        left_json["cbom"]["prompts"][0]["digest_sha256"]
            .as_str()
            .is_some_and(|digest| !digest.is_empty())
    );
    assert_eq!(left_json["cbom"]["resources"][0]["uri"], "docs://handbook");
    assert_eq!(
        left_json["cbom"]["provenance"][2]["source_uri"],
        "protocol.prompts/list"
    );
    assert!(
        left.cbom
            .components
            .iter()
            .any(|component| component.name == "docs:resource:docs://handbook")
    );
}

#[test]
fn mik_6556_public_docs_cover_license_cli_schema_and_handoffs() {
    let doc_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/trustcard.md");
    let doc = fs::read_to_string(&doc_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", doc_path.display()));
    for required in [
        "TrustCard",
        "CBOM",
        "Free/core",
        "Enterprise",
        "trust inspect",
        "trust generate",
        "trust validate",
        "ShadowRadar",
        "ControlPlaneUI",
        "mcp_gateway::trust::schema",
        "mcp_gateway::trust::generator",
        "tools",
        "prompts",
        "resources",
        "annotations",
        "dependencies",
        "provenance",
    ] {
        assert!(
            doc.contains(required),
            "docs/trustcard.md missing required MIK-6556 term {required}"
        );
    }
}
