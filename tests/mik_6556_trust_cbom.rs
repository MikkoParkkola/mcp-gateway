use std::{fs, path::Path};

use mcp_gateway::{
    protocol::{Tool, ToolAnnotations},
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
