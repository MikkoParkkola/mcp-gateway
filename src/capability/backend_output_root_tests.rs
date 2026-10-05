// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7959: MCP restricts a tool's `outputSchema` root to `type: "object"` and
//! `structuredContent` to a JSON object. A capability declaring another root is
//! advertised and published under `items`; its text content is unchanged.

use super::*;
use serde_json::json;

fn capability_with_output(output: &str) -> CapabilityDefinition {
    crate::capability::parse_capability(&format!(
        r#"
name: listing_test
description: Test capability with a non-object output root
schema:
  input:
    type: object
    properties: {{}}
  output:
{output}
providers:
  primary:
    service: rest
    config:
      base_url: "https://api.example.com"
      path: /list
      method: GET
"#
    ))
    .unwrap()
}

#[test]
fn an_array_output_root_is_advertised_and_published_under_items() {
    let cap = capability_with_output(
        "    type: array\n    items:\n      type: object\n      properties:\n        id:\n          type: string",
    );
    let declared = json!({
        "type": "array",
        "items": { "type": "object", "properties": { "id": { "type": "string" } } }
    });

    assert_eq!(
        cap.to_mcp_tool().output_schema,
        Some(json!({
            "type": "object",
            "properties": { "items": declared },
            "required": ["items"]
        }))
    );

    let payload = json!([{ "id": "a" }, { "id": "b" }]);
    let result = build_success_tool_result(&cap, payload.clone());
    assert_eq!(result.structured_content, Some(json!({ "items": payload })));
    let Content::Text { text, .. } = &result.content[0] else {
        panic!("expected text content, got {:?}", result.content[0]);
    };
    assert_eq!(text, &serde_json::to_string_pretty(&payload).unwrap());
}

#[test]
fn a_scalar_output_root_is_published_under_items() {
    let cap = capability_with_output("    type: string");

    let advertised = cap.to_mcp_tool().output_schema.expect("advertised");
    assert_eq!(advertised["type"], json!("object"));
    assert_eq!(
        advertised["properties"]["items"],
        json!({ "type": "string" })
    );

    let result = build_success_tool_result(&cap, json!("42 is the answer"));
    assert_eq!(
        result.structured_content,
        Some(json!({ "items": "42 is the answer" }))
    );
}

#[test]
fn an_object_output_root_is_advertised_and_published_as_declared() {
    let cap = capability_with_output(
        "    type: object\n    properties:\n      id:\n        type: string",
    );
    let declared = json!({ "type": "object", "properties": { "id": { "type": "string" } } });

    assert_eq!(cap.to_mcp_tool().output_schema, Some(declared));
    let result = build_success_tool_result(&cap, json!({ "id": "a" }));
    assert_eq!(result.structured_content, Some(json!({ "id": "a" })));
}

#[test]
fn a_wrapped_root_keeps_its_local_references_and_dialect() {
    let cap = capability_with_output(
        "    $schema: https://json-schema.org/draft/2020-12/schema\n    type: array\n    items:\n      $ref: '#/$defs/Entry'\n    $defs:\n      Entry:\n        type: object\n        properties:\n          next:\n            $ref: '#'\n          remote:\n            $ref: 'https://schemas.invalid/s.json#/x'",
    );
    let advertised = cap.to_mcp_tool().output_schema.expect("advertised");

    assert_eq!(
        advertised["$schema"],
        json!("https://json-schema.org/draft/2020-12/schema")
    );
    let inner = &advertised["properties"]["items"];
    assert!(inner.get("$schema").is_none());
    assert_eq!(
        inner["items"]["$ref"],
        json!("#/properties/items/$defs/Entry")
    );
    let entry = &inner["$defs"]["Entry"]["properties"];
    assert_eq!(entry["next"]["$ref"], json!("#/properties/items"));
    assert_eq!(
        entry["remote"]["$ref"],
        json!("https://schemas.invalid/s.json#/x")
    );
}

#[test]
fn a_typeless_or_union_root_is_wrapped_unless_it_declares_properties() {
    for output in [
        "    anyOf:\n      - type: array\n      - type: string",
        "    type: [object, \"null\"]",
    ] {
        let cap = capability_with_output(output);
        let advertised = cap.to_mcp_tool().output_schema.expect("advertised");
        assert_eq!(advertised["required"], json!(["items"]), "{output}");
        let result = build_success_tool_result(&cap, json!(null));
        assert_eq!(result.structured_content, Some(json!({ "items": null })));
    }

    let cap = capability_with_output("    properties:\n      id:\n        type: string");
    assert_eq!(
        cap.to_mcp_tool().output_schema,
        Some(json!({ "type": "object", "properties": { "id": { "type": "string" } } }))
    );
    let result = build_success_tool_result(&cap, json!({ "id": "a" }));
    assert_eq!(result.structured_content, Some(json!({ "id": "a" })));
}
