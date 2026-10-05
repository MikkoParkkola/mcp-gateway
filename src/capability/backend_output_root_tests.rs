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

    let mut advertised = cap.to_mcp_tool().output_schema.expect("advertised");
    let id = advertised["properties"]["items"]
        .as_object_mut()
        .and_then(|inner| inner.remove("$id"))
        .expect("the nested schema is its own resource");
    assert!(
        id.as_str()
            .is_some_and(|id| id.starts_with("urn:mcp-gateway:declared-output:")),
        "{id}"
    );
    assert_eq!(
        advertised,
        json!({
            "type": "object",
            "properties": { "items": declared },
            "required": ["items"]
        })
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
    assert_eq!(advertised["properties"]["items"]["type"], json!("string"));

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

/// The advertised schema accepts and refuses what the declared one does,
/// judged by a JSON Schema validator rather than by its text.
#[test]
fn a_wrapped_root_resolves_its_references_as_declared() {
    let cases = [
        // A root pointer, a root recursion, and a declared root `$id`.
        "    type: array\n    items:\n      $ref: '#/$defs/E'\n    $defs:\n      E:\n        type: string",
        "    type: array\n    items:\n      anyOf:\n        - type: string\n        - $ref: '#'",
        "    $id: https://schemas.invalid/root\n    type: array\n    items:\n      $ref: '#/$defs/E'\n    $defs:\n      E:\n        type: string",
        // A nested resource, and a `$ref` that is instance data.
        "    type: array\n    items:\n      $id: https://schemas.invalid/entry\n      $ref: '#/$defs/E'\n      $defs:\n        E:\n          type: string",
        "    type: array\n    items:\n      anyOf:\n        - type: string\n        - const:\n            $ref: '#/target'",
        // Another dialect, read in that dialect.
        "    $schema: http://json-schema.org/draft-07/schema#\n    type: array\n    items:\n      $ref: '#/definitions/E'\n    definitions:\n      E:\n        type: string",
    ];
    for output in cases {
        let cap = capability_with_output(output);
        let advertised = cap.to_mcp_tool().output_schema.expect("advertised");
        assert_eq!(
            advertised["$schema"], cap.schema.output["$schema"],
            "{output}"
        );
        let validator = jsonschema::validator_for(&advertised)
            .unwrap_or_else(|e| panic!("{output}: advertised schema does not compile: {e}"));
        assert!(validator.is_valid(&json!({ "items": ["ok"] })), "{output}");
        assert!(!validator.is_valid(&json!({ "items": [1] })), "{output}");
        assert!(!validator.is_valid(&json!({ "items": "ok" })), "{output}");
    }

    let cap = capability_with_output(cases[4]);
    let advertised = cap.to_mcp_tool().output_schema.expect("advertised");
    let validator = jsonschema::validator_for(&advertised).expect("compiles");
    assert!(validator.is_valid(&json!({ "items": [{ "$ref": "#/target" }] })));
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

/// The nested schema's `$id` names its content, and a declared `$id` that
/// names the enclosing document is replaced.
#[test]
fn a_wrapped_root_is_named_by_its_content() {
    let id_of = |output: &str| {
        capability_with_output(output)
            .to_mcp_tool()
            .output_schema
            .expect("advertised")["properties"]["items"]["$id"]
            .clone()
    };
    let strings = id_of("    type: array\n    items:\n      type: string");
    let numbers = id_of("    type: array\n    items:\n      type: number");
    assert_ne!(strings, numbers);
    assert_eq!(
        strings,
        id_of("    type: array\n    items:\n      type: string")
    );
    assert_eq!(
        id_of("    $id: https://schemas.invalid/kept\n    type: array"),
        json!("https://schemas.invalid/kept")
    );

    for declared in ["''", "'#'"] {
        let output = format!(
            "    $id: {declared}\n    type: array\n    items:\n      $ref: '#/$defs/E'\n    $defs:\n      E:\n        type: string"
        );
        let advertised = capability_with_output(&output)
            .to_mcp_tool()
            .output_schema
            .expect("advertised");
        assert!(
            advertised["properties"]["items"]["$id"]
                .as_str()
                .is_some_and(|id| id.starts_with("urn:mcp-gateway:declared-output:")),
            "{output}"
        );
        let validator = jsonschema::validator_for(&advertised).expect("compiles");
        assert!(validator.is_valid(&json!({ "items": ["ok"] })), "{output}");
        assert!(!validator.is_valid(&json!({ "items": [1] })), "{output}");
    }
}
