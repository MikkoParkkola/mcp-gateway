// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `prepare_tool_metadata` cases, split out of `tests.rs` to keep that file
//! under the line-count ceiling.
use super::*;

// --- MIK-7214.HEADER.8 — tools violating an `x-mcp-header` constraint are
// excluded from `tools/list`, on the same tool-metadata path as the
// destructive-annotation gate.

fn tool_with_schema(name: &str, input_schema: serde_json::Value) -> Tool {
    let mut tool = sample_tool(name);
    tool.input_schema = input_schema;
    tool
}

#[test]
fn prepare_tool_metadata_keeps_a_well_formed_annotation() {
    // GIVEN one tool whose `x-mcp-header` meets every constraint
    let mut tools = vec![tool_with_schema(
        "search",
        json!({"type": "object", "properties": {
            "tenant": {"type": "string", "x-mcp-header": "Tenant"}
        }}),
    )];

    // WHEN the tool-metadata path filters the list
    prepare_tool_metadata(
        "beeper",
        &std::collections::BTreeMap::new(),
        crate::backend::Judging::Judge,
        &mut tools,
    );

    // THEN it survives
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "search");
}

#[test]
fn prepare_tool_metadata_drops_only_the_violating_tool() {
    // GIVEN a valid tool beside one annotating a `number` property
    let mut tools = vec![
        tool_with_schema("keep", json!({"type": "object", "properties": {}})),
        tool_with_schema(
            "drop",
            json!({"type": "object", "properties": {
                "ratio": {"type": "number", "x-mcp-header": "Ratio"}
            }}),
        ),
    ];

    prepare_tool_metadata(
        "beeper",
        &std::collections::BTreeMap::new(),
        crate::backend::Judging::Judge,
        &mut tools,
    );

    // THEN exclusion is per-tool, never per-backend
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "keep");
}

#[test]
fn prepare_tool_metadata_drops_a_crlf_injection_attempt() {
    let mut tools = vec![tool_with_schema(
        "inject",
        json!({"type": "object", "properties": {
            "tenant": {"type": "string", "x-mcp-header": "T\r\nX-Injected: 1"}
        }}),
    )];

    prepare_tool_metadata(
        "beeper",
        &std::collections::BTreeMap::new(),
        crate::backend::Judging::Judge,
        &mut tools,
    );

    assert!(
        tools.is_empty(),
        "a control character must exclude the tool"
    );
}

#[test]
fn prepare_tool_metadata_leaves_unannotated_tools_untouched() {
    let mut tools = vec![sample_tool("plain"), sample_tool("also_plain")];

    prepare_tool_metadata(
        "beeper",
        &std::collections::BTreeMap::new(),
        crate::backend::Judging::Judge,
        &mut tools,
    );

    assert_eq!(tools.len(), 2);
}

#[test]
fn prepare_tool_metadata_excludes_and_annotates_in_one_pass() {
    // GIVEN a violating tool beside one that needs its hints inferred
    let mut tools = vec![
        tool_with_schema(
            "bad",
            json!({"type": "object", "properties": {
                "tenant": {"type": "string", "x-mcp-header": "Tenant Id"}
            }}),
        ),
        tool_with_schema("get_thing", json!({"type": "object"})),
    ];

    // WHEN the single tool-metadata entry point runs
    prepare_tool_metadata(
        "beeper",
        &std::collections::BTreeMap::new(),
        crate::backend::Judging::Judge,
        &mut tools,
    );

    // THEN both steps happened: neither caller can get one without the other
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "get_thing");
    assert_eq!(
        tools[0].annotations.as_ref().and_then(|a| a.read_only_hint),
        Some(true)
    );
}

// --- MIK-7216.IDEM.1 — the backend-tool classification, pinned on the real
// function. Unannotated / `readOnlyHint:false` / a read-looking name are
// side-effecting (ADR-012 A1 deny default); an explicit `readOnlyHint:true`
// or `idempotentHint:true` grants resend permission. Admission never reads
// annotations: see `idempotency_config_tests` in `config/features/idempotency.rs`.
// Wire-level cases live in `tests/mik_7272_sub4_adr012_acs.rs`.

fn annotated(name: &str, read_only: Option<bool>, idempotent: Option<bool>) -> Tool {
    let mut tool = sample_tool(name);
    tool.annotations = Some(crate::protocol::ToolAnnotations {
        read_only_hint: read_only,
        idempotent_hint: idempotent,
        ..Default::default()
    });
    tool
}

#[test]
fn prepare_tool_metadata_grants_resend_only_to_explicit_hints() {
    // GIVEN one tool per annotation shape, including a read-looking mutation
    let mut tools = vec![
        sample_tool("unannotated"),
        sample_tool("get_and_increment"),
        annotated("read_true", Some(true), None),
        annotated("read_false", Some(false), None),
        annotated("idempotent_only", None, Some(true)),
        annotated("idempotent_false", None, Some(false)),
    ];

    // WHEN the tool-metadata entry point classifies them
    let prepared = prepare_tool_metadata(
        "beeper",
        &std::collections::BTreeMap::new(),
        crate::backend::Judging::Judge,
        &mut tools,
    );

    // THEN only an explicit true hint grants permission; idempotentHint:true
    // without readOnlyHint is permitted for resend (the gateway does not
    // require both), and everything else is side-effecting
    let mut permitted: Vec<&str> = prepared
        .resend_permitted
        .iter()
        .map(String::as_str)
        .collect();
    permitted.sort_unstable();
    assert_eq!(permitted, ["idempotent_only", "read_true"]);
}
