// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `prepare_tool_metadata` cases, split out of `tests.rs` to keep that file
//! under the line-count ceiling.
use super::*;

// --- Response-cache admission: only an explicit `readOnlyHint` lets a stored
// result stand in for a call (`gateway/meta_mcp/invoke.rs`).

fn annotated_tool(name: &str, read_only: Option<bool>, idempotent: Option<bool>) -> Tool {
    let mut tool = sample_tool(name);
    tool.annotations = Some(ToolAnnotations {
        read_only_hint: read_only,
        destructive_hint: None,
        idempotent_hint: idempotent,
        open_world_hint: None,
        title: None,
    });
    tool
}

#[test]
fn explicit_read_only_tools_admits_a_declaration_and_nothing_else() {
    // GIVEN a declared read-only tool, a declared idempotent write, and an
    // unannotated getter whose name alone reads as a read
    let tools = vec![
        annotated_tool("search", Some(true), None),
        annotated_tool("mark_emails_as_read", Some(false), Some(true)),
        sample_tool("get_status"),
    ];

    // WHEN the cache-admission set is read
    let admitted = explicit_read_only_tools(&tools);

    // THEN only the declaration counts. Retry permission is not the permission
    // to skip the call: `mark_emails_as_read` is resend-permitted and is still
    // a write whose cached answer describes an effect this call did not have.
    assert!(admitted.contains("search"));
    assert!(!admitted.contains("mark_emails_as_read"));
    assert!(!admitted.contains("get_status"));
}

#[test]
fn explicit_read_only_tools_is_only_meaningful_before_normalization() {
    // GIVEN an unannotated tool
    let mut tools = vec![sample_tool("get_status")];

    // WHEN the set is read before the metadata path runs, and again after
    let before = explicit_read_only_tools(&tools);
    prepare_tool_metadata("beeper", &mut tools);
    let after = explicit_read_only_tools(&tools);

    // THEN only the early read answers the question that was asked. This is a
    // canary, not a preference: normalization writes the name inference into
    // the hint, so a read taken afterwards admits a guess as if the backend had
    // declared it. `Backend::get_tools_shared` therefore reads this first, and
    // if normalization ever stops overwriting the hint this fails and the
    // ordering note above it comes out.
    assert!(
        tools[0].annotations.as_ref().unwrap().read_only_hint == Some(true),
        "normalization is expected to fill the omitted hint"
    );
    assert!(!before.contains("get_status"));
    assert!(after.contains("get_status"));
}

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
    prepare_tool_metadata("beeper", &mut tools);

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

    prepare_tool_metadata("beeper", &mut tools);

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

    prepare_tool_metadata("beeper", &mut tools);

    assert!(
        tools.is_empty(),
        "a control character must exclude the tool"
    );
}

#[test]
fn prepare_tool_metadata_leaves_unannotated_tools_untouched() {
    let mut tools = vec![sample_tool("plain"), sample_tool("also_plain")];

    prepare_tool_metadata("beeper", &mut tools);

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
    prepare_tool_metadata("beeper", &mut tools);

    // THEN both steps happened: neither caller can get one without the other
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "get_thing");
    assert_eq!(
        tools[0].annotations.as_ref().and_then(|a| a.read_only_hint),
        Some(true)
    );
}
