// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8639 DEPTH.2: library entry points refuse a 10,000-deep unread field
//! with the guard's Depth text.
//!
//! Red on the skeleton: these reads either succeed or refuse with the backend
//! parser's own wording, which never contains "nesting deeper than 128".

/// `head` plus an unread `probe` field nesting 10,000 flow sequences.
fn deep_probe(head: &str) -> String {
    format!(
        "{head}probe: {}1{}\n",
        "[".repeat(10_000),
        "]".repeat(10_000)
    )
}

#[test]
fn openapi_converter_refuses_deep_unread_field() {
    let content =
        deep_probe("openapi: 3.0.0\ninfo:\n  title: probe\n  version: \"1\"\npaths: {}\n");
    let Err(err) = mcp_gateway::capability::OpenApiConverter::new().convert_string(&content) else {
        panic!("10k-deep spec must be refused")
    };
    assert!(
        err.to_string().contains("nesting deeper than 128"),
        "got: {err}"
    );
}

#[test]
fn parse_capability_refuses_deep_unread_field() {
    let content = deep_probe(
        "name: probe\ndescription: depth probe\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: https://example.invalid\n",
    );
    let Err(err) = mcp_gateway::capability::parse_capability(&content) else {
        panic!("10k-deep capability must be refused")
    };
    assert!(
        err.to_string().contains("nesting deeper than 128"),
        "got: {err}"
    );
}

#[test]
fn parse_skill_md_refuses_deep_unread_field() {
    let frontmatter = deep_probe("name: probe\ndescription: depth probe\n");
    let content = format!("---\n{frontmatter}---\n# probe\n");
    let Err(err) = mcp_gateway::skills::parse_skill_md(&content) else {
        panic!("10k-deep frontmatter must be refused")
    };
    assert!(
        err.to_string().contains("nesting deeper than 128"),
        "got: {err}"
    );
}
