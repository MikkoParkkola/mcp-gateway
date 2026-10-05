// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Every shipped capability advertises an object `outputSchema` root
//! (MIK-7959). MCP 2025-11-25 restricts the root to `type: "object"`, and a
//! strict client can refuse the tool, or the whole `tools/list`, otherwise.

use std::path::Path;

use mcp_gateway::capability::parse_capability;

/// Capabilities whose declared root is not an object. Listed so the scan is
/// shown to reach them: an empty walk would otherwise pass.
const NON_OBJECT_ROOTS: &[&str] = &[
    "country_info",
    "hackernews_ask",
    "hackernews_show",
    "hackernews_top",
    "number_facts",
    "public_holidays",
    "sentry_list_issues",
    "uuid_generate",
    "wayback_cdx",
];

#[test]
fn every_capability_advertises_an_object_output_schema_root() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut checked = 0usize;
    let mut non_object_declared = Vec::new();
    let mut offenders = Vec::new();
    for entry in walkdir::WalkDir::new(root.join("capabilities"))
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|x| x == "yaml" || x == "yml")
        })
    {
        checked += 1;
        let text = std::fs::read_to_string(entry.path()).expect("capability file is readable");
        let cap = parse_capability(&text)
            .unwrap_or_else(|e| panic!("{} does not parse: {e}", entry.path().display()));
        if cap.schema.output.get("type").is_some_and(|t| t != "object") {
            non_object_declared.push(cap.name.clone());
        }
        if let Some(schema) = cap.to_mcp_tool().output_schema
            && schema.get("type").and_then(serde_json::Value::as_str) != Some("object")
        {
            offenders.push(cap.name);
        }
    }

    assert!(checked >= 100, "scanned only {checked} capability files");
    for name in NON_OBJECT_ROOTS {
        assert!(
            non_object_declared.iter().any(|n| n == name),
            "{name} was not reached with a non-object declared root"
        );
    }
    assert!(
        offenders.is_empty(),
        "outputSchema root is not an object for: {offenders:?}"
    );
}
