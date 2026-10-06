// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7916 AC3: every `tools/list` projects the same catalogue, so a memo
//! hit must cost no more than handing back a copy of what it already holds.
//! The copy is the oracle: a hit that re-serialises each tool, re-inserts
//! the `trustCard` key or allocates its lookup key asks the allocator for
//! more than `clone()` of its own output does. The AC3 bar itself is a CPU
//! share, which no unit test can state; the profile rerun grades that.

use serde_json::json;

use super::alloc_meter::measure;
use super::signing_nonce_allocations_support::isolate;
use crate::protocol::Tool;
use crate::trust::project_tool_descriptors_trust_cards;

/// Same as `signing_nonce_allocations::test_path`; it must expand here.
fn test_path(name: &str) -> String {
    let module = module_path!();
    let module = module
        .split_once("::")
        .map_or(module, |(_crate, rest)| rest);
    format!("{module}::{name}")
}

/// Nested schemas, so a per-tool re-serialisation costs many allocations.
fn catalogue() -> Vec<Tool> {
    (0..4)
        .map(|i| Tool {
            name: format!("alloc_hit_tool_{i}"),
            title: Some(format!("Tool {i}")),
            description: Some(format!("Looks things up, variant {i}")),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "what to find"},
                    "limit": {"type": "integer", "minimum": 1},
                    "filters": {"type": "array", "items": {"type": "string"}}
                },
                "required": ["query"]
            }),
            output_schema: None,
            annotations: None,
            role: None,
            projection: None,
        })
        .collect()
}

#[test]
fn a_memo_hit_allocates_no_more_than_the_copy_it_returns() {
    if isolate(&test_path(
        "a_memo_hit_allocates_no_more_than_the_copy_it_returns",
    )) {
        return;
    }
    let tools = catalogue();
    let (id, name) = ("backend:alloc-hit", "alloc-hit");
    // The first list computes and stores every card; the second is all hits.
    let _ = project_tool_descriptors_trust_cards(id, name, &tools);
    let (listed, hit) = measure(|| project_tool_descriptors_trust_cards(id, name, &tools));
    let (_copy, copy) = measure(|| listed.clone());

    // Positive control: a meter that saw nothing would pass the bound vacuously.
    assert!(
        copy.calls > tools.len() as u64,
        "the meter saw only {copy} for a copy of {} descriptors",
        tools.len()
    );
    assert!(
        hit.calls <= copy.calls,
        "a memo hit took {hit}; a copy of its own output takes {copy} (MIK-7916 AC3)"
    );
}
