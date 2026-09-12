// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6865 fail-fast probe (MCPGW.SCHEMA.1).
//!
//! Opus 4.8 / Sonnet 5 invent trailing keys on nested-object-in-array schemas.
//! The gate: does `validate_arguments` refuse an undeclared key at nesting
//! depth >= 2, or does it accept it silently?

use mcp_gateway::capability::validate_arguments;
use serde_json::json;

/// A nested-object-in-array schema, the shape the source flags as risky.
fn schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "edits": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "oldText": { "type": "string" },
                        "newText": { "type": "string" }
                    },
                    "required": ["oldText", "newText"]
                }
            }
        },
        "required": ["edits"]
    })
}

/// The five invented keys named in the source report, each at depth >= 2.
fn invented_cases() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        (
            "type",
            json!({"edits":[{"oldText":"a","newText":"b","type":"replace"}]}),
        ),
        (
            "requireUnique",
            json!({"edits":[{"oldText":"a","newText":"b","requireUnique":true}]}),
        ),
        (
            "in_file",
            json!({"edits":[{"oldText":"a","newText":"b","in_file":"x.rs"}]}),
        ),
        (
            "oldText2",
            json!({"edits":[{"oldText":"a","newText":"b","oldText2":"c"}]}),
        ),
        (
            "additionalProperties",
            json!({"edits":[{"oldText":"a","newText":"b","additionalProperties":false}]}),
        ),
    ]
}

// Ignored by default: this is the MIK-6865 GATE and is RED until the fix at
// origin/fix/mik-6865-schema-key-invention (f14f2eb3) lands. Run via probe/run.sh.
#[test]
#[ignore = "MIK-6865 gate: RED until f14f2eb3 lands"]
fn undeclared_key_at_depth_two_is_refused() {
    let schema = schema();
    let mut accepted = Vec::new();
    for (name, args) in invented_cases() {
        let result = validate_arguments(&args, &schema);
        if result.violations.is_empty() {
            accepted.push(name);
        }
    }
    assert!(
        accepted.is_empty(),
        "MIK-6865 PROBE RED: {}/5 invented nested keys accepted silently: {:?}",
        accepted.len(),
        accepted
    );
}

/// Falsifier: the same validator must still refuse an invented key at depth 1,
/// so a green result above cannot come from a validator that refuses nothing.
#[test]
fn falsifier_undeclared_key_at_depth_one_is_refused() {
    let result = validate_arguments(&json!({"edits": [], "exfil": "x"}), &schema());
    assert!(
        !result.violations.is_empty(),
        "falsifier failed: validator accepts an undeclared TOP-LEVEL key"
    );
}
