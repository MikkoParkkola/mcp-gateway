// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An MCP operation's `wait` polls a second tool until an item is ready.

use serde_json::json;

use super::{CapabilityExecutor, call, caller, capability, parse_capability, python};

#[tokio::test]
async fn a_wait_polls_until_the_matching_item_is_ready() {
    let executor = CapabilityExecutor::new();
    let out = call(
        &executor,
        &capability(),
        json!({"operation": "import_wait", "binary_path": "/data/x"}),
        &caller("a"),
    )
    .await
    .unwrap();
    assert_eq!(out["ready"]["analysis_complete"], true, "{out}");
    assert_eq!(out["ready"]["name"], "prog-x");
    assert_eq!(out["result"]["program_name"], "prog-x");
}

#[tokio::test]
async fn a_wait_that_runs_out_says_so_and_keeps_the_child() {
    let executor = CapabilityExecutor::new();
    let err = call(
        &executor,
        &capability(),
        json!({"operation": "import_slow", "binary_path": "/data/x"}),
        &caller("a"),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("poll again to keep waiting"), "{err}");
    assert_eq!(
        executor.mcp_children.len(),
        1,
        "a busy server is not discarded"
    );
}

fn probe_with(operation: &str) -> String {
    format!(
        r"name: mcp_probe2
description: probe
schema:
  input:
    type: object
    properties:
      operation: {{ type: string }}
      text: {{ type: string }}
providers:
  primary:
    service: mcp
    timeout: 30
    config:
      command: '{python}'
      transport: stdio
      tool_selector:
        param: operation
        tools:
          op:
{operation}
",
        python = python(),
    )
}

#[test]
fn a_requires_naming_an_undeclared_property_fails_the_load() {
    let def = parse_capability(&probe_with(
        "            tool: echo\n            requires: [typo]",
    ))
    .unwrap();
    let err = crate::capability::validate_capability(&def)
        .unwrap_err()
        .to_string();
    assert!(err.contains("requires 'typo'"), "{err}");
}

#[test]
fn a_wait_must_leave_ten_seconds_of_the_provider_timeout() {
    let wait = |max: u64| {
        probe_with(&format!(
            "            tool: echo\n            wait:\n              tool: echo\n              until: {{ array: a, match: {{ x: y }}, field: f, equals: true }}\n              max_wait_s: {max}"
        ))
    };
    let check =
        |max| crate::capability::validate_capability(&parse_capability(&wait(max)).unwrap());
    assert!(check(20).is_ok());
    let err = check(21).unwrap_err().to_string();
    assert!(err.contains("max_wait_s"), "{err}");
}
