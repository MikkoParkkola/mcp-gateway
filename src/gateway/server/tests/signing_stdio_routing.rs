// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::router::backend_tool_targets_for_call;
use serde_json::{Value, json};

type RoutingCase = (&'static str, Value, &'static [(&'static str, &'static str)]);

#[tokio::test]
async fn stdio_followup_routing_projection_preserves_backend_target_identity() {
    let meta_mcp = MetaMcp::new(std::sync::Arc::new(crate::backend::BackendRegistry::new()));
    let project = super::super::stdio_routing_keys_only;
    let payload_sentinel = "ROUTING-PAYLOAD-SENTINEL-alpha-beta";

    let execute_chain = json!({
        "chain": [
            {
                "tool": "alpha:read",
                "arguments": {"body": payload_sentinel, "n": 1},
                "extra": {"note": payload_sentinel}
            },
            {"tool": false, "arguments": {"body": payload_sentinel}},
            Value::Null,
            {"arguments": {"body": payload_sentinel}},
            {"tool": "bad", "arguments": {"body": payload_sentinel}},
            {
                "tool": "beta:write",
                "arguments": {"body": payload_sentinel, "n": 2},
                "extra": {"note": payload_sentinel}
            },
            {
                "tool": "alpha:read",
                "arguments": {"body": payload_sentinel, "dup": true}
            }
        ]
    });
    let execute_fallback = json!({
        "chain": {"not": "an-array"},
        "tool": "alpha:read",
        "arguments": {"body": payload_sentinel}
    });
    let execute_missing_tool = json!({"chain": {"not": "an-array"}});
    let execute_malformed_tool = json!({
        "chain": {"not": "an-array"},
        "tool": 12
    });
    let invoke_ok = json!({
        "server": "alpha",
        "tool": "read",
        "arguments": {"body": payload_sentinel}
    });
    let invoke_bad = json!({
        "server": 1,
        "tool": true,
        "arguments": {"body": payload_sentinel}
    });

    let cases: &[RoutingCase] = &[
        (
            "gateway_execute",
            execute_chain,
            &[("alpha", "read"), ("beta", "write"), ("alpha", "read")],
        ),
        ("gateway_execute", execute_fallback, &[("alpha", "read")]),
        ("gateway_execute", execute_missing_tool, &[]),
        ("gateway_execute", execute_malformed_tool, &[]),
        ("gateway_invoke", invoke_ok, &[("alpha", "read")]),
        ("gateway_invoke", invoke_bad, &[]),
    ];

    for (tool_name, arguments, expected) in cases {
        let expected: Vec<(String, String)> = expected
            .iter()
            .map(|(s, t)| ((*s).to_string(), (*t).to_string()))
            .collect();
        let full = backend_tool_targets_for_call(&meta_mcp, tool_name, arguments);
        let projected_args = project(arguments);
        let projected = backend_tool_targets_for_call(&meta_mcp, tool_name, &projected_args);
        let full_ids: Vec<(String, String)> = full
            .iter()
            .map(|t| (t.server.clone(), t.tool.clone()))
            .collect();
        let projected_ids: Vec<(String, String)> = projected
            .iter()
            .map(|t| (t.server.clone(), t.tool.clone()))
            .collect();
        assert_eq!(full_ids, expected, "{tool_name} full {arguments}");
        assert_eq!(
            projected_ids, expected,
            "{tool_name} projected {projected_args}"
        );
        let serialized = serde_json::to_string(&projected_args).expect("serialize projection");
        assert!(
            !serialized.contains(payload_sentinel),
            "projection leaked payload: {serialized}"
        );
        for target in &projected {
            assert_eq!(target.arguments, json!({}));
        }
        if !expected.is_empty() {
            assert!(
                full.iter().any(|t| t.arguments != json!({})),
                "valid full targets must retain payload: {full_ids:?}"
            );
        }
    }
}
