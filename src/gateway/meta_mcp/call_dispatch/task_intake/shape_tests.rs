// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8498 characterisation (DISPATCH): a repeated task call's failed-fill
//! answer is shaped by the presented name. A surfaced backend tool answers
//! with its value verbatim (native); `gateway_invoke`, and a name no operator
//! surfaced, answer exactly as `wrap_tool_success` wraps the value (the meta
//! reply). Kept beside `shape_repeat_fill`, so its shape rule cannot move
//! without this file seeing it.

use std::sync::Arc;

use crate::backend::BackendRegistry;
use crate::config::SurfacedToolConfig;
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::RequestId;

#[test]
fn a_repeat_fill_answer_is_shaped_by_the_presented_name() {
    let mm = MetaMcp::new(Arc::new(BackendRegistry::new())).with_surfaced_tools(vec![
        SurfacedToolConfig {
            server: "backend_a".to_string(),
            tool: "my_custom_tool".to_string(),
        },
    ]);
    let authz = crate::gateway::authz::AllowAll;
    let caller = crate::gateway::meta_mcp::authz_tests::ctx(&authz);
    let value = serde_json::json!({ "content": [{ "type": "text", "text": "x" }] });
    let shaped = |name: &str| {
        mm.shape_repeat_fill(RequestId::Number(7), name, value.clone(), &caller)
            .result
    };
    let wrapped =
        crate::gateway::meta_mcp_helpers::wrap_tool_success(RequestId::Number(7), &value, false)
            .result;
    assert!(
        wrapped.is_some() && wrapped != Some(value.clone()),
        "premise"
    );
    assert_eq!(
        shaped("my_custom_tool"),
        Some(value.clone()),
        "surfaced: native"
    );
    assert_eq!(shaped("gateway_invoke"), wrapped, "gateway_invoke: wrapped");
    assert_eq!(
        shaped("not_surfaced"),
        wrapped,
        "an unsurfaced name: wrapped"
    );
    // The rule reads the operator's surfaced map, not the caller's view: a
    // surfaced name withheld from this caller still answers native.
    let denied = crate::gateway::authz::DenyOne {
        tool: "my_custom_tool",
    };
    let withheld = crate::gateway::meta_mcp::authz_tests::ctx(&denied);
    assert_eq!(
        mm.shape_repeat_fill(
            RequestId::Number(7),
            "my_custom_tool",
            value.clone(),
            &withheld
        )
        .result,
        Some(value.clone()),
        "a surfaced name withheld from the caller: still native"
    );
}
