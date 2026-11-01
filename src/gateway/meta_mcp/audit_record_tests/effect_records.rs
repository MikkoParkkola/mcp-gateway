// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A dispatched call's record carries the effect the tool
//! declared, read where the cache admits it, never inferred from the name.

use serde_json::{Value, json};

use super::{api_key_caller, context, meta, ok_result, records};
use crate::gateway::authz::AllowAll;

/// A listed tool `read` whose `readOnlyHint` is `hint`.
fn read_tool(hint: Option<bool>) -> crate::protocol::Tool {
    let mut tool = json!({"name": "read", "inputSchema": {"type": "object"}});
    if let Some(hint) = hint {
        tool["annotations"] = json!({"readOnlyHint": hint});
    }
    serde_json::from_value(tool).expect("tool")
}

/// The decision of the one record a call to `alpha`'s `read` writes, after
/// the shared slot listed `read` with `hint`.
async fn decision_after(hint: Option<bool>, read_only_admitted: bool) -> Value {
    let dir = tempfile::tempdir().unwrap();
    let meta = meta(Ok(ok_result()), &dir);
    let alpha = meta.backends.for_test().get("alpha").expect("alpha");
    alpha.prefill_tools_for_test(vec![read_tool(hint)]);
    if read_only_admitted {
        alpha.set_read_only_declared_for_test(&["read"]);
    }
    let who = api_key_caller();
    let caller = context(&AllowAll, &who);
    let args = json!({"server": "alpha", "tool": "read", "arguments": {}});
    let _ = meta.invoke_tool(&args, None, &caller).await;
    let all = records(&dir);
    assert_eq!(all.len(), 1, "{all:?}");
    all[0]["decision"].clone()
}

#[tokio::test]
async fn a_declared_read_only_tool_records_read_only_from_the_tool() {
    let d = decision_after(Some(true), true).await;
    assert_eq!(d["declared_effect"], "read_only", "{d}");
    assert_eq!(d["declared_effect_source"], "tool_annotation", "{d}");
}

#[tokio::test]
async fn a_tool_declaring_read_only_false_records_may_write() {
    let d = decision_after(Some(false), false).await;
    assert_eq!(d["declared_effect"], "may_write", "{d}");
    assert_eq!(d["declared_effect_source"], "tool_annotation", "{d}");
}

#[tokio::test]
async fn a_tool_with_no_hint_records_undeclared() {
    let d = decision_after(None, false).await;
    assert_eq!(d["declared_effect"], "undeclared", "{d}");
}

#[tokio::test]
async fn a_cold_slot_records_no_effect() {
    let dir = tempfile::tempdir().unwrap();
    let meta = meta(Ok(ok_result()), &dir);
    let who = api_key_caller();
    let caller = context(&AllowAll, &who);
    let args = json!({"server": "alpha", "tool": "read", "arguments": {}});
    let _ = meta.invoke_tool(&args, None, &caller).await;
    let all = records(&dir);
    assert_eq!(all.len(), 1, "{all:?}");
    let d = &all[0]["decision"];
    assert!(d.get("declared_effect").is_none(), "{d}");
    assert!(d.get("declared_effect_source").is_none(), "{d}");
}
