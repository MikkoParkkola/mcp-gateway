// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Admission refusals on stdio, as their records name them: a deferred plan
//! refusal never labels the refusal returned, and a refusal with its own
//! status or data keeps its answer while it is recorded once, `denied`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

use super::{Counting, stdio_meta, stdio_send_under};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::grant_audit_fixture::{invocations, logger};
use crate::security::ToolPolicyConfig;
use crate::security::audit::AuditFailurePolicy;

/// A stdio Meta-MCP serving `alpha` (`read`, `write`) with code mode, keyed
/// calls and a transparency log in `dir`; and its backend send count.
async fn logged(dir: &Arc<tempfile::TempDir>) -> (Arc<MetaMcp>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let transport = Arc::new(Counting {
        calls: Arc::clone(&calls),
        answer: json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
    });
    let meta = stdio_meta(
        |meta| {
            let empty = MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
            *meta = std::mem::replace(meta, empty).with_code_mode(true);
            meta.enable_idempotency(
                Arc::new(crate::idempotency::IdempotencyCache::new()),
                crate::idempotency::CLEANUP_INTERVAL,
            );
            meta.enable_transparency_log(logger(dir, AuditFailurePolicy::BestEffort));
        },
        transport,
    )
    .await;
    (meta, calls)
}

/// The `_meta` of a keyed call, modern or legacy.
fn keyed(key: &str, modern: bool) -> Value {
    let mut meta = json!({ (crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key });
    if modern {
        meta["io.modelcontextprotocol/protocolVersion"] = json!("2026-07-28");
        meta["io.modelcontextprotocol/clientCapabilities"] = json!({});
    }
    meta
}

/// A keyed modern `gateway_execute` of `tools`.
fn execute(tools: &[&str], key: &str) -> Value {
    let chain: Vec<Value> = tools
        .iter()
        .map(|tool| json!({"tool": tool, "arguments": {}}))
        .collect();
    json!({"name": "gateway_execute", "arguments": {"chain": chain}, "_meta": keyed(key, true)})
}

fn denying(tool: &str) -> ToolPolicyConfig {
    ToolPolicyConfig {
        enabled: true,
        deny: vec![tool.to_string()],
        ..ToolPolicyConfig::default()
    }
}

/// The one record whose code is `code`.
fn the_record(dir: &tempfile::TempDir, code: i64, answer: &Value) -> Value {
    let records: Vec<Value> = invocations(dir)
        .into_iter()
        .filter(|record| record["error_code"] == json!(code))
        .collect();
    let [record] = records.as_slice() else {
        panic!("exactly one {code} record: {records:#?}; answer {answer}");
    };
    record.clone()
}

/// d1, first case, on stdio: `[alpha:write, alpha:read, no_prefix]`, keyed,
/// `write` denied by the tool policy (its refusal deferred; `read` keeps the
/// call past the route's all-invisible gate). Admission returns the parse
/// refusal; its one record carries no deferred pair: kind `unrecorded`, no
/// rule id. The answer is the parse refusal's, as before.
#[tokio::test]
async fn d1_a_deferred_step_does_not_label_a_later_refusal_on_stdio() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (meta, calls) = logged(&dir).await;
    let params = execute(&["alpha:write", "alpha:read", "no_prefix"], "k-d1");
    let answer = stdio_send_under(&meta, params, &denying("write")).await;
    let refusal = crate::Error::json_rpc(
        crate::error::rpc_codes::INVALID_PARAMS,
        "Tool reference requires a server:tool_name prefix",
    );
    assert_eq!(
        (&answer["error"]["code"], &answer["error"]["message"]),
        (&json!(refusal.to_rpc_code()), &json!(refusal.to_string())),
        "{answer}"
    );
    let records = invocations(&dir);
    let [record] = records.as_slice() else {
        panic!("exactly one record: {records:#?}; answer {answer}");
    };
    assert_eq!(record["decision"]["kind"], json!("unrecorded"), "{record}");
    assert_eq!(record["decision"].get("rule_id"), None, "{record}");
    assert_eq!(calls.load(Ordering::SeqCst), 0, "never sent");
}

/// Status and data, the cross-era replay: a keyed legacy `gateway_invoke`
/// runs, the same key from the modern era is refused with 409 and its
/// gateway-authored data, as before (the cross-era rows), and now leaves
/// one record: `denied` (a noted refusal's code is promoted), kind
/// `unrecorded`.
#[tokio::test]
async fn an_admission_refusal_keeps_its_data_on_stdio() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (meta, calls) = logged(&dir).await;
    let invoke = |modern| {
        json!({"name": "gateway_invoke",
               "arguments": {"server": "alpha", "tool": "read", "arguments": {}},
               "_meta": keyed("k-era", modern)})
    };
    let policy = ToolPolicyConfig::default();
    let first = stdio_send_under(&meta, invoke(false), &policy).await;
    assert!(
        first.get("result").is_some(),
        "premise: the first runs: {first}"
    );
    let answer = stdio_send_under(&meta, invoke(true), &policy).await;
    let error = &answer["error"];
    assert_eq!(error["code"], json!(409), "{answer}");
    assert!(
        error["message"]
            .as_str()
            .is_some_and(|message| message.starts_with("JSON-RPC error 409:")),
        "{answer}"
    );
    assert_eq!(
        error["data"],
        json!({"reason": "idempotency_era_mismatch", "stored_era": "legacy",
               "request_era": "modern", "already_executed": true}),
        "{answer}"
    );
    assert_eq!(answer["id"], json!(7), "{answer}");
    let record = the_record(&dir, 409, &answer);
    assert_eq!(record["outcome"], json!("denied"), "{record}");
    assert_eq!(record["decision"]["kind"], json!("unrecorded"), "{record}");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the backend ran once");
}
