// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! d1, first case, on stdio: a deferred plan refusal never labels the
//! refusal keyed admission returns.

use super::*;

/// A keyed modern stdio `gateway_execute` of `[alpha:blocked, no_prefix]`,
/// `blocked` denied by the tool policy (so its refusal is deferred), the
/// second step malformed. Admission returns the parse refusal; its one record
/// carries no deferred pair: kind `unrecorded`, no rule id. The answer is the
/// parse refusal's, as before.
#[tokio::test]
async fn d1_a_deferred_step_does_not_label_a_later_refusal_on_stdio() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new())).with_code_mode(true);
    meta.enable_transparency_log(crate::gateway::meta_mcp::grant_audit_fixture::logger(
        &dir,
        crate::security::audit::AuditFailurePolicy::BestEffort,
    ));
    let meta = Arc::new(meta);
    let policy = crate::security::ToolPolicyConfig {
        enabled: true,
        deny: vec!["blocked".to_string()],
        ..crate::security::ToolPolicyConfig::default()
    };
    let mut call_meta = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                               "io.modelcontextprotocol/clientCapabilities": {}});
    call_meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!("k-d1");
    let chain = json!([{"tool": "alpha:blocked", "arguments": {}},
                       {"tool": "no_prefix", "arguments": {}}]);
    let response = Gateway::dispatch_single(
        &meta,
        &crate::gateway::authz::test_line(&meta, &policy),
        &test_mtls_policy(),
        &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "gateway_execute", "arguments": {"chain": chain}, "_meta": call_meta}}),
        "stdio-session",
    )
    .await
    .expect("a tools/call carrying an id must return a response");
    let refusal = crate::Error::json_rpc(
        crate::error::rpc_codes::INVALID_PARAMS,
        "Tool reference requires a server:tool_name prefix",
    );
    assert_eq!(
        (
            response["error"]["code"].as_i64(),
            response["error"]["message"].as_str()
        ),
        (
            Some(i64::from(refusal.to_rpc_code())),
            Some(refusal.to_string().as_str())
        ),
        "{response}"
    );
    let records = crate::gateway::meta_mcp::grant_audit_fixture::invocations(&dir);
    let [record] = records.as_slice() else {
        panic!("exactly one record: {records:#?}; answer {response}");
    };
    assert_eq!(record["decision"]["kind"], json!("unrecorded"), "{record}");
    assert_eq!(record["decision"].get("rule_id"), None, "{record}");
}
