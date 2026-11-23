// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! In process, through `handle_tools_call`: a `gateway_invoke` refused for a
//! missing `server` or `tool` is answered as before and leaves one `invalid`
//! -32602 record whose decision kind is the request's form (`syntax`).

use std::sync::Arc;

use serde_json::{Value, json};

use super::grant_audit_fixture::{invocations, logger};
use super::grant_decision_audit_tests::{api_key, call};
use crate::backend::BackendRegistry;
use crate::gateway::meta_mcp::MetaMcp;
use crate::security::audit::AuditFailurePolicy;

/// The answer's text for a missing `key`, rendered by the error type the
/// refusal is built from, so the row follows its prefix.
fn missing_answer(key: &str) -> String {
    crate::Error::json_rpc(
        crate::error::rpc_codes::INVALID_PARAMS,
        format!("Missing '{key}' parameter"),
    )
    .to_string()
}

#[tokio::test]
async fn missing_server_is_recorded_as_syntax_in_process() {
    for (arguments, missing) in [
        (json!({"tool": "t"}), "server"),
        (json!({"server": "alpha"}), "tool"),
    ] {
        let dir = crate::test_dir_keep::kept_tempdir();
        let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
        meta.enable_transparency_log(logger(&dir, AuditFailurePolicy::BestEffort));
        let answer = call(&meta, &api_key("alice"), "gateway_invoke", arguments).await;
        assert_eq!(
            answer.pointer("/error/code").and_then(Value::as_i64),
            Some(-32602),
            "{missing}: {answer}"
        );
        assert_eq!(
            answer.pointer("/error/message").and_then(Value::as_str),
            Some(missing_answer(missing).as_str()),
            "{missing}: {answer}"
        );
        assert_eq!(answer["id"], json!(1), "{missing}: {answer}");
        let records = invocations(&dir);
        let [record] = records.as_slice() else {
            panic!("{missing}: exactly one record: {records:#?}; answer {answer}");
        };
        assert_eq!(record["outcome"], json!("invalid"), "{missing}: {record}");
        assert_eq!(record["error_code"], json!(-32602), "{missing}: {record}");
        assert_eq!(
            record["decision"]["kind"],
            json!("syntax"),
            "{missing}: {record}"
        );
    }
}
