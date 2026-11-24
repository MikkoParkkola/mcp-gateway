// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F2d: the stdio signing-refusal writer on its own, before any delivery
//! step could replace its answer. Under a fail-closed log that cannot take
//! the record it answers the log's unavailability, under the request's own
//! id; once the log takes writes again, the refusal as decided. Deleting the
//! writer's unavailable branch fails the first half.

use std::sync::Arc;

use crate::gateway::router::{AnswerId, SigningSite, answer_stdio_signing_refusal};
use crate::security::audit::AuditFailurePolicy::FailClosed;
use crate::security::transparency_log::TransparencyLogConfig;

#[tokio::test]
async fn f2d_stdio_writer_answers_unavailable_when_it_cannot_record() {
    let temp = crate::security::transparency_log::temp::TempLog::new();
    let config = TransparencyLogConfig {
        key_id: "f2d".into(),
        path: temp.path().display().to_string(),
        enabled: true,
        ..TransparencyLogConfig::default()
    };
    let opened = crate::security::TransparencyLogger::open(Arc::new(config));
    let log = Arc::new(opened.expect("f2d log").with_failure_policy(FailClosed));
    let mut meta = super::MetaMcp::new(Arc::new(super::BackendRegistry::new()));
    meta.enable_transparency_log(Arc::clone(&log));

    let target = serde_json::json!({"server": "alpha", "tool": "read"});
    let refuse = || {
        let id = AnswerId::Present(crate::protocol::RequestId::Number(41));
        answer_stdio_signing_refusal(
            &meta,
            super::stdio_audit_who(meta.record_key()),
            (&target, "gateway_invoke", "f2d"),
            (id, SigningSite::Intake),
            crate::Error::json_rpc(-32602, "Invalid signing nonce"),
        )
    };
    let id_and_code =
        |frame: serde_json::Value| (frame["id"].as_i64(), frame["error"]["code"].as_i64());

    log.set_append_failure_for_test(true);
    let unrecordable = id_and_code(refuse().await.to_value_lossy());
    log.set_append_failure_for_test(false);
    let recorded = id_and_code(refuse().await.to_value_lossy());
    assert_eq!(
        (unrecordable, recorded),
        ((Some(41), Some(-32005)), (Some(41), Some(-32602)))
    );
}
