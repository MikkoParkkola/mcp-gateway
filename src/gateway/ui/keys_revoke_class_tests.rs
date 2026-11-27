// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// R3: key revoke's answer to each writer refusal, by class.

use axum::http::header::RETRY_AFTER;

use super::*;

async fn reply_of(error: ReplaceError) -> (StatusCode, Option<String>, serde_json::Value) {
    let reply = refused("target", error);
    let code = reply.status();
    let wait = reply
        .headers()
        .get(RETRY_AFTER)
        .map(|h| h.to_str().unwrap().to_owned());
    let raw = axum::body::to_bytes(reply.into_body(), usize::MAX)
        .await
        .unwrap();
    (code, wait, serde_json::from_slice(&raw).unwrap())
}

#[tokio::test]
async fn key_revoke_refusals_follow_the_class() {
    use crate::config_reload::{RELOAD_STOPPING, RefusalClass};
    use crate::gateway::restart_config_floor::Refusal as Gate;
    let flat = |text: &str| serde_json::json!({ "error": text });
    let now = Some("1".to_owned());
    let rows: Vec<(ReplaceError, StatusCode, Option<String>, serde_json::Value)> = vec![
        (
            ReplaceError::Busy,
            StatusCode::CONFLICT,
            now.clone(),
            flat("the config is being written; retry"),
        ),
        (
            ReplaceError::Gated(Gate::Busy),
            StatusCode::CONFLICT,
            now,
            flat("a restart is being prepared; retry"),
        ),
        (
            ReplaceError::Gated(Gate::Stopping),
            StatusCode::CONFLICT,
            None,
            serde_json::json!({"error": "stopping", "message": RELOAD_STOPPING}),
        ),
        (
            ReplaceError::NoAuditLog,
            StatusCode::CONFLICT,
            None,
            flat("audit_unavailable"),
        ),
        (
            ReplaceError::AuditRefused("a".into()),
            StatusCode::SERVICE_UNAVAILABLE,
            None,
            flat("audit_unavailable"),
        ),
        (
            ReplaceError::ConfigRefused("c".into()),
            StatusCode::CONFLICT,
            None,
            flat("gateway.yaml could not be loaded"),
        ),
        (
            ReplaceError::NoConfigFile,
            StatusCode::CONFLICT,
            None,
            flat("no_config_file"),
        ),
        (
            ReplaceError::WriterRefused {
                code: "target-changed",
                text: "w".into(),
            },
            StatusCode::CONFLICT,
            None,
            flat("not_written"),
        ),
        // Kept as they were: a step was started, or the outcome is uncertain.
        (
            ReplaceError::Stage("s".into()),
            StatusCode::INTERNAL_SERVER_ERROR,
            None,
            flat("not_written"),
        ),
        (
            ReplaceError::ReloadRefused {
                class: RefusalClass::Internal,
                reason: "r".into(),
            },
            StatusCode::INTERNAL_SERVER_ERROR,
            None,
            flat("state_uncertain"),
        ),
    ];
    for (error, code, wait, body) in rows {
        let label = format!("{error:?}");
        assert_eq!(reply_of(error).await, (code, wait, body), "{label}");
    }
}
