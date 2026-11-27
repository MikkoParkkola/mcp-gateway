// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// R2: how the key create route answers each writer refusal, by class.

use axum::http::header::RETRY_AFTER;

use super::*;

async fn seen(error: ReplaceError) -> (StatusCode, Option<String>, serde_json::Value) {
    let reply = refused_by_writer(error);
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
async fn key_create_refusals_follow_the_class() {
    use crate::config_reload::{RELOAD_RESTARTING, RefusalClass};
    use crate::gateway::restart_config_floor::Refusal as Gate;
    let flat = |text: &str| json!({ "error": text });
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
            now.clone(),
            flat("a restart is being prepared; retry"),
        ),
        (
            ReplaceError::Gated(Gate::ReplayOwed),
            StatusCode::CONFLICT,
            now,
            flat("a restart is being prepared; retry"),
        ),
        (
            ReplaceError::Gated(Gate::Restarting),
            StatusCode::CONFLICT,
            None,
            json!({"error": "restarting", "message": RELOAD_RESTARTING}),
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
            flat("reload is off or gateway.yaml could not be loaded"),
        ),
        (
            ReplaceError::NoConfigFile,
            StatusCode::CONFLICT,
            None,
            flat("no_config_file"),
        ),
        (
            ReplaceError::WriterRefused {
                code: "foreign-owner",
                text: "w".into(),
            },
            StatusCode::CONFLICT,
            None,
            flat("the key was not created"),
        ),
        // Kept as they were: a step was started, or a reload refused it.
        (
            ReplaceError::Write("w".into()),
            StatusCode::INTERNAL_SERVER_ERROR,
            None,
            flat("the key was not created"),
        ),
        (
            ReplaceError::ReloadRefused {
                class: RefusalClass::Internal,
                reason: "r".into(),
            },
            StatusCode::CONFLICT,
            None,
            flat("reload_refused"),
        ),
    ];
    for (error, code, wait, body) in rows {
        let label = format!("{error:?}");
        assert_eq!(seen(error).await, (code, wait, body), "{label}");
    }
}
