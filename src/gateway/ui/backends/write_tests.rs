// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The backend routes' write answers: a write whose outcome on disk is
//! unknown never says nothing was written.

use super::*;

async fn message(e: &ReplaceError) -> (StatusCode, String) {
    let response = refused_write(e);
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// A failed rollback, and a write that failed anywhere, may have left
/// gateway.yaml changed: the answer never says nothing was written.
#[tokio::test]
async fn a_failed_rollback_or_write_answers_state_neutral_text() {
    let failures = [
        ReplaceError::RollbackFailed {
            journal: std::path::PathBuf::from("j"),
            error: "e".to_owned(),
        },
        ReplaceError::Failed("e".to_owned()),
    ];
    for e in &failures {
        let (status, text) = message(e).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{e:?}: {text}");
        assert!(!text.contains("not written"), "{e:?}: {text}");
        assert!(text.contains("may have changed"), "{e:?}: {text}");
    }
}

/// The writer's typed outcomes answer fixed text: a missing file the shared
/// 409 with its way forward, the guard's refusal a 503 that never carries
/// the guard's own text (it names the file).
#[tokio::test]
async fn the_writer_refusals_answer_fixed_text() {
    let (status, text) = message(&ReplaceError::NoConfigFile).await;
    assert_eq!(status, StatusCode::CONFLICT, "{text}");
    assert!(
        text.contains("no_config_file") && text.contains("mcp-gateway init --profile local"),
        "{text}"
    );

    let detail = "/secret/path/gateway.yaml is writable by its group";
    let (status, text) = message(&ReplaceError::ConfigRefused(detail.to_owned())).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{text}");
    assert!(text.contains("gateway.yaml could not be loaded"), "{text}");
    assert!(
        !text.contains("/secret/path"),
        "the guard's text leaked: {text}"
    );
}

/// SAVE.6: the audit-log answer follows the refusal's type. Any other
/// refusal answers its own code, even one carrying the same words.
#[tokio::test]
async fn the_audit_log_answer_follows_the_type_not_the_words() {
    let (status, text) = message(&ReplaceError::Refused(NO_AUDIT_LOG.to_owned())).await;
    assert_ne!(status, StatusCode::SERVICE_UNAVAILABLE, "{text}");
    assert!(!text.contains("audit_log_required"), "{text}");
}
