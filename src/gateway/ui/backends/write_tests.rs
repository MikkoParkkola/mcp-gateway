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
