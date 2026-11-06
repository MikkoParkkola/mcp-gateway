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

/// T6e and the store's other refusals: each answers fixed text naming no
/// store detail. A vault lock another save held past the deadline is the
/// store's `Refused(Failed(..))` (secret_store/save.rs `take_lock`): a 503
/// that says nothing was written. A timed-out create is a 503 that says its
/// entry may land later; an unavailable store and an over-limit value 422.
#[tokio::test]
async fn the_store_refusals_answer_fixed_text_by_kind() {
    use crate::secret_store::{SaveError, StoreError, StoreKind};
    let busy = "another save held the vault lock until the deadline; nothing was written";
    let cases = [
        (
            SaveError::Refused(StoreError::Failed(busy.to_owned())),
            StatusCode::SERVICE_UNAVAILABLE,
            "nothing was written",
        ),
        (
            SaveError::Store(StoreError::TimedOut),
            StatusCode::SERVICE_UNAVAILABLE,
            "kept and listed as unused",
        ),
        (
            SaveError::Refused(StoreError::Unavailable("probe-detail".to_owned())),
            StatusCode::UNPROCESSABLE_ENTITY,
            "secrets.store cannot take",
        ),
        (
            SaveError::Refused(StoreError::TooLarge {
                limit: 4,
                store: StoreKind::Files,
            }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "value_too_large",
        ),
    ];
    for (error, code, says) in cases {
        let (status, text) = message(&ReplaceError::Secrets(error)).await;
        assert_eq!(status, code, "{text}");
        assert!(text.contains(says), "{text}");
        assert!(
            !text.contains("probe-detail") && !text.contains("vault lock"),
            "a store detail leaked: {text}"
        );
    }
}
