// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

#[test]
fn admin_auth_required_shape_is_stable() {
    let (status, body) = admin_auth_required();
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body.0, json!({ "error": "Admin authentication required" }));
}

#[test]
fn auth_required_preserves_caller_status() {
    let (status, body) = auth_required(StatusCode::UNAUTHORIZED);
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body.0, json!({ "error": "Authentication required" }));
}

#[test]
fn config_path_unavailable_shape_is_stable() {
    let (status, body) = config_path_unavailable();
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body.0,
        json!({ "error": "Config file path not available; cannot persist changes" })
    );
}

#[test]
fn flat_error_uses_error_field() {
    let (status, body) = flat_error(StatusCode::CONFLICT, "example");
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body.0, json!({ "error": "example" }));
}

#[test]
fn structured_error_uses_error_and_message_fields() {
    let (status, body) = structured_error(
        StatusCode::BAD_REQUEST,
        "invalid_name",
        "bad capability name",
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body.0,
        json!({
            "error": "invalid_name",
            "message": "bad capability name",
        })
    );
}

/// C1: every writer error is classified, and exactly as the class rule says
/// (sidecar 1 for `WriterRefused`).
#[test]
fn every_writer_error_is_classified() {
    use crate::config_reload::FileRevision;
    use std::path::PathBuf;
    let s = || "x".to_owned();
    let cases: Vec<(ReplaceError, Option<Retry>)> = vec![
        (ReplaceError::Busy, Some(Retry::Now)),
        (ReplaceError::Gated(Refusal::Busy), Some(Retry::Now)),
        (ReplaceError::Gated(Refusal::ReplayOwed), Some(Retry::Now)),
        (ReplaceError::Gated(Refusal::Restarting), Some(Retry::No)),
        (ReplaceError::Gated(Refusal::Stopping), Some(Retry::No)),
        (
            ReplaceError::Stale {
                current: FileRevision::of(b"x"),
            },
            Some(Retry::No),
        ),
        (ReplaceError::NoAuditLog, Some(Retry::No)),
        (ReplaceError::NoConfigFile, Some(Retry::No)),
        (ReplaceError::ConfigRefused(s()), Some(Retry::No)),
        (
            ReplaceError::WriterRefused {
                code: "foreign-owner",
                text: s(),
            },
            Some(Retry::No),
        ),
        (ReplaceError::AuditRefused(s()), None),
        (ReplaceError::Refused(s()), None),
        (ReplaceError::Unsupported(s()), None),
        (ReplaceError::Stage(s()), None),
        (ReplaceError::Write(s()), None),
        (
            ReplaceError::ReloadRefused {
                class: RefusalClass::Posture,
                reason: s(),
            },
            None,
        ),
        (
            ReplaceError::RollbackFailed {
                journal: PathBuf::new(),
                error: s(),
            },
            None,
        ),
        (
            ReplaceError::Unconfirmed {
                journal: PathBuf::new(),
                error: s(),
            },
            None,
        ),
        (ReplaceError::Failed(s()), None),
        (
            ReplaceError::Secrets(SaveError::Store(StoreError::TimedOut)),
            None,
        ),
    ];
    for (error, expected) in &cases {
        assert_eq!(nothing_attempted(error), *expected, "{error:?}");
    }
}

/// C2: `refusal` sets 409, keeps the body and every other header, and owns
/// `Retry-After` in both directions.
#[tokio::test]
async fn refusal_sets_409_and_owns_retry_after() {
    let incoming = || {
        let mut answer = flat_error(StatusCode::SERVICE_UNAVAILABLE, "busy body").into_response();
        let headers = answer.headers_mut();
        headers.insert("x-probe", HeaderValue::from_static("kept"));
        headers.insert(RETRY_AFTER, HeaderValue::from_static("30"));
        answer
    };
    for (retry, header) in [(Retry::Now, Some("1")), (Retry::No, None)] {
        let answer = refusal(retry, incoming());
        assert_eq!(answer.status(), StatusCode::CONFLICT, "{retry:?}");
        assert_eq!(
            answer.headers().get("x-probe").unwrap(),
            "kept",
            "{retry:?}"
        );
        let after = answer
            .headers()
            .get(RETRY_AFTER)
            .map(|v| v.to_str().unwrap().to_owned());
        assert_eq!(after.as_deref(), header, "{retry:?}");
        let body = axum::body::to_bytes(answer.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], br#"{"error":"busy body"}"#, "{retry:?}");
    }
}
