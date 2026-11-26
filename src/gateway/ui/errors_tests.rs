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
