// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use axum::Json;
use axum::http::StatusCode;
use serde_json::{Value, json};

use crate::config_reload::FileRevision;
use crate::gateway::http_error::{flat_error_body, json_body, structured_error_body};

pub(super) fn flat_error(
    status: StatusCode,
    message: impl Into<String>,
) -> (StatusCode, Json<Value>) {
    json_body(status, flat_error_body(message))
}

pub(super) fn structured_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> (StatusCode, Json<Value>) {
    json_body(status, structured_error_body(code, message))
}

/// The 409 of a gateway.yaml revision that moved: the one to retry against.
pub(super) fn stale(current: &FileRevision) -> (StatusCode, Json<Value>) {
    json_body(
        StatusCode::CONFLICT,
        json!({"error": "stale", "current": current.as_str()}),
    )
}

/// Why a config write found no gateway.yaml to write into, and the way
/// forward: every web UI route that edits the file answers it.
const NO_CONFIG_FILE: &str = "no gateway.yaml exists yet; create one with `mcp-gateway init --profile local` (see QUICKSTART), then retry";

/// 409 `no_config_file`: nothing is written; the operator creates the file.
pub(super) fn no_config_file() -> (StatusCode, Json<Value>) {
    structured_error(StatusCode::CONFLICT, "no_config_file", NO_CONFIG_FILE)
}

/// gateway.yaml could not be read, or the read guard refused it or its
/// recovery files. Fixed text for every route that writes it: the reason
/// names the file, so it goes to the log only.
pub(super) fn config_refusal() -> (StatusCode, Json<Value>) {
    flat_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "gateway.yaml could not be loaded",
    )
}

pub(super) fn admin_auth_required() -> (StatusCode, Json<Value>) {
    flat_error(StatusCode::FORBIDDEN, "Admin authentication required")
}

pub(super) fn auth_required(status: StatusCode) -> (StatusCode, Json<Value>) {
    flat_error(status, "Authentication required")
}

pub(super) fn config_path_unavailable() -> (StatusCode, Json<Value>) {
    flat_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "Config file path not available; cannot persist changes",
    )
}

#[cfg(test)]
mod tests {
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
}
