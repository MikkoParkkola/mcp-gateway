// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one §9.1 error envelope every `/accounts/v1` JSON route answers in,
//! so POST, status and DELETE refusals cannot drift apart.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

/// Every `/accounts/v1` JSON body carries this version.
pub(super) const SCHEMA: &str = "accounts.v1";

/// The envelope's body; callers may add sibling fields (`local_status`).
pub(super) fn body(code: &str, retryable: bool) -> Value {
    body_with_message(code, code, retryable)
}

/// [`body`] with a caller-facing `message`, for a refusal whose text says
/// more than its code (the dispatch-site connect offer).
pub(super) fn body_with_message(code: &str, message: &str, retryable: bool) -> Value {
    json!({"schema_version": SCHEMA,
           "error": {"code": code, "message": message, "retryable": retryable}})
}

/// The refusal; `Retry-After` when the refusal names one.
pub(super) fn refusal(status: StatusCode, code: &str, retry_after: Option<u64>) -> Response {
    let retryable = retry_after.is_some() || status == StatusCode::SERVICE_UNAVAILABLE;
    let mut response = (status, axum::Json(body(code, retryable))).into_response();
    if let Some(seconds) = retry_after {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from(seconds));
    }
    response
}
