// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How the capability editor's routes answer a refusal: one body shape,
//! `{error, message, patch?, errors?, current_sha256?}`, for every refusal
//! the capability writer returns.

use axum::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::{Value, json};

use crate::capability::file_writer::{FieldError, Refused};

pub(super) fn field_errors(errors: &[FieldError]) -> Value {
    errors
        .iter()
        .map(|e| {
            let mut entry = serde_json::Map::new();
            if let Some(line) = e.line {
                entry.insert("line".into(), line.into());
            }
            if let Some(column) = e.column {
                entry.insert("column".into(), column.into());
            }
            if let Some(field) = &e.field {
                entry.insert("field".into(), field.clone().into());
            }
            entry.insert("message".into(), e.message.clone().into());
            Value::Object(entry)
        })
        .collect()
}

/// A refusal as the editor's routes answer it: `{error, message, patch?,
/// errors?, current_sha256?}`. Nothing was written.
pub(super) fn refused(name: &str, refusal: Refused) -> axum::response::Response {
    let (status, code, message, extra) = match refusal {
        Refused::Stale {
            patch,
            current_sha256,
        } => (
            StatusCode::CONFLICT,
            "stale",
            format!("Capability '{name}' changed on disk since it was loaded; reload it"),
            json!({ "patch": patch, "current_sha256": current_sha256 }),
        ),
        Refused::PinMismatch { patch } => (
            StatusCode::CONFLICT,
            "pin_mismatch",
            format!(
                "Capability '{name}' no longer matches its pin; review the file, then run `cap pin` or restore a version"
            ),
            json!({ "patch": patch }),
        ),
        Refused::Unpin { patch } => (
            StatusCode::CONFLICT,
            "unpin",
            format!(
                "Capability '{name}' is pinned; removing its pin is a `cap` command, not an edit"
            ),
            json!({ "patch": patch }),
        ),
        Refused::PinAmbiguous { patch } => (
            StatusCode::CONFLICT,
            "pin_ambiguous",
            "The text has more than one pin line, or text after a line break on its pin line"
                .to_owned(),
            json!({ "patch": patch }),
        ),
        Refused::Symlinked { real_path } => (
            StatusCode::CONFLICT,
            "symlinked",
            format!("Capability '{name}' is a symlink; edit it where it lives: {real_path}"),
            json!({}),
        ),
        Refused::Unwritable { error, patch } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "unwritable",
            format!("Capability '{name}' could not be written: {error}"),
            json!({ "patch": patch }),
        ),
        Refused::LockBusy => (
            StatusCode::SERVICE_UNAVAILABLE,
            "lock_busy",
            "Another write to this capability directory is in progress; retry".to_owned(),
            json!({}),
        ),
        Refused::Invalid { errors, patch } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid",
            format!("Capability '{name}' would not load"),
            json!({ "errors": field_errors(&errors), "patch": patch }),
        ),
    };
    let mut body = json!({ "error": code, "message": message });
    if let (Value::Object(body), Value::Object(extra)) = (&mut body, extra) {
        body.extend(extra);
    }
    (status, Json(body)).into_response()
}
