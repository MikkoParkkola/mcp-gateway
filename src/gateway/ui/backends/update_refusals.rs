// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The backend update's refusals, checked before anything is read.

use axum::http::StatusCode;
use axum::response::IntoResponse;

use super::super::errors::flat_error;

/// The update's refusals before anything is read: an invalid allowed-tools
/// list, both a command and a URL, or a credential in the new command or URL
/// (it would land in gateway.yaml as text; refused by field).
pub(super) fn refuse_update(
    name: &str,
    allowed_tools: Option<&[String]>,
    command: Option<&str>,
    url: Option<&str>,
) -> Option<axum::response::Response> {
    if let Some(list) = allowed_tools
        && let Err(refused) = crate::config::check_backend_allowed_tools(name, list)
    {
        return Some(
            flat_error(StatusCode::UNPROCESSABLE_ENTITY, refused.to_string()).into_response(),
        );
    }
    if command.is_some() && url.is_some() {
        return Some(
            flat_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Provide either 'command' or 'url', not both",
            )
            .into_response(),
        );
    }
    let refused = super::super::backend_ops::credential_refusals(command, url);
    (!refused.is_empty()).then(|| super::super::secret_slots::refused_values(&refused))
}
