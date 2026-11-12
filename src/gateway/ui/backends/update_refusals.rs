// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The backend update's refusals, checked before anything is read.

use axum::http::StatusCode;
use axum::response::IntoResponse;

use super::super::errors::flat_error;
use super::super::refusals::WriteTicket;
use crate::config_reload::refusals::RefusalKind;
use crate::gateway::router::AppState;

/// The update's refusals before anything is read: an invalid allowed-tools
/// list, both a command and a URL, or a credential in the new command or URL
/// (it would land in gateway.yaml as text; refused by field).
pub(super) fn refuse_update(
    state: &AppState,
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
    credential_answer(state, RefusalKind::Edit, name, command, url)
}

/// The 422 for a credential in the saved command or URL, by field, after
/// recording the refused add or edit in the refusal list so it is listed like
/// any other refused write (without its values); `None` when there is none.
pub(super) fn credential_answer(
    state: &AppState,
    kind: RefusalKind,
    name: &str,
    command: Option<&str>,
    url: Option<&str>,
) -> Option<axum::response::Response> {
    let refused = super::super::backend_ops::credential_refusals(command, url);
    if refused.is_empty() {
        return None;
    }
    WriteTicket::new(state).record(kind, name, &listed_cause(name, command, url));
    Some(super::super::secret_slots::refused_values(&refused))
}

/// The cause the refusal list classifies: the most specific code that already
/// exists. A plain-HTTP (or WS) URL to a host off this machine is exactly what
/// the cleartext check refuses, so it is listed as that; any other credential
/// in a command or URL is listed as invalid configuration. Never a value.
fn listed_cause(name: &str, command: Option<&str>, url: Option<&str>) -> String {
    // A given command is what is saved (and checked); its URL is not.
    let cleartext = command.is_none()
        && url
            .and_then(|raw| url::Url::parse(raw).ok())
            .is_some_and(|url| {
                matches!(url.scheme(), "http" | "ws")
                    && !crate::gateway::is_loopback_host(url.host_str().unwrap_or_default())
            });
    let cause = if cleartext {
        crate::config::CLEARTEXT_REFUSAL
    } else {
        super::super::backend_ops::CREDENTIAL_IN_ARGV
    };
    format!("Backend '{name}' {cause}")
}
