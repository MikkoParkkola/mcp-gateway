// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The add body's `headers` and cleartext override: the checks the add and
//! the preview route share, where the headers go, the cleartext refusal
//! answered before anything is written, and the add's one audit detail.

use std::collections::{HashMap, HashSet};

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use super::AddBackendRequest;
use crate::config::{BackendConfig, Config, TransportConfig};
use crate::config_reload::refusals::{RefusalKind, cleartext_words};
use crate::gateway::router::AppState;
use crate::gateway::ui::admin_audit::{AuditDetail, attach_selection};
use crate::gateway::ui::refusals::WriteTicket;
use crate::gateway::ui::secret_slots::refused_values;

/// The request's own faults in `headers`, the override and the URL, as one
/// first-match list answered by field, before anything is resolved or stored.
/// The add and the preview call this at the same place, so a preview never
/// accepts what the save would refuse. A bad header name or value is never
/// echoed: the refusal names the field `headers` only.
pub(in crate::gateway::ui) fn request_answer(req: &AddBackendRequest) -> Option<Response> {
    let refuse =
        |reason: &'static str, field: &str| Some(refused_values(&[(reason, field.to_owned())]));
    if !req.headers.is_empty() {
        // A command server sends no headers; a registry entry brings its own.
        if req.command.is_some() || req.url.is_none() {
            return refuse("headers_need_url", "headers");
        }
        // Names first, over the whole map, so the answer never depends on the
        // map's order: a name the HTTP parser refuses, then two names that are
        // one header once letter case is ignored (the parsed name is lowercase).
        let mut names = HashSet::new();
        for name in req.headers.keys() {
            let fresh = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                .is_ok_and(|parsed| names.insert(parsed));
            if !fresh {
                return refuse("header_name", "headers");
            }
        }
        if req
            .headers
            .values()
            .any(|value| reqwest::header::HeaderValue::from_str(value).is_err())
        {
            return refuse("header_value", "headers");
        }
    }
    // A command wins over a URL (resolve_backend), so the override with a
    // command would land on a stdio server: refused as headers are.
    if req.allow_cleartext_credentials == Some(true) && (req.command.is_some() || req.url.is_none())
    {
        return refuse("override_needs_url", "allow_cleartext_credentials");
    }
    if req
        .url
        .as_deref()
        .is_some_and(|url| url::Url::parse(url).is_err())
    {
        return refuse("url_invalid", "url");
    }
    None
}

/// The add's own checks on the request, in order, before anything is
/// resolved: the tool selection, the faults [`request_answer`] names, then a
/// credential in the saved command or URL (it would land in gateway.yaml as
/// text), refused by field.
pub(super) fn add_answer(state: &AppState, req: &AddBackendRequest) -> Option<Response> {
    if let Some(list) = &req.allowed_tools
        && let Err(refused) = crate::config::check_backend_allowed_tools(&req.name, list)
    {
        let refused = refused.to_string();
        return Some(
            crate::gateway::ui::errors::flat_error(StatusCode::UNPROCESSABLE_ENTITY, refused)
                .into_response(),
        );
    }
    request_answer(req).or_else(|| {
        super::update_refusals::credential_answer(
            state,
            RefusalKind::Add,
            &req.name,
            req.command.as_deref(),
            req.url.as_deref(),
        )
    })
}

/// The request's headers onto the backend about to be written, and the
/// override only when asked as `true`. Both are set only when given: a
/// registry entry's own headers (a login template) are never replaced by an
/// absent member. A body that gives either without a URL, or with a command,
/// never gets here: [`request_answer`] refused it.
pub(in crate::gateway::ui) fn put_headers(
    backend: &mut BackendConfig,
    headers: HashMap<String, String>,
    allow_cleartext: Option<bool>,
) {
    if !headers.is_empty() {
        backend.headers = headers;
    }
    if allow_cleartext == Some(true) {
        backend.allow_cleartext_credentials = true;
    }
}

/// The config's own cleartext predicate on `backend` exactly as it would be
/// written, but judged as enabled: a server written disabled meets the same
/// refusal when it is enabled later, so the operator hears it at the add.
/// On a refusal it is recorded in the refusal list (kind `add`) and answered
/// 422 with the list's own cause and fix; nothing has been read, stored or
/// locked yet.
pub(super) fn cleartext_answer(
    state: &AppState,
    name: &str,
    backend: &BackendConfig,
) -> Option<Response> {
    let url = match &backend.transport {
        TransportConfig::Http { http_url: url, .. }
        | TransportConfig::WebSocket { ws_url: url, .. } => url,
        #[cfg(feature = "a2a")]
        TransportConfig::A2a { a2a_url: url, .. } => url,
        TransportConfig::Stdio { .. } => return None,
    };
    // A URL that does not parse was refused by field before this point.
    let url = url::Url::parse(url).ok()?;
    let as_enabled = BackendConfig {
        enabled: true,
        ..backend.clone()
    };
    let refused = Config::reject_cleartext_credentials(name, &as_enabled, &url).err()?;
    WriteTicket::new(state).record(RefusalKind::Add, name, &refused.to_string());
    let (message, fix) = cleartext_words(name);
    Some(
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": "cleartext_credentials", "message": message, "fix": fix})),
        )
            .into_response(),
    )
}

/// The add's one `admin_action` detail: the tool selection when one was
/// given, and the override when the entry was written with it. One detail,
/// because a second one attached later would replace the first. Never a
/// header name or value.
pub(super) fn attach_add_detail(
    response: &mut Response,
    name: &str,
    selected: Option<&[String]>,
    cleartext_override: bool,
) {
    if selected.is_some() {
        attach_selection(response, name, None, selected);
    }
    if !cleartext_override {
        return;
    }
    let extensions = response.extensions_mut();
    let mut detail = extensions
        .remove::<AuditDetail>()
        .map_or_else(serde_json::Map::new, |AuditDetail(map)| map);
    detail.insert("cleartext_override".into(), json!(true));
    detail.insert("backend".into(), json!(name));
    extensions.insert(AuditDetail(detail));
}
