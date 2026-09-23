// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /accounts/v1/callback` (design §6.2, §7): the provider's redirect
//! back. Custody does the work; this handler parses the request and renders
//! the outcome page itself (step 12), because a second redirect would arrive
//! at `/complete` as `cross-site`.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{Html, IntoResponse, Response};

use super::super::AppState;
use super::hosted::CALLBACK;
use crate::personal_accounts::{CallbackOutcome, CallbackRequest, JourneyLimits, JourneyService};

/// Each journey's binding cookie is named for it, so parallel journeys in one
/// browser never overwrite each other's (§4.2 step 7, L4).
const BINDING_COOKIE: &str = "__Secure-mcpgw-journey-";
/// Where the page sends the user next, a same-origin navigation.
const COMPLETE: &str = "/accounts/v1/complete";

/// The binding cookie for journey `id`. `__Host-` would need `Path=/`; the
/// cookie is scoped to the callback only. `max_age == 0` clears it.
pub(super) fn binding_cookie(id: &str, value: &str, max_age: u64) -> String {
    format!(
        "{BINDING_COOKIE}{id}={value}; Secure; HttpOnly; SameSite=Lax; Path={CALLBACK}; \
         Max-Age={max_age}"
    )
}

pub(super) async fn callback(
    journeys: Arc<dyn JourneyService>,
    State(state): State<Arc<AppState>>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let Some(request) = request_of(&state, &uri, &headers) else {
        return render(&CallbackOutcome::Invalid);
    };
    render(&journeys.callback(request).await)
}

/// `None` without a `state` or without an accounts block: nothing to name.
fn request_of(state: &AppState, uri: &Uri, headers: &HeaderMap) -> Option<CallbackRequest> {
    let mut query: BTreeMap<String, String> = BTreeMap::new();
    for (name, value) in url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes()) {
        query
            .entry(name.into_owned())
            .or_insert_with(|| value.into_owned());
    }
    let config = state.live_config.get();
    let accounts = config.accounts.as_ref()?;
    Some(CallbackRequest {
        limits: JourneyLimits::from(&accounts.limits),
        state: query.remove("state")?,
        code: query.remove("code"),
        error: query.remove("error"),
        iss: query.remove("iss"),
        bindings: bindings_of(headers),
        descriptors: accounts.descriptors.clone().unwrap_or_default(),
        audit: state.transparency_log.clone(),
    })
}

/// Every journey binding cookie the browser sent, by journey id.
fn bindings_of(headers: &HeaderMap) -> BTreeMap<String, String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .filter_map(|(name, value)| {
            let id = name.strip_prefix(BINDING_COOKIE)?;
            Some((id.to_owned(), value.to_owned()))
        })
        .collect()
}

/// Gateway text only, escaped, no script; a known journey's binding cookie
/// is cleared with the attributes that set it.
fn render(outcome: &CallbackOutcome) -> Response {
    let (status, message, links, cleared) = match outcome {
        CallbackOutcome::Invalid => (
            StatusCode::BAD_REQUEST,
            "This link is not valid. Start again from Open WebUI.",
            String::new(),
            None,
        ),
        CallbackOutcome::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "The account service is unavailable. Try again later.",
            String::new(),
            None,
        ),
        CallbackOutcome::Page {
            journey_id,
            message,
            return_path,
        } => (
            StatusCode::OK,
            message.as_str(),
            format!(
                "<p><a href=\"{}\">Return to Open WebUI</a></p>\
                 <p><a href=\"{COMPLETE}\">Manage account connections</a></p>",
                escape(return_path)
            ),
            Some(binding_cookie(journey_id, "", 0)),
        ),
    };
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <title>Connect account</title></head><body><p>Account connection: {}</p>{links}\
         </body></html>",
        escape(message)
    );
    let mut response = (status, Html(body)).into_response();
    if let Some(cookie) = cleared.and_then(|cookie| HeaderValue::from_str(&cookie).ok()) {
        response.headers_mut().insert(header::SET_COOKIE, cookie);
    }
    response
}

fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}
