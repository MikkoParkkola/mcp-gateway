// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /accounts/v1/complete` and its one script (design §4.3, §8.3): the
//! bridge-verified caller's own connection per managed descriptor, each
//! connected one with a Disconnect button.
//!
//! Descriptor ids come from config and are still escaped. The script tag is
//! emitted only when a button exists, since the button is its only use.

use std::fmt::Write as _;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;

use super::super::AppState;
use super::bridge::{OwuiSessionBridge, session_of};
use super::callback::escape;
use crate::config::{Config, account_bindings};
use crate::key_server::oidc::VerifiedIdentity;
use crate::personal_accounts::AccountRevocation;
use crate::personal_accounts::identity::{Principal, account_key};

/// Where the callback page sends the user next, a same-origin navigation.
pub(super) const COMPLETE: &str = "/accounts/v1/complete";
const SCRIPT: &str = "/accounts/v1/assets/complete.js";
const SCRIPT_BODY: &str = include_str!("complete.js");

pub(super) fn routes(
    revocation: Arc<dyn AccountRevocation>,
    bridge: Arc<OwuiSessionBridge>,
) -> Router<Arc<AppState>> {
    Router::new()
        .route(
            COMPLETE,
            get(move |state, headers| complete(revocation, bridge, state, headers)),
        )
        .route(
            SCRIPT,
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    SCRIPT_BODY,
                )
            }),
        )
}

async fn complete(
    revocation: Arc<dyn AccountRevocation>,
    bridge: Arc<OwuiSessionBridge>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let config = state.live_config.get();
    let Some(session) = session_of(&config) else {
        return page(StatusCode::FORBIDDEN, SIGN_IN);
    };
    let Some(identity) = bridge.identity(&session, &headers).await else {
        return page(StatusCode::FORBIDDEN, SIGN_IN);
    };
    match connections(&config, &identity, &*revocation).await {
        Some(rows) => page(StatusCode::OK, &list(&rows)),
        None => page(
            StatusCode::SERVICE_UNAVAILABLE,
            "<p>The account service is unavailable. Try again later.</p>",
        ),
    }
}

const SIGN_IN: &str = "<p>Sign in to Open WebUI in this browser, then retry.</p>";

/// `(descriptor id, connected)` for each managed descriptor, keyed to the
/// caller only; `None` when any read fails, so no partial state is shown.
async fn connections(
    config: &Config,
    identity: &VerifiedIdentity,
    revocation: &dyn AccountRevocation,
) -> Option<Vec<(String, bool)>> {
    let mut rows = Vec::new();
    for compiled in account_bindings::compile_descriptors(config).ok()? {
        let Some(descriptor) = compiled.account else {
            continue;
        };
        let key = account_key(Some(Principal::Verified(identity)), &descriptor).ok()?;
        rows.push((
            compiled.descriptor_id,
            revocation.connected(&key).await.ok()?,
        ));
    }
    Some(rows)
}

fn list(rows: &[(String, bool)]) -> String {
    let mut html = String::from("<h1>Account connections</h1><ul>");
    for (id, connected) in rows {
        let id = escape(id);
        if *connected {
            let _ = write!(
                html,
                "<li>{id}: connected <button type=\"button\" data-account=\"{id}\">\
                 Disconnect</button></li>"
            );
        } else {
            let _ = write!(html, "<li>{id}: not connected</li>");
        }
    }
    html.push_str("</ul>");
    if rows.iter().any(|(_, connected)| *connected) {
        let _ = write!(html, "<script src=\"{SCRIPT}\" defer></script>");
    }
    html
}

fn page(status: StatusCode, content: &str) -> Response {
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <title>Account connections</title></head><body>{content}</body></html>"
    );
    (status, Html(body)).into_response()
}
