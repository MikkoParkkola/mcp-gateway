// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The dashboard handoff code (#2130): how a link redeemed at the loopback URL
//! signs a browser in on an HTTPS `public_url` served through a proxy.
//!
//! The loopback redemption shows a one-time code; the operator enters it in a
//! same-origin form on the public origin, which sets the session cookie there.
//! The code never travels in a URL, so no proxy access log, history entry or
//! `Referer` carries it, and no proxy header is trusted to vouch for anything.
//!
//! Only a build with the dashboard (`webui`) hands off; `private` alone is
//! shared, since every bootstrap answer uses it.

use axum::http::{HeaderValue, header};
use axum::response::Response;
#[cfg(feature = "webui")]
use axum::{http::StatusCode, response::IntoResponse};
#[cfg(feature = "webui")]
use tracing::warn;

#[cfg(feature = "webui")]
use crate::security::security_metrics::{AuthFailureKind, auth_failure};

#[cfg(feature = "webui")]
use super::{AuthState, DashboardBootstrap, Now, Redemption, bearer_unauthorized_response};

/// Where the code is entered, on the public origin.
#[cfg(feature = "webui")]
pub(crate) const HANDOFF_PATH: &str = crate::gateway::routes::DASHBOARD_HANDOFF;

/// The HTTPS origin browsers reach this gateway at, from the live
/// `public_url`; `None` when there is none or it is not HTTPS.
#[cfg(feature = "webui")]
fn public_origin(state: &AuthState) -> Option<String> {
    public_origin_of(&state.live_config)
}

#[cfg(feature = "webui")]
fn public_origin_of(live: &crate::config_reload::LiveConfig) -> Option<String> {
    let live = live.get();
    let url = url::Url::parse(live.server.public_url.as_deref()?).ok()?;
    (url.scheme() == "https").then(|| url.origin().ascii_serialization())
}

/// The loopback redemption's hand-off (#2130): spend the link and answer
/// with a one-time code for the public origin. `None` when there is no HTTPS
/// public origin, or the link is no longer the live value.
#[cfg(feature = "webui")]
pub(super) fn hand_off(state: &AuthState, candidate: &str) -> Option<Response> {
    let origin = public_origin(state)?;
    let Redemption { not_after, now } = state.dashboard_bootstrap.consume_capped(candidate)?;
    let code = state.dashboard_bootstrap.mint_handoff(now, not_after);
    Some(code_page(&origin, &code))
}

/// The loopback redemption's answer: the code, and where to enter it. There is
/// deliberately no link to follow: a navigation from this loopback page to the
/// public origin is cross-site, which the origin gate refuses.
#[cfg(feature = "webui")]
fn code_page(origin: &str, code: &str) -> Response {
    let (origin, code) = (escape(origin), escape(code));
    private(html(format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Dashboard sign-in</title>\
         <p>Open <strong>{origin}{HANDOFF_PATH}</strong> and enter this code within 60 \
         seconds. It works once. Type the address; do not follow a link to it.</p>\
         <p><code id=\"handoff\">{code}</code></p>"
    )))
}

/// `GET /dashboard/handoff`: a form that holds nothing, served to anyone.
#[cfg(feature = "webui")]
pub(crate) fn handoff_form() -> Response {
    let mut response = private(html(format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Dashboard sign-in</title>\
         <form method=\"post\" action=\"{HANDOFF_PATH}\"><label>Code \
         <input name=\"code\" autocomplete=\"off\" required autofocus></label> \
         <button>Sign in</button></form>"
    )));
    // A form posted from a page under `no-referrer` sends `Origin: null`
    // (Fetch), which the origin gate refuses. `same-origin` keeps the Origin
    // and still sends no `Referer` off this origin; this URL holds nothing.
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    response
}

/// `POST /dashboard/handoff`: spend the posted code for a session.
///
/// Routed outside authentication, like logout: the code is the credential,
/// and a live or dead session cookie the browser holds must not decide it.
/// The origin gate still applies, so only a same-origin form can post here.
/// Neither the body nor the code is logged or echoed.
#[cfg(feature = "webui")]
pub(crate) fn redeem_handoff(
    bootstrap: &DashboardBootstrap,
    live: &crate::config_reload::LiveConfig,
    origin: Option<&str>,
    body: &[u8],
) -> Response {
    // Spent anywhere but the public origin, the code would set a cookie there
    // that a browser drops: refuse it, unspent. `Origin` is written by the
    // browser and passed through by a proxy, unlike `Host`, which a proxy may
    // rewrite to this listener's own address.
    if origin.is_none() || public_origin_of(live).as_deref() != origin {
        warn!("Dashboard handoff refused: the code was not posted on the public origin");
        return private(bearer_unauthorized_response(
            "Enter the code on the gateway's public HTTPS address, at /dashboard/handoff.",
        ));
    }
    let code = url::form_urlencoded::parse(body)
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.trim().to_string());
    let Some(Redemption { not_after, now }) =
        code.and_then(|code| bootstrap.take_handoff(&code, Now::read()))
    else {
        auth_failure(AuthFailureKind::BootstrapRefused);
        warn!("Dashboard handoff refused: wrong, used or expired code");
        return private(bearer_unauthorized_response(
            "The code is wrong, used or expired. Run `mcp-gateway dashboard-link` for a new link.",
        ));
    };
    // Always `Secure`: a code exists only because this origin is HTTPS, and a
    // reload since it was minted must not downgrade the cookie it sets.
    private(super::bootstrap::signed_in(
        bootstrap, live, not_after, now, true,
    ))
}

/// Nothing on these pages may be cached or sent onward as a `Referer`.
pub(crate) fn private(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    // A page that set its own policy keeps it: the code form needs one.
    headers
        .entry(header::REFERRER_POLICY)
        .or_insert(HeaderValue::from_static("no-referrer"));
    response
}

#[cfg(feature = "webui")]
fn html(body: String) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

#[cfg(feature = "webui")]
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
