// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The dashboard handoff code (#2130): how a link redeemed at the loopback URL
//! signs a browser in on an HTTPS `public_url` served through a proxy.
//!
//! The loopback redemption shows a one-time code; the operator enters it in a
//! same-origin form on the public origin, which sets the session cookie there.
//! The code never travels in a URL, so no proxy access log, history entry or
//! `Referer` carries it, and no proxy header is trusted to vouch for anything.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
#[cfg(feature = "webui")]
use tracing::warn;

#[cfg(feature = "webui")]
use crate::security::security_metrics::{AuthFailureKind, auth_failure};

use super::AuthState;
#[cfg(feature = "webui")]
use super::{DashboardBootstrap, Now, Redemption, bearer_unauthorized_response};

/// Where the code is entered, on the public origin.
pub(crate) const HANDOFF_PATH: &str = "/dashboard/handoff";

/// The HTTPS origin browsers reach this gateway at, from the live
/// `public_url`; `None` when there is none or it is not HTTPS.
pub(super) fn public_origin(state: &AuthState) -> Option<String> {
    let live = state.live_config.get();
    let url = url::Url::parse(live.server.public_url.as_deref()?).ok()?;
    (url.scheme() == "https").then(|| url.origin().ascii_serialization())
}

/// The loopback redemption's answer: the code, and where to enter it. There is
/// deliberately no link to follow: a navigation from this loopback page to the
/// public origin is cross-site, which the origin gate refuses.
pub(super) fn code_page(origin: &str, code: &str) -> Response {
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
    private(html(format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Dashboard sign-in</title>\
         <form method=\"post\" action=\"{HANDOFF_PATH}\"><label>Code \
         <input name=\"code\" autocomplete=\"off\" required autofocus></label> \
         <button>Sign in</button></form>"
    )))
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
    body: &[u8],
) -> Response {
    let code = url::form_urlencoded::parse(body)
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.trim().to_string());
    let Some(Redemption { not_after }) =
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
        bootstrap, live, not_after, true,
    ))
}

/// Nothing on these pages may be cached or sent onward as a `Referer`.
pub(crate) fn private(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

fn html(body: String) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
