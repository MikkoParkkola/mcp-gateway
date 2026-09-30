// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The dashboard handoff code (#2130): how a link redeemed at the loopback URL
//! signs a browser in on an HTTPS `public_url` served through a proxy.
//!
//! The loopback redemption shows a one-time code; the operator enters it in a
//! same-origin form on the public origin, which sets the session cookie there.
//! The code never travels in a URL, so no proxy access log, history entry or
//! `Referer` carries it, and no proxy header is trusted to vouch for anything.

use axum::body::Body;
use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use tracing::warn;

use crate::security::security_metrics::{AuthFailureKind, auth_failure};

use super::{AuthState, Now, Redemption, bearer_unauthorized_response};

/// Where the code is entered, on the public origin.
pub(super) const HANDOFF_PATH: &str = "/dashboard/handoff";

/// The code form's body limit: `code=` and a 43-character value, with room to
/// spare, and nothing a client could use to make this path buffer much.
const MAX_FORM_BYTES: usize = 512;

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

/// The code exchange on the public origin, or the request back when this is
/// not one. It runs before the session cookie is judged, so a browser holding
/// a live or a dead cookie still signs in.
pub(super) async fn try_handoff(
    state: &AuthState,
    request: Request<Body>,
) -> Result<Response, Request<Body>> {
    if request.uri().path() != HANDOFF_PATH {
        return Err(request);
    }
    Ok(match *request.method() {
        Method::GET | Method::HEAD => form_page(),
        Method::POST => redeem(state, request.into_body()).await,
        _ => private(StatusCode::METHOD_NOT_ALLOWED.into_response()),
    })
}

/// A form that holds nothing: served to anyone.
fn form_page() -> Response {
    private(html(format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Dashboard sign-in</title>\
         <form method=\"post\" action=\"{HANDOFF_PATH}\"><label>Code \
         <input name=\"code\" autocomplete=\"off\" required autofocus></label> \
         <button>Sign in</button></form>"
    )))
}

/// Spend the posted code for a session. Neither the body nor the code is
/// logged or echoed: the refusal names the outcome only.
async fn redeem(state: &AuthState, body: Body) -> Response {
    let code = axum::body::to_bytes(body, MAX_FORM_BYTES)
        .await
        .ok()
        .and_then(|bytes| {
            url::form_urlencoded::parse(&bytes)
                .find(|(key, _)| key == "code")
                .map(|(_, value)| value.trim().to_string())
        });
    let Some(Redemption { not_after }) =
        code.and_then(|code| state.dashboard_bootstrap.take_handoff(&code, Now::read()))
    else {
        auth_failure(AuthFailureKind::BootstrapRefused);
        warn!("Dashboard handoff refused: wrong, used or expired code");
        return private(bearer_unauthorized_response(
            "The code is wrong, used or expired. Run `mcp-gateway dashboard-link` for a new link.",
        ));
    };
    // Always `Secure`: a code exists only because this origin is HTTPS, and a
    // reload since it was minted must not downgrade the cookie it sets.
    private(super::bootstrap::signed_in(state, not_after, true))
}

/// Nothing on these pages may be cached or sent onward as a `Referer`.
fn private(mut response: Response) -> Response {
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
