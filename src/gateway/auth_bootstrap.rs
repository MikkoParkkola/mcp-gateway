// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The dashboard bootstrap link exchange: the one place a credential arrives
//! in a URL. Its own file so `auth.rs` stays at its line baseline.

use axum::body::Body;
use axum::http::Request;
use axum::response::Response;
use tracing::warn;

use crate::security::security_metrics::{AuthFailureKind, auth_failure};

use super::{
    AuthState, DashboardBootstrap, Now, Redeem, Redemption, ResolvedAuthConfig, SessionLimits,
    bearer_unauthorized_response, cookie_secure, session_cookie,
};

/// Exchange a dashboard bootstrap link for a session, if this is one.
///
/// Split out of the middleware so the credential path stays readable; a
/// browser navigation is the one place a value arrives in the URL, and that is
/// worth being able to see in one screen.
pub(super) fn try_dashboard_bootstrap(
    state: &AuthState,
    auth_config: &ResolvedAuthConfig,
    request: &Request<Body>,
) -> Option<Response> {
    if request.uri().path() != "/dashboard" {
        return None;
    }
    let candidate = request.uri().query().and_then(bootstrap_param)?;
    {
        // Redeemable only from this machine, whatever the origin gate admits.
        //
        // The value is printed to the operator's own terminal on the assumption
        // that seeing it means being at the machine. That assumption breaks the
        // moment a `public_url` is declared: the origin gate then admits that
        // hostname by design, so anyone who obtains the printed value — shipped
        // logs, shared scrollback, a screenshot — can exchange it for an admin
        // session from anywhere. Printing is already gated on a loopback bind;
        // the exchange was not, which left the weaker half deciding.
        //
        // Read from the CONNECTION, not from the request. `Host` is written by
        // the caller and rewritten by proxies — nginx's default for a bare
        // `proxy_pass` is the upstream address — so a forwarded request could
        // present a loopback `Host` and redeem a leaked link from anywhere
        // (MIK-7257). The peer address is the socket the kernel accepted and
        // nobody upstream can dictate it.
        //
        // Absent connect info is treated as NOT local. Both serve paths install
        // it (`server::mod`, `support::serve_tls`); a request without it came
        // from somewhere unaccounted for, and the safe reading of "unaccounted
        // for" is "not at this machine".
        let peer_is_local = request
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .is_some_and(|info| info.0.ip().is_loopback());

        // A loopback peer is not conclusive on its own: a reverse proxy running
        // on THIS machine also connects from loopback. Such a proxy announces
        // itself — every convention-following one sets a forwarding header, and
        // this project's own nginx example sets `X-Forwarded-For`. Refusing
        // when one is present closes the same-host case for any proxy that
        // follows the convention.
        //
        // Stated honestly: a proxy that strips these headers defeats it. That
        // is a narrower residual than trusting `Host`, not an empty one.
        let looks_forwarded = ["x-forwarded-for", "forwarded", "x-forwarded-host"]
            .iter()
            .any(|h| request.headers().contains_key(*h));

        if !peer_is_local || looks_forwarded {
            // Spent when it matches (#1529): the link lives in a URL, so a
            // copy may survive in a history, proxy log or `Referer`; a copy
            // presented from elsewhere must die on first use. A wrong value
            // spends nothing.
            let spent = state.dashboard_bootstrap.consume(&candidate);
            auth_failure(AuthFailureKind::BootstrapRefused);
            warn!(
                peer_is_local,
                looks_forwarded,
                spent,
                "Dashboard bootstrap refused: redeemable only from this machine"
            );
            // One answer whether or not it was spent: saying "used up" only
            // for the live value told a caller from elsewhere that they had
            // guessed it. The operator sees `spent` in the log above.
            return Some(bearer_unauthorized_response(
                "The dashboard link works only from the machine running the gateway. If this \
                 was the live link, it is now used up: run `mcp-gateway dashboard-link` for a \
                 fresh one.",
            ));
        }

        // Checked BEFORE the value is spent. The bootstrap is one-time, so
        // consuming it and then discovering there is no credential to exchange
        // it for leaves the operator holding a dead link with no way to retry
        // short of restarting the gateway — and nothing tells them that. An
        // install configured with API keys but no bearer hits exactly this.
        //
        // An admin API key counts. The exchange hands back an opaque session
        // handle and never touches the credential itself, so a bearer is not
        // mechanically required — demanding one refused every API-key-only
        // operator over a token the exchange would not have used. A RESTRICTED
        // key does not count: the session it opens carries admin.
        let has_admin_credential =
            auth_config.bearer_token.is_some() || auth_config.api_keys().iter().any(|k| k.admin);
        if !has_admin_credential {
            auth_failure(AuthFailureKind::BootstrapRefused);
            warn!("Dashboard bootstrap unusable: no admin credential is configured");
            return Some(bearer_unauthorized_response(
                "No admin credential is configured. Set auth.bearer_token or an admin \
                 API key, or run `mcp-gateway init` to generate one, then restart for \
                 a fresh link.",
            ));
        }
        // Checked BEFORE the value is spent, like the admin-credential check:
        // an HTTPS `public_url` added by reload makes the session cookie
        // `Secure`, and a browser on this plain-HTTP listener would drop it,
        // wasting the only link. One reading, used for both this check and the
        // cookie below, so a reload in between cannot split them.
        //
        // Decided from configuration alone, never by comparing the value: with
        // the dashboard built, the live value is handed off (the one success
        // here); every other outcome, the live value included when the hand-off
        // cannot happen, gets exactly the wrong-value refusal and spends
        // nothing. So no caller learns whether they hold the live value, and
        // only the operator learns about the deployment, from this log line and
        // from `mcp-gateway dashboard-link`.
        let secure = cookie_secure(state);
        if secure && !state.tls_enabled {
            // The clock first, before any hand-off spends or compares: on a
            // clock before 1970 every value gets the clock refusal, and the
            // live link is kept, as on the direct path below.
            if super::dashboard::wall_unreadable(Now::read()) {
                auth_failure(AuthFailureKind::BootstrapRefused);
                return Some(clock_refusal());
            }
            // A cookie set here would be scoped to this loopback host. Hand off
            // to the public origin instead (#2130): the page shows a one-time
            // code the operator enters there, in a same-origin form, so the
            // code never travels in a URL and no proxy header is trusted. Only
            // a build with the dashboard serves the page the code is entered on.
            #[cfg(feature = "webui")]
            if let super::handoff::Handoff::Shown(page) =
                super::handoff::hand_off(state, auth_config, &candidate)
            {
                return Some(page);
            }
            auth_failure(AuthFailureKind::BootstrapRefused);
            warn!(
                "Dashboard bootstrap refused: server.public_url is HTTPS but this listener is \
                 plain HTTP, so the session cookie would be discarded; enable mtls or remove \
                 public_url"
            );
            return Some(refused_sign_in(
                Navigation::of(request.headers()),
                refused_value(),
            ));
        }
        let Redemption { bound, now } = match state
            .dashboard_bootstrap
            .consume_capped(&candidate, auth_config)
        {
            Redeem::Issued(redemption) => redemption,
            // Refused but kept: the clock reads before 1970 (MIK-8202). Said
            // to every candidate, decided before any compare, so it does not
            // tell the live value from a guess.
            Redeem::ClockUnreadable => {
                auth_failure(AuthFailureKind::BootstrapRefused);
                return Some(clock_refusal());
            }
            Redeem::Refused => {
                auth_failure(AuthFailureKind::BootstrapRefused);
                warn!("Dashboard bootstrap rejected: wrong or already-used value");
                return Some(refused_sign_in(
                    Navigation::of(request.headers()),
                    refused_value(),
                ));
            }
        };
        // Hand the browser an opaque session in an HttpOnly cookie and redirect.
        // Done here rather than in the handler so the token never leaves this
        // module, and so the address bar keeps nothing after the redirect.
        Some(signed_in(
            &state.dashboard_bootstrap,
            &state.live_config,
            bound,
            now,
            secure,
        ))
    }
}

/// How a request arrived: a top-level browser navigation, or anything else.
/// Browsers send both headers on a navigation and a form POST to the
/// potentially trustworthy origins sign-in runs on, and script cannot set them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Navigation {
    /// `Sec-Fetch-Mode: navigate` and `Sec-Fetch-Dest: document`, exactly.
    Document,
    /// No Fetch Metadata, or any other value: keeps today's answers.
    Other,
}

impl Navigation {
    pub(crate) fn of(headers: &axum::http::HeaderMap) -> Self {
        let is = |name: &str, want: &str| headers.get(name).is_some_and(|v| v == want);
        if is("sec-fetch-mode", "navigate") && is("sec-fetch-dest", "document") {
            Self::Document
        } else {
            Self::Other
        }
    }
}

/// Where a refused browser is sent: one fixed shell address and hint word.
/// Nothing in the request feeds it, so it cannot be turned into a redirect
/// elsewhere, and it reads the same whichever value was refused.
#[cfg(feature = "webui")]
const REFUSED_SIGN_IN_TARGET: &str = "/ui/overview/status?signin=link-refused";

/// A refused link or code: a browser navigation goes back to the shell,
/// which says so in plain words; anything else gets `refusal` unchanged.
/// Without the dashboard there is no shell, so every caller gets `refusal`.
pub(crate) fn refused_sign_in(navigation: Navigation, refusal: Response) -> Response {
    #[cfg(feature = "webui")]
    if navigation == Navigation::Document {
        return super::handoff::private(axum::response::IntoResponse::into_response((
            axum::http::StatusCode::SEE_OTHER,
            [(axum::http::header::LOCATION, REFUSED_SIGN_IN_TARGET)],
        )));
    }
    #[cfg(not(feature = "webui"))]
    let _ = navigation;
    refusal
}

/// The refusal of a value that is not the live one, and of every value where
/// telling them apart would leak which is live: one response, built in one
/// place, so the paths that share it cannot drift apart.
fn clock_refusal() -> Response {
    bearer_unauthorized_response(
        "The host clock reads before 1970, so a sign-in cannot be dated. Set the clock; a \
         live link is kept and works afterwards.",
    )
}

/// The refusal of a value that is not the live one: see [`refused_sign_in`].
fn refused_value() -> Response {
    bearer_unauthorized_response(
        "Bootstrap link is invalid or already used. Run `mcp-gateway dashboard-link` for a \
         fresh one.",
    )
}

/// A fresh session for a redeemed link or handoff code: an opaque handle in a
/// cookie and a 303 to `/dashboard`. The session ends at `bound`'s cap, the
/// minting credential's expiry, when that comes before the absolute limit,
/// and with its minting key.
pub(super) fn signed_in(
    bootstrap: &DashboardBootstrap,
    live: &crate::config_reload::LiveConfig,
    bound: super::Bound,
    now: Now,
    secure: bool,
) -> Response {
    let not_after = bound.not_after;
    let limits = SessionLimits::from(&live.get().auth.dashboard_session);
    let handle = bootstrap.issue_session_until(now, &limits, bound);
    // The cookie lives exactly as long as the server will honour it, so a
    // browser never keeps presenting a handle the server already dropped:
    // the absolute limit, or less when the minting credential expires first.
    let max_age = not_after
        .map(|cap| cap.duration_since(now.wall).unwrap_or_default())
        .map_or(limits.absolute, |left| left.min(limits.absolute))
        .as_secs();
    axum::response::IntoResponse::into_response((
        axum::http::StatusCode::SEE_OTHER,
        [
            (axum::http::header::LOCATION, "/dashboard".to_string()),
            (
                axum::http::header::SET_COOKIE,
                session_cookie(&handle, max_age, secure),
            ),
        ],
    ))
}

/// The `bootstrap` query parameter, if present.
pub(super) fn bootstrap_param(query: &str) -> Option<String> {
    query
        .split('&')
        .filter_map(|p| p.split_once('='))
        .find(|(k, _)| *k == "bootstrap")
        .map(|(_, v)| v.to_string())
}
