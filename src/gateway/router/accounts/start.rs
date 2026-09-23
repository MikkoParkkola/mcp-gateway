// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /accounts/v1/journeys/{id}/start` (design §4.2): the journey owner's
//! own Open `WebUI` session, and nothing else, starts the provider flow.
//!
//! Unauthenticated by the main chain on purpose: an API key or a tool-call
//! assertion riding along names no principal here.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};

use super::super::AppState;
use super::bridge::{OwuiSessionBridge, Session};
use crate::config::Config;
use crate::personal_accounts::{
    JourneyError, JourneyLimits, JourneyRefusal, JourneyService, JourneyStarted,
};

pub(super) const START: &str = "/accounts/v1/journeys/{id}/start";

/// The gateway's own pages. Constant text only, so nothing needs escaping and
/// nothing a request carries is ever rendered.
#[derive(Clone, Copy)]
enum Page {
    /// Every bridge refusal, identical, so no page says which step failed.
    SignIn,
    Expired,
    Retry(u64),
    Unavailable,
}

impl IntoResponse for Page {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::SignIn => (
                StatusCode::FORBIDDEN,
                "Sign in to Open WebUI in this browser, then retry.",
            ),
            Self::Expired => (
                StatusCode::NOT_FOUND,
                "This link has expired or is not valid. Start again from Open WebUI.",
            ),
            Self::Retry(_) => (
                StatusCode::TOO_MANY_REQUESTS,
                "Too many attempts. Wait a minute, then retry.",
            ),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "The account service is unavailable. Try again later.",
            ),
        };
        let body = format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
             <title>Connect account</title></head><body><p>{message}</p></body></html>"
        );
        let mut response = (status, Html(body)).into_response();
        if let Self::Retry(seconds) = self {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(seconds));
        }
        response
    }
}

fn page_for(error: JourneyError) -> Page {
    match error {
        JourneyError::Refused(JourneyRefusal::OwnerMismatch) => Page::SignIn,
        JourneyError::Refused(JourneyRefusal::RateLimited { retry_after }) => {
            Page::Retry(retry_after)
        }
        JourneyError::Refused(_) => Page::Expired,
        JourneyError::Storage(_) => Page::Unavailable,
    }
}

/// The one adapter with a `session` block (config admits at most one, §4.2
/// step 1 L3) and the journey limits.
fn bridged(config: &Config) -> Option<(Session, JourneyLimits)> {
    let limits = JourneyLimits::from(&config.accounts.as_ref()?.limits);
    Some((super::bridge::session_of(config)?, limits))
}

pub(super) async fn start(
    journeys: Arc<dyn JourneyService>,
    bridge: Arc<OwuiSessionBridge>,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let config = state.live_config.get();
    let Some((session, limits)) = bridged(&config) else {
        return Page::Expired.into_response();
    };
    let account = match journeys.account_of(limits, id.clone()).await {
        Ok(Ok(account)) => account,
        Ok(Err(error)) => return page_for(error).into_response(),
        Err(_) => return Page::Unavailable.into_response(),
    };
    let Some(identity) = bridge.identity(&session, &headers).await else {
        return Page::SignIn.into_response();
    };
    let Some(owner) = super::own_key(&config, &identity, &account) else {
        return Page::Expired.into_response();
    };
    match journeys.start(limits, id.clone(), owner).await {
        Ok(Ok(started)) => redirect(&id, &started),
        Ok(Err(error)) => page_for(error).into_response(),
        Err(_) => Page::Unavailable.into_response(),
    }
}

/// 303 to the provider, with the binding in the journey's own cookie.
fn redirect(id: &str, started: &JourneyStarted) -> Response {
    let cookie = super::callback::binding_cookie(id, &started.binding, started.max_age);
    let (Ok(cookie), Ok(location)) = (
        HeaderValue::from_str(&cookie),
        HeaderValue::from_str(started.authorize_url.as_str()),
    ) else {
        return Page::Unavailable.into_response();
    };
    let mut response = StatusCode::SEE_OTHER.into_response();
    let headers = response.headers_mut();
    headers.insert(header::LOCATION, location);
    headers.insert(header::SET_COOKIE, cookie);
    response
}
