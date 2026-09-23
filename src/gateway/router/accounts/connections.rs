// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `DELETE /accounts/v1/connections/{account_id}` (design §6.4, §8.3): one
//! route outside `authenticate`, dispatched by the ONE credential presented.
//! An API credential is forwarded into the authenticated half unchanged; a
//! browser session is verified through the bridge; both at once is refused.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, delete};
use tower::ServiceExt;

use super::super::AppState;
use super::bridge::{OwuiSessionBridge, presents_session, session_of};
use super::envelope::refusal;
use crate::config::Config;
use crate::key_server::oidc::VerifiedIdentity;
use crate::personal_accounts::AccountRevocation;

/// The account id the dispatcher already extracted. Forwarded as an
/// extension because a re-matched route would append a second path param.
#[derive(Clone)]
struct Forwarded(String);

/// The API half, for the caller to wrap in `authenticate`; the principal is
/// only the adapter's `VerifiedIdentity`, never a bare API key.
pub(super) fn api_route(revocation: Arc<dyn AccountRevocation>) -> Router<Arc<AppState>> {
    let handler = move |State(state): State<Arc<AppState>>, request: Request| async move {
        let extensions = request.extensions();
        let (Some(identity), Some(Forwarded(account_id))) = (
            extensions.get::<VerifiedIdentity>().cloned(),
            extensions.get::<Forwarded>().cloned(),
        ) else {
            return refusal(StatusCode::UNAUTHORIZED, "unauthenticated", None);
        };
        super::revoke_for(&state, &*revocation, &identity, account_id).await
    };
    Router::new().route(super::ROUTE, delete(handler))
}

/// The mounted route. `api` is [`api_route`] already wrapped in the auth layers.
pub(super) fn route(
    api: Router<Arc<AppState>>,
    revocation: Arc<dyn AccountRevocation>,
    bridge: Option<Arc<OwuiSessionBridge>>,
) -> MethodRouter<Arc<AppState>> {
    delete(
        move |State(state): State<Arc<AppState>>,
              Path(account_id): Path<String>,
              request: Request| {
            let (api, revocation, bridge) = (api.clone(), Arc::clone(&revocation), bridge.clone());
            async move {
                let caller = Caller {
                    state,
                    revocation,
                    account_id,
                };
                dispatch(caller, api, bridge, request).await
            }
        },
    )
}

struct Caller {
    state: Arc<AppState>,
    revocation: Arc<dyn AccountRevocation>,
    account_id: String,
}

async fn dispatch(
    caller: Caller,
    api: Router<Arc<AppState>>,
    bridge: Option<Arc<OwuiSessionBridge>>,
    request: Request,
) -> Response {
    let config = caller.state.live_config.get();
    let session = session_of(&config);
    let headers = request.headers();
    let api_credential = headers.contains_key(header::AUTHORIZATION);
    let browser = session
        .as_ref()
        .is_some_and(|session| presents_session(session, headers));
    match (api_credential, browser, session, bridge) {
        (true, true, ..) => refusal(StatusCode::FORBIDDEN, "forbidden", None),
        (true, false, ..) => {
            let mut request = request;
            request
                .extensions_mut()
                .insert(Forwarded(caller.account_id));
            match api.with_state(caller.state).oneshot(request).await {
                Ok(response) => response.into_response(),
                Err(never) => match never {},
            }
        }
        (false, true, Some(session), Some(bridge)) => {
            if !same_origin_fetch(&config, headers) {
                return refusal(StatusCode::FORBIDDEN, "forbidden", None);
            }
            let Some(identity) = bridge.identity(&session, headers).await else {
                return refusal(StatusCode::UNAUTHORIZED, "unauthenticated", None);
            };
            let Caller {
                state,
                revocation,
                account_id,
            } = caller;
            super::revoke_for(&state, &*revocation, &identity, account_id).await
        }
        (false, true, ..) => refusal(StatusCode::SERVICE_UNAVAILABLE, "unavailable", None),
        (false, false, ..) => refusal(StatusCode::UNAUTHORIZED, "unauthenticated", None),
    }
}

/// §8.3 / §9.5 CSRF defence, checked before the cookie leaves the gateway:
/// `Origin` present and equal to `public_origin`, and the browser's own
/// `Sec-Fetch-*` report of a same-origin `fetch` (no CORS allowance exists).
fn same_origin_fetch(config: &Config, headers: &HeaderMap) -> bool {
    let origin_of = |value: &str| url::Url::parse(value).ok().map(|url| url.origin());
    let hosted = config
        .accounts
        .as_ref()
        .and_then(|accounts| accounts.hosted.as_ref())
        .and_then(|hosted| origin_of(&hosted.public_origin));
    let sent = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .and_then(origin_of);
    let is = |name: &str, want: &str| headers.get(name).is_some_and(|value| value == want);
    hosted.is_some()
        && sent == hosted
        && is("sec-fetch-site", "same-origin")
        && is("sec-fetch-mode", "cors")
}
