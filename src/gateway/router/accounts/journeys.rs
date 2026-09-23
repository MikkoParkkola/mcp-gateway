// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The journey owner API (design §5.3, §6.4): `POST /accounts/v1/journeys`
//! and `GET /accounts/v1/journeys/{id}`. Behind `auth_middleware` and the
//! Open `WebUI` adapter; the principal is only ever the adapter's
//! `VerifiedIdentity`.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};

use super::super::AppState;
use super::envelope::{SCHEMA, refusal};
use crate::config::Config;
use crate::gateway::openwebui_adapter::adapter_issuer;
use crate::key_server::oidc::VerifiedIdentity;
use crate::personal_accounts::identity::Principal;
use crate::personal_accounts::{
    JourneyError, JourneyLimits, JourneyRefusal, JourneyService, JourneyStatus, JourneyView,
};

/// Well above any valid body: both capped fields plus JSON framing.
const BODY_MAX: usize = 4096;
/// Design §10 caps, checked before any store access (T-R2-5).
const ACCOUNT_ID_MAX: usize = 64;
const RETURN_PATH_MAX: usize = 256;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    account_id: String,
    return_path: String,
}

/// L2: the principal must belong to the one adapter with a `session` block,
/// or no bridge could ever authenticate the journey's browser.
pub(super) fn is_bridged(config: &Config, identity: &VerifiedIdentity) -> bool {
    config.accounts.as_ref().is_some_and(|accounts| {
        accounts
            .adapters
            .iter()
            .filter(|adapter| adapter.session.is_some())
            .any(|adapter| identity.issuer == adapter_issuer(&adapter.installation_id))
    })
}

fn limits_of(config: &Config) -> Option<JourneyLimits> {
    config
        .accounts
        .as_ref()
        .map(|a| JourneyLimits::from(&a.limits))
}

pub(super) async fn create(
    journeys: Arc<dyn JourneyService>,
    State(state): State<Arc<AppState>>,
    identity: Option<axum::Extension<VerifiedIdentity>>,
    body: Bytes,
) -> Response {
    let Some(axum::Extension(identity)) = identity else {
        return refusal(StatusCode::UNAUTHORIZED, "unauthenticated", None);
    };
    let config = state.live_config.get();
    if !is_bridged(&config, &identity) {
        return refusal(StatusCode::FORBIDDEN, "forbidden", None);
    }
    let Some((request, hosted_origin)) = admissible(&config, &body) else {
        return refusal(StatusCode::BAD_REQUEST, "invalid_request", None);
    };
    let Some((owner, descriptor)) = owner_and_descriptor(&config, &identity, &request.account_id)
    else {
        return refusal(StatusCode::BAD_REQUEST, "invalid_request", None);
    };
    let Some(limits) = limits_of(&config) else {
        return refusal(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", None);
    };
    match journeys
        .create(limits, owner, descriptor, request.return_path)
        .await
    {
        Ok(Ok(created)) => {
            let start_url = format!(
                "{hosted_origin}/accounts/v1/journeys/{}/start",
                created.journey_id
            );
            let body = json!({"journey_id": created.journey_id, "start_url": start_url,
                              "expires_at": created.expires_at});
            (StatusCode::CREATED, axum::Json(body)).into_response()
        }
        Ok(Err(error)) => journey_refusal(error),
        Err(_) => refusal(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", None),
    }
}

/// Parse and cap the body, and match `return_path` byte-exactly against the
/// configured list. Returns the request and the hosted origin.
fn admissible(config: &Config, body: &Bytes) -> Option<(CreateRequest, String)> {
    if body.len() > BODY_MAX {
        return None;
    }
    let request: CreateRequest = serde_json::from_slice(body).ok()?;
    if request.account_id.len() > ACCOUNT_ID_MAX || request.return_path.len() > RETURN_PATH_MAX {
        return None;
    }
    let hosted = config.accounts.as_ref()?.hosted.as_ref()?;
    hosted
        .return_paths
        .iter()
        .any(|allowed| allowed.as_bytes() == request.return_path.as_bytes())
        .then(|| (request, hosted.public_origin.clone()))
}

/// The caller's own key and the `personal_managed` descriptor it names.
fn owner_and_descriptor(
    config: &Config,
    identity: &VerifiedIdentity,
    account_id: &str,
) -> Option<(
    crate::personal_accounts::AccountKey,
    crate::personal_accounts::config::AccountDescriptor,
)> {
    let descriptor = config
        .accounts
        .as_ref()?
        .descriptors
        .as_ref()?
        .get(account_id)
        .filter(|d| d.mode == crate::personal_accounts::config::DescriptorMode::PersonalManaged)?
        .clone();
    Some((
        super::own_key(config, identity, account_id).ok()?,
        descriptor,
    ))
}

pub(super) async fn status(
    journeys: Arc<dyn JourneyService>,
    State(state): State<Arc<AppState>>,
    identity: Option<axum::Extension<VerifiedIdentity>>,
    Path(id): Path<String>,
) -> Response {
    let Some(axum::Extension(identity)) = identity else {
        return refusal(StatusCode::UNAUTHORIZED, "unauthenticated", None);
    };
    let Some(limits) = limits_of(&state.live_config.get()) else {
        return refusal(StatusCode::NOT_FOUND, "not_found", None);
    };
    let (authority, subject) = Principal::Verified(&identity).authority_subject();
    let principal = (authority.to_owned(), subject.to_owned());
    match journeys.status(limits, id, principal).await {
        Ok(Ok(view)) => (StatusCode::OK, axum::Json(status_body(&view))).into_response(),
        Ok(Err(error)) => journey_refusal(error),
        Err(_) => refusal(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", None),
    }
}

/// The status JSON. Never carries a token, digest or account id; a superseded
/// journey is reported as expired, reason superseded (§3).
pub(super) fn status_body(view: &JourneyView) -> Value {
    let status = match view.status {
        JourneyStatus::Superseded => JourneyStatus::Expired,
        other => other,
    };
    json!({"schema_version": SCHEMA, "status": status, "reason": view.reason,
           "expires_at": view.expires_at, "replay_refused": view.replay_refused,
           "replay_refusals": view.replay_refusals})
}

fn journey_refusal(error: JourneyError) -> Response {
    let refusal_of = |status, code| refusal(status, code, None);
    match error {
        JourneyError::Refused(JourneyRefusal::InvalidRequest) => {
            refusal_of(StatusCode::BAD_REQUEST, "invalid_request")
        }
        JourneyError::Refused(JourneyRefusal::RateLimited { retry_after }) => refusal(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            Some(retry_after),
        ),
        JourneyError::Refused(JourneyRefusal::CapacityExceeded { retry_after }) => refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "capacity_exceeded",
            Some(retry_after),
        ),
        JourneyError::Refused(_) => refusal_of(StatusCode::NOT_FOUND, "not_found"),
        JourneyError::Storage(_) => {
            refusal_of(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable")
        }
    }
}

#[path = "offer.rs"]
mod offer;
pub(crate) use offer::ConnectOffers;

#[cfg(test)]
#[path = "journeys_tests.rs"]
mod journeys_tests;
