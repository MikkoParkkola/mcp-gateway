// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The connect offer on a refused dispatch (MIK-6745 design §9.1-§9.3, BC-1).
//!
//! THREE CALLERS, ALL DISPATCH SITES: the meta `gateway_invoke` route, the
//! capability route and the direct `/mcp/{backend}` route, each only after it
//! has decided to refuse. No catalogue or listing site calls in here, so a
//! backend's presence is never disclosed where the listing withholds it. The
//! shared credential resolver only TYPES the refusal (`Error::AccountRefused`);
//! it never mints, because the catalogue reaches it too.
//!
//! An offer needs predicate B: a principal from the bridged Open `WebUI`
//! adapter and `accounts.hosted` configured. Without it the refusal passes
//! through untouched, so its text and code are exactly today's.

use std::sync::Arc;

use axum::Json;
use axum::http::StatusCode;
use serde_json::{Value, json};

use super::super::super::helpers::build_http_response;
use super::{is_bridged, limits_of, owner_and_descriptor};
use crate::config_reload::LiveConfig;
use crate::error::AccountState;
use crate::gateway::meta_mcp::MetaMcp;
use crate::key_server::oidc::VerifiedIdentity;
use crate::personal_accounts::{JourneyError, JourneyRefusal, JourneyService};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::{Error, Result};

/// What a dispatch site needs to offer: the journey facade and the live config
/// the hosted origin, the bridge and the limits are read from per request.
pub(crate) struct ConnectOffers {
    journeys: Arc<dyn JourneyService>,
    live_config: Arc<LiveConfig>,
}

impl ConnectOffers {
    pub(crate) fn new(journeys: Arc<dyn JourneyService>, live_config: Arc<LiveConfig>) -> Self {
        Self {
            journeys,
            live_config,
        }
    }

    /// The refusal with its offer attached when it is a typed account
    /// refusal that passes predicate B; otherwise the refusal unchanged.
    async fn offer(&self, error: Error, identity: Option<&VerifiedIdentity>) -> Error {
        let text = error.to_string();
        match error {
            Error::AccountRefused {
                message,
                account_id,
                state,
                data: None,
            } => {
                let refusal = Refusal {
                    text: &text,
                    message: &message,
                    account_id: &account_id,
                    state,
                };
                let offered = self.attach(&refusal, identity).await;
                let (message, data) = offered.map_or((message, None), |(m, d)| (m, Some(d)));
                Error::AccountRefused {
                    message,
                    account_id,
                    state,
                    data,
                }
            }
            other => other,
        }
    }

    /// The offered message and data, or `None` when no offer applies.
    async fn attach(
        &self,
        refusal: &Refusal<'_>,
        identity: Option<&VerifiedIdentity>,
    ) -> Option<(String, Value)> {
        let Refusal {
            text,
            message,
            account_id,
            state,
        } = *refusal;
        let config = self.live_config.get();
        let hosted = config.accounts.as_ref()?.hosted.as_ref()?;
        let identity = identity.filter(|identity| is_bridged(&config, identity))?;
        let (owner, descriptor) = owner_and_descriptor(&config, identity, account_id)?;
        // The first allowlisted path: an offer has no caller-chosen return.
        let return_path = hosted.return_paths.first()?.clone();
        let limits = limits_of(&config)?;
        let offered = self.journeys.offer(limits, owner, descriptor, return_path);
        let (message, extra) = match offered.await {
            Ok(Ok(created)) => {
                let url = format!(
                    "{}/accounts/v1/journeys/{}/start",
                    hosted.public_origin, created.journey_id
                );
                let message = format!("{message}; connect your account: {url}");
                (message, json!({"retryable": false, "connect_url": url}))
            }
            Ok(Err(JourneyError::Refused(
                JourneyRefusal::RateLimited { retry_after }
                | JourneyRefusal::CapacityExceeded { retry_after },
            ))) => (
                message.to_owned(),
                json!({"retryable": true, "retry_after": retry_after}),
            ),
            _ => return None,
        };
        Some((message, envelope(text, account_id, state, &extra)))
    }
}

/// A typed refusal as the offer reads it; `text` is its displayed form.
#[derive(Clone, Copy)]
struct Refusal<'a> {
    text: &'a str,
    message: &'a str,
    account_id: &'a str,
    state: AccountState,
}

/// The §9.1 `accounts.v1` data: the refusal, its account, and the offer or
/// the limit that withheld one.
fn envelope(text: &str, account_id: &str, state: AccountState, extra: &Value) -> Value {
    let mut data = json!({"schema_version": "accounts.v1", "account_id": account_id,
        "error": {"code": state.code(), "message": text, "retryable": extra["retryable"]}});
    for key in ["connect_url", "retry_after"] {
        if let Some(value) = extra.get(key) {
            data[key] = value.clone();
        }
    }
    data
}

impl MetaMcp {
    /// Install the offer; before this no dispatch can offer.
    pub(crate) fn install_connect_offers(&self, offers: ConnectOffers) {
        *self.connect_offers.write() = Some(Arc::new(offers));
    }

    fn offers(&self) -> Option<Arc<ConnectOffers>> {
        self.connect_offers.read().clone()
    }

    /// Meta and capability dispatch sites: a typed account refusal gains its
    /// offer (and code `-32001`); anything else is returned unchanged.
    pub(crate) async fn with_connect_offer<T>(
        &self,
        result: Result<T>,
        identity: Option<&VerifiedIdentity>,
    ) -> Result<T> {
        match (result, self.offers()) {
            (Err(error), Some(offers)) => Err(offers.offer(error, identity).await),
            (result, _) => result,
        }
    }

    /// Direct route: its existing `-32003`/403 refusal, carrying the offer
    /// when `refused` is a typed account refusal that earns one.
    pub(crate) async fn direct_refusal(
        &self,
        id: Option<RequestId>,
        text: String,
        refused: Option<Error>,
        identity: Option<&VerifiedIdentity>,
    ) -> (StatusCode, Json<Value>) {
        let offered = match (refused, self.offers()) {
            (Some(error), Some(offers)) => Some(offers.offer(error, identity).await),
            _ => None,
        };
        let shown = offered.as_ref().map(ToString::to_string);
        let rpc = match (offered, shown) {
            (
                Some(Error::AccountRefused {
                    data: Some(data), ..
                }),
                Some(shown),
            ) => JsonRpcResponse::error_with_data(id, -32003, shown, data),
            _ => JsonRpcResponse::error(id, -32003, text),
        };
        build_http_response(&rpc, StatusCode::FORBIDDEN)
    }
}
