// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One refresh at a time per stored OAuth credential, process-wide (MIK-8018).
//!
//! Every client that holds a credential (a pooled transport, one a restart
//! replaced but a call still holds, a config-reload generation, the MCP
//! capability path's own backend) refreshes through the [`Flight`] of that
//! credential's token file. Keyed by the file, not by a backend object, so two
//! generations of one backend share it.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use sha2::{Digest, Sha256};
use tracing::warn;

use super::TokenResponse;
use super::destination::{Hop, hop};
use crate::Error;
use crate::oauth::storage::{RefreshState, TokenInfo, TokenStorage};
use crate::security::http_diagnostics::oauth_request_error;
use crate::security::ssrf::{DestinationPolicy, is_ssrf_refusal};
use crate::security::{safe_oauth_http_error, safe_reqwest_message};

/// The refresh coordination of one stored credential.
#[derive(Default)]
pub(super) struct Flight {
    /// Held for a whole exchange, from the stored-token re-read to the save.
    pub(super) lock: Arc<tokio::sync::Mutex<()>>,
    /// Hashes of refresh tokens that may have been consumed by an exchange
    /// with an unknown outcome; never sent again by this process, even when
    /// clearing them from storage failed.
    spent: parking_lot::Mutex<HashSet<[u8; 32]>>,
}

/// Every credential's flight. Entries are kept for the life of the process:
/// dropping one would drop its spent set (bounded by the credentials a process
/// ever refreshes).
static FLIGHTS: LazyLock<parking_lot::Mutex<HashMap<PathBuf, Arc<Flight>>>> =
    LazyLock::new(parking_lot::Mutex::default);

impl Flight {
    /// The flight of the credential stored at `token_path`.
    pub(super) fn of(token_path: &Path) -> Arc<Self> {
        Arc::clone(FLIGHTS.lock().entry(token_path.to_path_buf()).or_default())
    }

    pub(super) fn spend(&self, refresh_token: &str) {
        self.spent.lock().insert(fingerprint(refresh_token));
    }

    pub(super) fn is_spent(&self, refresh_token: &str) -> bool {
        self.spent.lock().contains(&fingerprint(refresh_token))
    }
}

/// SHA-256 of a refresh token: what the spent set and the persisted in-flight
/// marker hold, so neither keeps the secret itself.
pub(super) fn fingerprint(refresh_token: &str) -> [u8; 32] {
    Sha256::digest(refresh_token.as_bytes()).into()
}

/// [`fingerprint`] as lowercase hex, for the persisted marker.
pub(super) fn fingerprint_hex(refresh_token: &str) -> String {
    hex::encode(fingerprint(refresh_token))
}

/// What one refresh exchange settled to.
pub(super) enum Outcome {
    /// The server answered with a token, and it is saved.
    Refreshed(TokenInfo),
    /// The server refused with an OAuth error: the token was not consumed.
    Rejected {
        status: reqwest::StatusCode,
        body: String,
    },
    /// Nothing reached the server: a connect error with redirects off, or a
    /// destination-policy refusal before sending.
    NotSent(Error),
    /// The request may have reached the server and its answer is unknown.
    Uncertain(Error),
}

/// One refresh exchange, run detached so a dropped caller cannot cut it short
/// between the server rotating the token and the save (the connect path's
/// detached OAuth task is the precedent, MIK-4486).
pub(super) struct Exchange {
    /// The flight's guard: released only when the exchange has settled and
    /// its result is saved, so the next waiter re-reads what this one wrote.
    pub(super) guard: tokio::sync::OwnedMutexGuard<()>,
    pub(super) flight: Arc<Flight>,
    pub(super) http: reqwest::Client,
    pub(super) endpoint: String,
    pub(super) params: Vec<(&'static str, String)>,
    pub(super) sent: String,
    pub(super) storage: Arc<TokenStorage>,
    pub(super) key: String,
    pub(super) resource_url: String,
    pub(super) backend: String,
    pub(super) state: RefreshState,
    pub(super) destination: DestinationPolicy,
}

impl Exchange {
    pub(super) fn spawn(self) -> tokio::task::JoinHandle<Outcome> {
        tokio::spawn(self.run())
    }

    async fn run(mut self) -> Outcome {
        let outcome = self.send().await;
        // The marker stays when a possibly consumed token could not be retired
        // from storage: a later refresh, even after a restart, retires it then.
        let retired =
            !(matches!(outcome, Outcome::Uncertain(_)) && self.state.rotates) || self.spend();
        if retired {
            self.state.in_flight = None;
        }
        if let Err(error) =
            self.storage
                .save_refresh_state(&self.key, &self.resource_url, &self.state)
        {
            warn!(backend = %self.backend, %error, "Could not settle the refresh state");
        }
        drop(self.guard);
        outcome
    }

    async fn send(&mut self) -> Outcome {
        let response = match self
            .http
            .post(&self.endpoint)
            .form(&self.params)
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                let mapped = oauth_request_error("Token refresh failed", &error);
                return if error.is_connect() || is_ssrf_refusal(&mapped) {
                    Outcome::NotSent(mapped)
                } else {
                    Outcome::Uncertain(mapped)
                };
            }
        };
        let status = response.status();
        if status.is_redirection() {
            return Outcome::Uncertain(self.redirect_error(&response));
        }
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            if status.is_client_error() && names_an_oauth_error(&body) {
                return Outcome::Rejected { status, body };
            }
            let message = safe_oauth_http_error("Token refresh failed", status, &body);
            return Outcome::Uncertain(Error::OAuth(message));
        }
        let answer: TokenResponse = match response.json().await {
            Ok(answer) => answer,
            Err(error) => {
                let message = safe_reqwest_message("Failed to parse refresh response", &error);
                return Outcome::Uncertain(Error::OAuth(message));
            }
        };
        if answer
            .refresh_token
            .as_deref()
            .is_some_and(|issued| issued != self.sent)
        {
            // Persisted before the rotated token is saved: a stop in between
            // must not forget that this server rotates. Unrecorded, the sent
            // token is treated as possibly consumed rather than kept.
            self.state.rotates = true;
            if let Err(error) =
                self.storage
                    .save_refresh_state(&self.key, &self.resource_url, &self.state)
            {
                warn!(backend = %self.backend, %error, "Could not record that the server rotates");
                return Outcome::Uncertain(error);
            }
        }
        let token = TokenInfo::from_response(
            answer.access_token,
            answer.token_type,
            // No new refresh token means keep the one sent (RFC 6749 section 6).
            answer.refresh_token.or_else(|| Some(self.sent.clone())),
            answer.expires_in,
            answer.scope,
        );
        match self.storage.save(&self.key, &self.resource_url, &token) {
            Ok(()) => Outcome::Refreshed(token),
            Err(error) => {
                warn!(backend = %self.backend, %error, "Could not save a refreshed token");
                Outcome::Uncertain(error)
            }
        }
    }

    /// A redirect is never followed. A target the destination policy refuses
    /// stays `-32600 SSRF blocked` (MIK-7701), so no caller walks past it.
    fn redirect_error(&self, response: &reqwest::Response) -> Error {
        let target = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|location| location.to_str().ok())
            .and_then(|location| url::Url::parse(&self.endpoint).ok()?.join(location).ok());
        if let Some(target) = target
            && let Hop::Refuse(reason) = hop(self.destination, 0, &target)
        {
            return Error::Protocol(reason);
        }
        Error::OAuth(format!(
            "Token refresh failed: the token endpoint answered HTTP {}; redirects are not followed",
            response.status().as_u16()
        ))
    }

    /// The sent refresh token may be consumed: see [`spend`].
    fn spend(&self) -> bool {
        spend(
            &self.flight,
            &self.storage,
            (&self.key, &self.resource_url),
            &self.backend,
            &self.sent,
        )
    }
}

/// `sent` may be consumed: no client of this process sends it again, and it is
/// cleared from the stored record at `at` (credential key, resource URL) unless
/// a login stored a fresh one meanwhile (compare-and-clear). Whether storage no
/// longer holds `sent` afterwards: `false` only when clearing it failed.
pub(super) fn spend(
    flight: &Flight,
    storage: &TokenStorage,
    at: (&str, &str),
    backend: &str,
    sent: &str,
) -> bool {
    let (key, resource_url) = at;
    flight.spend(sent);
    warn!(backend = %backend, "A refresh with an unknown outcome spent its refresh token");
    let Some(mut stored) = storage.load(key, resource_url) else {
        return true;
    };
    if stored.refresh_token.as_deref() != Some(sent) {
        return true;
    }
    stored.refresh_token = None;
    if let Err(error) = storage.save(key, resource_url, &stored) {
        tracing::error!(backend = %backend, %error, "Could not clear a spent refresh token");
        return false;
    }
    true
}

/// Whether `body` is an RFC 6749 error response (an `error` string field).
fn names_an_oauth_error(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("error")?.as_str().map(str::to_owned))
        .is_some()
}
