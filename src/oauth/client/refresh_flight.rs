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
use super::destination::{Hop, RefreshRoute, hop};
use crate::Error;
use crate::fs_lock::ExclusiveFileLock;
use crate::oauth::storage::{RefreshState, TokenInfo, TokenStorage};
use crate::security::http_diagnostics::oauth_request_error;
use crate::security::ssrf::{
    DestinationPolicy, PinningResolver, SystemResolver, is_ssrf_refusal, ssrf_denial,
};
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
    /// A test's pause point in an exchange, after the answer is parsed and
    /// before the token is saved, with the flight still held.
    #[cfg(test)]
    pub(super) save_gate: parking_lot::Mutex<Option<Arc<SaveGate>>>,
}

/// Holds an exchange before its save: it signals `reached` and waits for
/// `release`.
#[cfg(test)]
#[derive(Default)]
pub(super) struct SaveGate {
    pub(super) reached: tokio::sync::Notify,
    pub(super) release: tokio::sync::Notify,
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

/// Hold the credential at `token_path` against other gateway processes that
/// share the storage directory, as [`Flight::lock`] holds it within this one:
/// an `flock` on a sidecar, released by the OS if the process dies. Taken
/// after the in-process lock, so one waiter per process blocks here.
pub(super) async fn hold_across_processes(token_path: &Path) -> crate::Result<ExclusiveFileLock> {
    let lock_path = token_path.with_extension("refresh.lock");
    tokio::task::spawn_blocking(move || ExclusiveFileLock::acquire(&lock_path))
        .await
        .map_err(|e| Error::OAuth(format!("The refresh lock task failed: {e}")))?
        .map_err(|e| Error::OAuth(format!("Could not take the refresh lock: {e}")))
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
    /// The server refused with an OAuth error: the token was not consumed,
    /// unless a supplied client followed a redirect to the refusal.
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
    pub(super) route: RefreshRoute,
    /// The flight's other half: other gateway processes sharing the storage
    /// directory wait on it too.
    pub(super) across: ExclusiveFileLock,
}

impl Exchange {
    pub(super) fn spawn(self) -> tokio::task::JoinHandle<Outcome> {
        tokio::spawn(self.run())
    }

    async fn run(mut self) -> Outcome {
        let outcome = self.send().await;
        // The marker stays when a possibly consumed token could not be retired
        // from storage: a later refresh, even after a restart, retires it then.
        // A supplied client may follow a redirect, so even an OAuth refusal
        // can come from a hop after the server consumed the token.
        let possibly_consumed = match outcome {
            Outcome::Uncertain(_) => true,
            Outcome::Rejected { .. } => self.route == RefreshRoute::Supplied,
            Outcome::Refreshed(_) | Outcome::NotSent(_) => false,
        };
        let retired = !(possibly_consumed && self.state.rotates) || self.spend();
        if retired {
            self.state.in_flight = None;
        }
        if let Err(error) =
            self.storage
                .save_refresh_state(&self.key, &self.resource_url, &self.state)
        {
            warn!(backend = %self.backend, %error, "Could not settle the refresh state");
        }
        drop(self.across);
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
                // Only a client that follows no redirect proves nothing was sent:
                // through a followed hop the server may already have the token.
                let unsent = error.is_connect() || is_ssrf_refusal(&mapped);
                return if unsent && self.route == RefreshRoute::Owned {
                    Outcome::NotSent(mapped)
                } else {
                    Outcome::Uncertain(mapped)
                };
            }
        };
        let status = response.status();
        if status.is_redirection() {
            let target = self.redirect_target(&response);
            return Outcome::Uncertain(self.redirect_error(status.as_u16(), target).await);
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
        #[cfg(test)]
        {
            let gate = self.flight.save_gate.lock().clone();
            if let Some(gate) = gate {
                gate.reached.notify_one();
                gate.release.notified().await;
            }
        }
        match self.storage.save(&self.key, &self.resource_url, &token) {
            Ok(()) => Outcome::Refreshed(token),
            Err(error) => {
                warn!(backend = %self.backend, %error, "Could not save a refreshed token");
                Outcome::Uncertain(error)
            }
        }
    }

    /// A redirect is never followed. A target the destination policy refuses,
    /// by its literal or by what its name resolves to, stays
    /// `-32600 SSRF blocked` (MIK-7701), so no caller walks past it into a
    /// login.
    async fn redirect_error(&self, status: u16, target: Option<url::Url>) -> Error {
        if let Some(target) = target
            && let Some(reason) = refused_target(self.destination, &target).await
        {
            return Error::Protocol(reason);
        }
        Error::OAuth(format!(
            "Token refresh failed: the token endpoint answered HTTP {status}; redirects are not followed"
        ))
    }

    /// The redirect's `Location`, resolved against the token endpoint.
    fn redirect_target(&self, response: &reqwest::Response) -> Option<url::Url> {
        response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|location| location.to_str().ok())
            .and_then(|location| url::Url::parse(&self.endpoint).ok()?.join(location).ok())
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
        // Absent is retired. A record that exists but cannot be read may
        // still hold `sent`: not retired, so the marker stays. So does a path
        // whose existence cannot be checked.
        return matches!(
            storage.token_path(key, resource_url).try_exists(),
            Ok(false)
        );
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

/// How long a redirect target's name may take to resolve.
const REDIRECT_LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Why `destination` refuses a redirect to `target`, if it does: a literal
/// through [`hop`], a name through the pinning resolver a followed hop would
/// have met. A name that does not resolve is not a refusal: nothing was sent.
pub(super) async fn refused_target(
    destination: DestinationPolicy,
    target: &url::Url,
) -> Option<String> {
    if let Hop::Refuse(reason) = hop(destination, 0, target) {
        return Some(reason);
    }
    if destination == DestinationPolicy::Configured {
        return None;
    }
    let url::Host::Domain(name) = target.host()? else {
        return None;
    };
    let name = name.parse::<reqwest::dns::Name>().ok()?;
    let resolver = PinningResolver::new(SystemResolver).with_policy(destination);
    // Bounded: the flight is held meanwhile. A lookup that does not finish
    // is not a refusal; the redirect error stays untyped.
    let lookup = reqwest::dns::Resolve::resolve(&resolver, name);
    let error = tokio::time::timeout(REDIRECT_LOOKUP_TIMEOUT, lookup)
        .await
        .ok()?
        .err()?;
    ssrf_denial(&*error).map(ToString::to_string)
}

/// Whether `body` is an RFC 6749 error response (an `error` string field).
fn names_an_oauth_error(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("error")?.as_str().map(str::to_owned))
        .is_some()
}
