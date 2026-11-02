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
    /// A test's pause point in `save_issued`, before its contention budget
    /// starts: by then the grant's answer has been read, so a test may pause
    /// the clock with no socket exchange left in flight.
    #[cfg(test)]
    pub(super) issued_gate: parking_lot::Mutex<Option<Arc<SaveGate>>>,
    /// A test's shorter bound on one exchange, in place of `EXCHANGE_LIMIT`.
    #[cfg(test)]
    pub(super) exchange_limit: parking_lot::Mutex<Option<std::time::Duration>>,
}

/// Holds an exchange before its save: it signals `reached` and waits for
/// `release`.
#[cfg(test)]
#[derive(Default)]
pub(super) struct SaveGate {
    pub(super) reached: tokio::sync::Notify,
    pub(super) release: tokio::sync::Notify,
}

#[cfg(test)]
impl SaveGate {
    /// Signal `reached`, then wait for `release`.
    async fn hold(&self) {
        self.reached.notify_one();
        self.release.notified().await;
    }
}

/// Every credential's flight. Entries are kept for the life of the process:
/// dropping one would drop its spent set (bounded by the credentials a process
/// ever refreshes).
static FLIGHTS: LazyLock<parking_lot::Mutex<HashMap<PathBuf, Arc<Flight>>>> =
    LazyLock::new(parking_lot::Mutex::default);

impl Flight {
    /// Wait at [`Self::issued_gate`] when a test set one.
    #[cfg(test)]
    pub(super) async fn hold_before_issued_save(&self) {
        let gate = self.issued_gate.lock().clone();
        if let Some(gate) = gate {
            gate.hold().await;
        }
    }

    /// The bound on one exchange: `EXCHANGE_LIMIT`, or a test's shorter one.
    #[cfg_attr(not(test), allow(clippy::unused_self))]
    fn limit(&self) -> std::time::Duration {
        #[cfg(test)]
        if let Some(limit) = *self.exchange_limit.lock() {
            return limit;
        }
        EXCHANGE_LIMIT
    }

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

/// The contention deadline for the calling task: `now + SHORT_CONTENTION_WAIT`
/// (2 s) for a Short caller, `now + CREDENTIAL_LOCK_WAIT` (90 s) otherwise.
/// Whether the caller may log in does not change it.
pub(super) fn contention_deadline() -> tokio::time::Instant {
    let now = tokio::time::Instant::now();
    match crate::oauth::login_gate::contention_class() {
        crate::oauth::login_gate::ContentionClass::Short => now + SHORT_CONTENTION_WAIT,
        crate::oauth::login_gate::ContentionClass::Long => now + CREDENTIAL_LOCK_WAIT,
    }
}

/// Wait for the credential's in-process flight lock until `deadline`; past it,
/// answer the marked busy error (the same text the lease's timeout gives).
pub(super) async fn lock_flight_until(
    flight: &Flight,
    deadline: tokio::time::Instant,
) -> crate::Result<tokio::sync::OwnedMutexGuard<()>> {
    let wait = Arc::clone(&flight.lock).lock_owned();
    let guard = tokio::time::timeout_at(deadline, wait)
        .await
        .map_err(|_| busy_error("the refresh lock stayed held past the contention budget"))?;
    Ok(guard)
}

/// The marked busy error: `BackendUnavailable` with the busy marker, which
/// frees the key and never starts a login.
fn busy_error(detail: &str) -> crate::Error {
    Error::BackendUnavailable(format!("{CREDENTIAL_LOCK_BUSY}: {detail}"))
}

/// Hold the credential at `token_path` against other gateway processes that
/// share the storage directory, as [`Flight::lock`] holds it within this one:
/// a lock on a sidecar file, released by the OS if the process dies. Taken
/// after the in-process lock, so one waiter per process polls here. Polled,
/// not blocked on: a cancelled caller leaves no thread waiting behind it.
///
/// Bounded by the caller's `deadline`: `refresh_stored` and `save_issued`
/// pass `contention_deadline()`, a login's save passes its window, and
/// storage's polled save passes its own bound. Every lock failure answers
/// `BackendUnavailable` with the busy marker, which frees the key and never
/// starts a login.
pub(super) async fn hold_across_processes(
    token_path: &Path,
    deadline: tokio::time::Instant,
) -> crate::Result<ExclusiveFileLock> {
    let lock_path = token_path.with_extension("refresh.lock");
    match ExclusiveFileLock::lease(&lock_path, LOCK_POLL, deadline).await {
        Ok(lock) => Ok(lock),
        // A spent contention budget, not proof the holder stalled: try again later.
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => Err(busy_error(
            "the refresh lock stayed held past the contention budget",
        )),
        // A login cannot fix a lock-file failure, so it carries the marker too.
        Err(error) => Err(busy_error(&format!(
            "could not take the refresh lock: {error}"
        ))),
    }
}

/// Whether `error` is a busy credential lock: a `BackendUnavailable` that
/// starts with the marker. A login joiner gets the same typed error
/// (`LoginOutcome::Busy`), so no text form is read: `OAuth` text can carry
/// server-chosen values and is never busy (MIK-8658).
pub(crate) fn is_credential_lock_busy(error: &Error) -> bool {
    // The marker with its colon: a bare-prefix message such as
    // "credential lock busy-service..." is not a busy lock.
    let marker = format!("{CREDENTIAL_LOCK_BUSY}:");
    matches!(error, Error::BackendUnavailable(text) if text.starts_with(&marker))
}

/// Test-only: the marked busy error, so a backend fill row can drive its
/// failure without spelling the marker (MIK-8619 T13f).
#[cfg(all(test, feature = "metrics"))]
pub(crate) fn busy_error_for_test(label: &str) -> crate::Error {
    busy_error(label)
}

/// The most one exchange may take, answer body included. Above an owned
/// client's own 30 s request timeout plus the 5 s redirect lookup, so it
/// only ever ends an exchange through a supplied client.
const EXCHANGE_LIMIT: std::time::Duration = std::time::Duration::from_secs(60);

/// The contention budget: the longest a healthy holder should need, one
/// exchange capped at `EXCHANGE_LIMIT` (60 s) plus its storage write. Past it
/// the waiter answers busy instead of holding the flight; it is not proof the
/// holder stalled. Under `OAUTH_AUTHORIZATION_WINDOW` (300 s), so an
/// interactive caller's own window ends later.
pub(super) const CREDENTIAL_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(90);

/// The contention budget of the Short class (the probe, era discovery,
/// transport close): callers whose own deadline is at or below it. A peer
/// legitimately holds the lease for a moment while refreshing, so zero is
/// too strict, but a full exchange wait would outlast the probe's own timeout.
/// Pinned below it by test.
/// Known limit: a configured health timeout of 2 s or less can still time out
/// and rebuild under lock contention, as it did before this fix (follow-up
/// MIK-8624).
pub(super) const SHORT_CONTENTION_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// The busy marker every lock failure carries: messages read
/// `credential lock busy: <label>`.
pub(super) const CREDENTIAL_LOCK_BUSY: &str = "credential lock busy";

/// How often a credential held by another process is tried again.
const LOCK_POLL: std::time::Duration = std::time::Duration::from_millis(50);

/// SHA-256 of a refresh token: what the spent set and the persisted in-flight
/// marker hold, so neither keeps the secret itself.
pub(super) fn fingerprint(refresh_token: &str) -> [u8; 32] {
    Sha256::digest(refresh_token.as_bytes()).into()
}

/// [`fingerprint`] as lowercase hex, for the persisted marker.
pub(super) fn fingerprint_hex(refresh_token: &str) -> String {
    crate::hashing::sha256_hex(refresh_token.as_bytes())
}

/// The stored credential a refresh renews: where it is kept, and the name
/// logs give it.
pub(crate) struct StoredCredential<'a> {
    pub(crate) storage: &'a Arc<TokenStorage>,
    pub(crate) key: &'a str,
    pub(crate) resource_url: &'a str,
    pub(crate) label: &'a str,
}

/// A client of a stored credential: the MCP backend's `OAuthClient` or a
/// capability provider (MIK-8020). Both run under the credential's flight.
pub(crate) trait RefreshCaller: Sync {
    /// The access token of a fresher stored record another client wrote,
    /// taken up instead of refreshing; `None` to refresh.
    fn adopt(&self, stored: Option<&TokenInfo>) -> Option<String>;
    /// The request that renews `sent`, built from `stored`, the record
    /// re-read under the flight.
    fn request(&self, stored: &TokenInfo, sent: &str) -> crate::Result<RefreshRequest>;
}

/// One refresh request, as its caller sends it.
pub(crate) struct RefreshRequest {
    pub(crate) http: reqwest::Client,
    pub(crate) endpoint: String,
    pub(crate) params: Vec<(&'static str, String)>,
    pub(crate) destination: DestinationPolicy,
    pub(crate) route: RefreshRoute,
    /// What the caller keeps beside the issued token, filled in before the
    /// save.
    pub(crate) finish: Box<dyn Fn(TokenInfo) -> TokenInfo + Send + Sync>,
}

/// What [`refresh_stored`] settled to.
pub(crate) enum Refreshed {
    /// Another client had stored a fresher token: nothing was sent.
    Adopted(String),
    /// The server issued a token, and it is saved.
    Exchanged(TokenInfo),
    /// The server refused with an OAuth error.
    Rejected {
        status: reqwest::StatusCode,
        body: String,
    },
    /// No refresh token may be sent (none stored, spent, or possibly
    /// consumed by an exchange that never settled): a login is needed.
    LoginRequired,
}

/// Refresh the credential at `at`: at most one exchange per stored credential
/// across this process and others sharing its storage, with the stored
/// refresh token, never one an earlier exchange may have consumed (MIK-8018).
/// A stored record is the only source of the refresh token.
pub(crate) async fn refresh_stored(
    caller: &impl RefreshCaller,
    at: StoredCredential<'_>,
) -> crate::Result<Refreshed> {
    let StoredCredential {
        storage,
        key,
        resource_url,
        label,
    } = at;
    let token_path = storage.token_path(key, resource_url);
    let flight = Flight::of(&token_path);
    // One budget covers the in-process flight and the cross-process lease: a
    // waiter queued behind an in-process holder answers the same busy error
    // at the deadline instead of queuing unbounded (MIK-8619).
    let deadline = contention_deadline();
    let guard = lock_flight_until(&flight, deadline).await?;
    let across = hold_across_processes(&token_path, deadline).await?;

    let stored = storage.load(key, resource_url);
    if let Some(access) = caller.adopt(stored.as_ref()) {
        return Ok(Refreshed::Adopted(access));
    }
    let Some((stored, sent)) = stored.and_then(|record| {
        let sent = record.refresh_token.clone()?;
        Some((record, sent))
    }) else {
        drop(across);
        drop(guard);
        warn!(backend = %label, "No stored refresh token; a login is needed");
        return Ok(Refreshed::LoginRequired);
    };
    if flight.is_spent(&sent) {
        drop(across);
        drop(guard);
        warn!(backend = %label, "Refusing to resend a spent refresh token");
        return Ok(Refreshed::LoginRequired);
    }
    let mut state = storage.load_refresh_state(key, resource_url);
    let marker = fingerprint_hex(&sent);
    // A damaged sidecar may have held this token's marker (MIK-8091).
    if state.may_rotate() && (state.damaged || state.in_flight.as_deref() == Some(marker.as_str()))
    {
        if state.damaged {
            warn!(backend = %label, "Refresh state unreadable; retiring the stored token");
        }
        retire_unsettled(&flight, storage, (key, resource_url), label, &sent, state);
        return Ok(Refreshed::LoginRequired);
    }
    let request = caller.request(&stored, &sent)?;
    // Written before sending, so a process that stops mid-exchange leaves
    // a mark the next refresh reads (FU-A.4). Without it, nothing is sent.
    state.in_flight = Some(marker);
    if let Err(error) = storage.save_refresh_state(key, resource_url, &state) {
        drop(across);
        drop(guard);
        warn!(backend = %label, %error, "Could not mark the refresh in flight; not refreshing");
        return Err(error);
    }
    let exchange = Exchange {
        guard,
        flight,
        http: request.http,
        endpoint: request.endpoint,
        params: request.params,
        sent,
        storage: Arc::clone(storage),
        key: key.to_string(),
        resource_url: resource_url.to_string(),
        backend: label.to_string(),
        state,
        destination: request.destination,
        route: request.route,
        finish: request.finish,
        across,
    };
    let outcome = exchange
        .spawn()
        .await
        .map_err(|e| Error::OAuth(format!("Token refresh task failed: {e}")))?;
    match outcome {
        Outcome::Refreshed(token) => Ok(Refreshed::Exchanged(token)),
        Outcome::Rejected { status, body } => Ok(Refreshed::Rejected { status, body }),
        Outcome::NotSent(error) | Outcome::Uncertain(error) => Err(error),
    }
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
    /// Fills what the caller keeps beside the issued token (MIK-8020).
    pub(super) finish: Box<dyn Fn(TokenInfo) -> TokenInfo + Send + Sync>,
    /// The flight's other half: other gateway processes sharing the storage
    /// directory wait on it too.
    pub(super) across: ExclusiveFileLock,
}

impl Exchange {
    pub(super) fn spawn(self) -> tokio::task::JoinHandle<Outcome> {
        tokio::spawn(self.run())
    }

    async fn run(mut self) -> Outcome {
        let limit = self.flight.limit();
        // A supplied client may have no timeout: an endpoint that takes the
        // request and never answers would hold the credential, and every later
        // refresh and login save, for good. Unanswered means possibly consumed.
        let outcome = tokio::time::timeout(limit, self.send())
            .await
            .unwrap_or_else(|_| {
                Outcome::Uncertain(Error::OAuth(format!(
                    "Token refresh got no answer within {} s",
                    limit.as_secs()
                )))
            });
        // The marker stays when a possibly consumed token could not be retired
        // from storage: a later refresh, even after a restart, retires it then.
        // A supplied client may follow a redirect, so even an OAuth refusal
        // can come from a hop after the server consumed the token.
        let possibly_consumed = match outcome {
            Outcome::Uncertain(_) => true,
            Outcome::Rejected { .. } => self.route == RefreshRoute::Supplied,
            Outcome::Refreshed(_) | Outcome::NotSent(_) => false,
        };
        let retired = !(possibly_consumed && self.state.may_rotate()) || self.spend();
        if retired {
            self.state.in_flight = None;
        }
        if let Err(error) =
            self.storage
                .save_refresh_state(&self.key, &self.resource_url, &self.state)
        {
            let backend = &self.backend;
            warn!(backend = %backend, %error, "Could not settle the refresh state");
        }
        drop(self.across);
        drop(self.guard);
        outcome
    }

    async fn send(&mut self) -> Outcome {
        // One clock reading dates the refreshed token. On a clock that cannot
        // be read nothing is sent: `NotSent` keeps the stored refresh token and
        // clears the in-flight marker (MIK-8202).
        let now = match super::issuance_clock() {
            Ok(now) => now,
            Err(error) => return Outcome::NotSent(error),
        };
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
        // Malformed like an unparsable answer, and handled the same way: the
        // sent token may already be consumed.
        if let Err(error) = super::refuse_oversized_expires_in(&self.endpoint, answer.expires_in) {
            // The caller falls back to a login, so this is where the reason
            // is seen.
            warn!(backend = %self.backend, %error, "Refused the token endpoint's answer");
            return Outcome::Uncertain(error);
        }
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
                let backend = &self.backend;
                warn!(backend = %backend, %error, "Could not record that the server rotates");
                return Outcome::Uncertain(error);
            }
        } else {
            // The answer kept the sent token: this server does not rotate, so
            // a later exchange with an unknown outcome leaves it usable
            // (MIK-8145). Saved when the exchange settles; lost, the server
            // only reads as not yet seen, which retires rather than resends.
            self.state.keeps = true;
        }
        let token = (self.finish)(TokenInfo::from_response_at(
            answer.access_token,
            answer.token_type,
            // No new refresh token means keep the one sent (RFC 6749 section 6).
            answer.refresh_token.or_else(|| Some(self.sent.clone())),
            answer.expires_in,
            answer.scope,
            now,
        ));
        #[cfg(test)]
        {
            let gate = self.flight.save_gate.lock().clone();
            if let Some(gate) = gate {
                gate.hold().await;
            }
        }
        match self.storage.save(&self.key, &self.resource_url, &token) {
            Ok(()) => Outcome::Refreshed(token),
            Err(error) => {
                let backend = &self.backend;
                warn!(backend = %backend, %error, "Could not save a refreshed token");
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

/// An exchange with `sent` never settled (the process stopped mid-exchange)
/// on a server that may rotate: it may be consumed, so it is spent. The marker in
/// `state` stays unless storage no longer holds `sent`, so a later start
/// retires it again rather than sending it.
pub(super) fn retire_unsettled(
    flight: &Flight,
    storage: &TokenStorage,
    at: (&str, &str),
    backend: &str,
    sent: &str,
    mut state: RefreshState,
) {
    if spend(flight, storage, at, backend, sent) {
        state.in_flight = None;
        if let Err(error) = storage.save_refresh_state(at.0, at.1, &state) {
            warn!(backend = %backend, %error, "Could not settle the refresh state");
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    /// MIK-8658 (K3): no OAuth text is a busy lock, whatever server-chosen value it carries.
    #[test]
    fn oauth_text_holding_the_busy_marker_is_never_busy() {
        for s in [
            "authorization response came from issuer 'credential lock busy: x', not the recorded 'https://as.example'; the code was not redeemed",
            "OAuth metadata issuer mismatch: discovered at https://as.example, metadata claims credential lock busy: x",
            "Backend unavailable: credential lock busy: x",
        ] {
            assert!(
                !is_credential_lock_busy(&Error::OAuth(s.to_string())),
                "{s}"
            );
        }
    }

    /// The short wait answers before the probe's own timeout fires, so a busy
    /// probe returns the marked error instead of timing out and rebuilding.
    /// A test, not a const assertion: the probe timeout lives in config.
    #[test]
    fn the_short_wait_is_strictly_below_the_probe_timeout() {
        let probe = crate::config::HealthCheckConfig::default().timeout;
        assert!(
            SHORT_CONTENTION_WAIT < probe,
            "the short wait ({SHORT_CONTENTION_WAIT:?}) must answer before the probe timeout ({probe:?})"
        );
    }
}
