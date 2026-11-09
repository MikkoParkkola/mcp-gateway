// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The authorization flow: building the authorize URL and running a login.

use super::super::OAuthClient;
use super::OAUTH_AUTHORIZATION_WINDOW;
use crate::{Error, Result};
use url::Url;

impl OAuthClient {
    /// Build the OAuth 2.0 authorization-request URL (RFC 6749 §4.1.1 + PKCE
    /// RFC 7636 + Resource Indicators RFC 8707).
    ///
    /// Pure and side-effect free so the query parameters — critically the
    /// `resource` indicator required by the MCP auth spec (issue #369) — are
    /// unit-testable without standing up a browser or callback server.
    pub(in crate::oauth::client) fn build_authorize_url(
        &self,
        authorization_endpoint: &str,
        client_id: &str,
        callback_url: &str,
        state: &str,
        code_challenge: &str,
    ) -> Result<Url> {
        let mut auth_url = Url::parse(authorization_endpoint)
            .map_err(|e| Error::OAuth(format!("Invalid auth endpoint: {e}")))?;

        {
            let mut params = auth_url.query_pairs_mut();
            params.append_pair("response_type", "code");
            params.append_pair("client_id", client_id);
            params.append_pair("redirect_uri", callback_url);
            params.append_pair("state", state);
            params.append_pair("code_challenge", code_challenge);
            params.append_pair("code_challenge_method", "S256");

            if !self.scopes.is_empty() {
                params.append_pair("scope", &self.scopes.join(" "));
            }

            // RFC 8707 Resource Indicator (mandated by the MCP authorization
            // spec). Audience-binds the issued token to this MCP server; strict
            // providers reject the flow without it (issue #369).
            params.append_pair("resource", self.resource_indicator());
        }

        Ok(auth_url)
    }

    /// Perform the authorization flow
    ///
    /// This is ungated: it never takes the backend's login gate. Its only
    /// production caller is the gate-less fallback of
    /// [`authorize_shared_with`](Self::authorize_shared_with) (below), taken
    /// only when the client has no gate. Every serving client carries the
    /// backend's shared gate (`src/backend/oauth_client.rs`, where the client
    /// is built `with_login_gate`), and the HTTP transport keeps an existing
    /// gate (`src/transport/http/mod.rs`), so in a serving gateway that
    /// fallback is unreachable. Tests that mean to hold the gate call
    /// [`authorize_shared`](Self::authorize_shared).
    ///
    /// # Errors
    ///
    /// Returns an error if any step of the OAuth authorization flow fails
    /// (callback server, client registration, browser auth, or code exchange).
    pub async fn authorize(&self) -> Result<String> {
        let token = self
            .authorize_until(&tokio_util::sync::CancellationToken::new(), None)
            .await?;
        // A sign-in confirmed under another issuer while this login ran: the
        // token is the old issuer's, refused as the entry check would have.
        if self.issuer_differs() {
            return Err(self.issuer_wait());
        }
        Ok(token)
    }

    /// This client sharing `gate` with every other client of its backend.
    #[must_use]
    pub(crate) fn with_login_gate(
        mut self,
        gate: std::sync::Arc<crate::oauth::login_gate::LoginGate>,
    ) -> Self {
        self.login_gate = Some(gate);
        self
    }

    /// Authorize through the backend's login gate (MIK-7982): lead a login if
    /// none is in flight, or wait on the one that is and share its end. The
    /// leader records the end on the gate itself, so a caller that gave up
    /// loses nothing: this runs inside the start's detached OAuth task. A
    /// caller that is not `interactive` never begins or joins one.
    ///
    /// # Errors
    ///
    /// As [`Self::authorize_until`]; a joiner gets the led login's typed
    /// outcome, or an OAuth error if the led login stored no token;
    /// [`Error::AuthorizationRequired`] when not `interactive`.
    pub(crate) async fn authorize_shared(
        &self,
        interactive: bool,
        since: Option<u64>,
    ) -> Result<String> {
        self.authorize_shared_with(interactive, since, None, None)
            .await
    }

    /// [`authorize_shared`](Self::authorize_shared) for a caller that
    /// captured its `cohort` before it queued (MIK-8339): a failure already
    /// recorded on that cohort is shared, under the gate lock, instead of
    /// opening a second login.
    pub(crate) async fn authorize_shared_with(
        &self,
        interactive: bool,
        since: Option<u64>,
        cohort: Option<&std::sync::Arc<crate::oauth::login_gate::Cohort>>,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<String> {
        use crate::oauth::login_gate::Begin;
        if !interactive {
            return Err(Error::AuthorizationRequired {
                backend: self.backend_name().to_string(),
            });
        }
        let Some(gate) = &self.login_gate else {
            return self.authorize().await;
        };
        // A bounded caller's deadline must read this wait as a login's, even
        // once a dropped lead has released the gate (MIK-7982 C3).
        crate::oauth::login_gate::Provenance::mark_waited();
        match gate.begin(since, cohort) {
            Begin::Refused => Err(Error::AuthorizationCancelled {
                backend: self.backend_name().to_string(),
            }),
            Begin::Ended(outcome) => Err(outcome.to_error(self.backend_name())),
            Begin::Lead(mut lead) => {
                // A login that ended while this client was being built may
                // already have stored a token: use it, open no second login.
                let allowed = match self.adopt_stored_login() {
                    Adopt::Took(access) => {
                        lead.end(None);
                        return Ok(access);
                    }
                    // The issuer check is the login's own: a moved install
                    // ends here with the sign-in wait, before any link opens.
                    Adopt::Moved | Adopt::Nothing => match self.issuer_current() {
                        Ok(allowed) => allowed,
                        Err(error) => {
                            lead.end(Some(&error));
                            return Err(error);
                        }
                    },
                };
                // The retry hint of a sign-in started from the dashboard names
                // the deadline this login really runs to.
                #[cfg(feature = "webui")]
                if let Some(deadline) = deadline {
                    lead.set_end(crate::oauth::login_gate::stage_end(
                        super::OAUTH_AUTHORIZATION_WINDOW,
                        deadline,
                    ));
                }
                let listeners = lead.take_listeners_guard();
                let result = self
                    .authorize_until_by(allowed, lead.cancel_token(), listeners, deadline)
                    .await;
                lead.end(result.as_ref().err());
                result
            }
            Begin::Join(attempt) => {
                // The joiner's own deadline ends its wait; the lead's login
                // runs on for whoever else waits on it.
                let finished = tokio::select! {
                    biased;
                    finished = attempt.finished() => finished,
                    () = crate::oauth::login_gate::past(deadline) => {
                        return Err(self.incomplete());
                    }
                };
                if let Some(outcome) = finished {
                    return Err(outcome.to_error(self.backend_name()));
                }
                match self.adopt_stored_login() {
                    Adopt::Took(access) => Ok(access),
                    Adopt::Moved => Err(self.issuer_wait()),
                    Adopt::Nothing => Err(Error::OAuth(
                        "the shared login completed but stored no token".to_string(),
                    )),
                }
            }
        }
    }

    /// A login stage that outlived its window or its step's deadline.
    pub(super) fn incomplete(&self) -> Error {
        Error::AuthorizationIncomplete {
            backend: self.backend_name().to_string(),
            window_secs: OAUTH_AUTHORIZATION_WINDOW.as_secs(),
        }
    }

    /// This client's login gate, if it has one: the transport clones it at
    /// construction so a caller can read the gate without the client mutex
    /// (MIK-8339).
    pub(crate) fn login_gate(&self) -> Option<std::sync::Arc<crate::oauth::login_gate::LoginGate>> {
        self.login_gate.clone()
    }

    /// Take the confirmed token from storage, recording the count sampled before
    /// the read only once adopted under this client's own issuer (again if it
    /// moved), which alone ends a provider-changed state. A token inside the
    /// expiry buffer is cached, not adopted, so a refresh can use it.
    pub(in crate::oauth::client) fn adopt_installed(&self) -> Adopt {
        let Some(status) = self.sign_in_status.as_ref() else {
            return Adopt::Nothing;
        };
        loop {
            let sampled = status.installed();
            let (adopted, read_nothing) = match self.adopt_stored_login() {
                Adopt::Took(access) => (Some(access), false),
                Adopt::Moved => (None, false),
                Adopt::Nothing => {
                    let stored = self
                        .credential_key()
                        .ok()
                        .and_then(|key| self.storage.load(&key, &self.resource_url));
                    let read_nothing = stored.is_none();
                    match stored {
                        // Inside the expiry buffer: cached for a refresh, if the
                        // install is still this client's.
                        Some(stored) => {
                            self.cache_if_current(stored);
                        }
                        // Nothing could be read: the old account's token stops serving.
                        None => *self.current_token.write() = None,
                    }
                    (None, read_nothing)
                }
            };
            #[cfg(all(test, feature = "webui"))]
            self.adopt_pause.pause_blocking();
            // Before any exit: the install is under another issuer, so nothing
            // of this client's issuer stays cached and it is not acknowledged.
            if self.issuer_differs() {
                *self.current_token.write() = None;
                return Adopt::Moved;
            }
            // Nothing was read: unacknowledged, so the next call retries.
            if read_nothing {
                return Adopt::Nothing;
            }
            if status.clear_provider_changed() {
                self.publish_sign_in();
            }
            self.installed_seen
                .store(sampled, std::sync::atomic::Ordering::SeqCst);
            if status.installed() == sampled {
                return adopted.map_or(Adopt::Nothing, Adopt::Took);
            }
        }
    }

    /// Take up a live token another client of this backend stored, with the
    /// client id it registered (a refresh needs both). `Nothing` if there is
    /// none; `Moved` if the latest install is under another issuer, which no
    /// caller may read as leave to run a grant.
    pub(super) fn adopt_stored_login(&self) -> Adopt {
        // Before anything is read: a moved install is Moved, whether or not
        // this issuer still has a token stored.
        if self.issuer_differs() {
            return Adopt::Moved;
        }
        let Ok(key) = self.credential_key() else {
            return Adopt::Nothing;
        };
        let stored = self
            .storage
            .load(&key, &self.resource_url)
            .filter(|token| !token.is_expired());
        #[cfg(all(test, feature = "webui"))]
        self.stored_read_pause.pause_blocking();
        // A switch landing between the check above and this read is still a
        // move, not an empty store.
        let Some(token) = stored else {
            return if self.issuer_differs() {
                Adopt::Moved
            } else {
                Adopt::Nothing
            };
        };
        let access = token.access_token.clone();
        if !self.cache_if_current(token.clone()) {
            return Adopt::Moved;
        }
        self.reload_registered_client_id(&key);
        self.publish_token_state(Some(&token));
        Adopt::Took(access)
    }

    /// [`Self::adopt_stored_login`] for a test that races it.
    #[cfg(all(test, feature = "webui"))]
    pub(in crate::oauth::client) fn adopt_stored_login_for_test(&self) -> Adopt {
        self.adopt_stored_login()
    }

    /// The login or refresh that stored this credential may have registered
    /// afresh: a dynamically registered id held here is replaced by the stored
    /// one, or a refresh would present the old id. A configured id stays.
    pub(super) fn reload_registered_client_id(&self, key: &str) {
        if *self.client_id_source.read() == Some(super::super::ClientIdSource::Registered)
            && let Some(stored) = self.storage.load_client_id(key, &self.resource_url)
        {
            *self.client_id.write() = Some(stored);
        } else {
            self.restore_persisted_client_id();
        }
    }

    /// [`Self::authorize`], ended early by `cancel` (a restart or shutdown of
    /// the backend). The callback wait is bounded by
    /// [`OAUTH_AUTHORIZATION_WINDOW`] either way (MIK-7982).
    ///
    /// # Errors
    ///
    /// As [`Self::authorize`], plus [`Error::AuthorizationIncomplete`] when
    /// the window passes and [`Error::AuthorizationCancelled`] on `cancel`.
    pub(crate) async fn authorize_until(
        &self,
        cancel: &tokio_util::sync::CancellationToken,
        listeners: Option<tokio_util::sync::DropGuard>,
    ) -> Result<String> {
        let allowed = self.issuer_current()?;
        self.authorize_until_by(allowed, cancel, listeners, None)
            .await
    }
}

/// What adopting the latest confirmed sign-in came to.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::oauth::client) enum Adopt {
    /// Its token, now cached.
    Took(String),
    /// No live token was taken: the cache holds what could be read, if any.
    Nothing,
    /// The install is under another issuer than this client's: the cache is
    /// emptied, and the caller answers with the sign-in wait.
    Moved,
}
