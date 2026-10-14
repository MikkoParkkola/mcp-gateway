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
    /// # Errors
    ///
    /// Returns an error if any step of the OAuth authorization flow fails
    /// (callback server, client registration, browser auth, or code exchange).
    pub async fn authorize(&self) -> Result<String> {
        self.authorize_until(&tokio_util::sync::CancellationToken::new(), None)
            .await
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
                if let Some(access) = self.adopt_stored_login() {
                    lead.end(None);
                    return Ok(access);
                }
                let listeners = lead.take_listeners_guard();
                let result = self
                    .authorize_until_by(lead.cancel_token(), listeners, deadline)
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
                self.adopt_stored_login().ok_or_else(|| {
                    Error::OAuth("the shared login completed but stored no token".to_string())
                })
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

    /// Take up a live token another client of this backend stored, with the
    /// client id it registered (a refresh needs both). `None` if there is none.
    pub(super) fn adopt_stored_login(&self) -> Option<String> {
        let key = self.credential_key().ok()?;
        let token = self
            .storage
            .load(&key, &self.resource_url)
            .filter(|token| !token.is_expired())?;
        self.reload_registered_client_id(&key);
        let access = token.access_token.clone();
        *self.current_token.write() = Some(token);
        Some(access)
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
        self.authorize_until_by(cancel, listeners, None).await
    }
}
