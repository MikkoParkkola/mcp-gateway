// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The OAuth grants: authorization code exchange, refresh and client credentials, and their parameter builders.
// stdout is the stdio transport's JSON-RPC stream: nothing here prints to it (MIK-8197).
#![deny(clippy::print_stdout)]

use super::super::callback;
use super::super::metadata::AuthorizationServerMetadata;
use super::super::storage::TokenInfo;
use crate::security::http_diagnostics::oauth_request_error;
use crate::security::{safe_oauth_http_error, safe_reqwest_message};
use crate::{Error, Result};
use tracing::{info, warn};

use super::{OAuthClient, TokenResponse, generate_pkce, generate_state, validate_issuer};

/// How long a login waits for the person at the browser (MIK-7982). Not the
/// backend's request `timeout`: an interactive login with MFA routinely takes
/// longer than one request may.
pub(crate) const OAUTH_AUTHORIZATION_WINDOW: std::time::Duration =
    std::time::Duration::from_secs(300);

mod authorize;

/// Build a token from a token endpoint's answer, first refusing an
/// oversized `expires_in` (MIK-8207).
fn token_from_answer(
    token_endpoint: &str,
    token_response: TokenResponse,
    now: u64,
) -> Result<TokenInfo> {
    super::refuse_oversized_expires_in(token_endpoint, token_response.expires_in)?;
    Ok(TokenInfo::from_response_at(
        token_response.access_token,
        token_response.token_type,
        token_response.refresh_token,
        token_response.expires_in,
        token_response.scope,
        now,
    ))
}

impl OAuthClient {
    /// The discovered authorization-server metadata, or the error every
    /// grant gives before `initialize` has run.
    fn auth_meta(&self) -> Result<&AuthorizationServerMetadata> {
        self.auth_metadata
            .as_ref()
            .ok_or_else(|| Error::OAuth("OAuth not initialized".to_string()))
    }

    /// Attempt client-credentials grant (headless re-auth, no browser required).
    ///
    /// Returns `Ok(token)` only when the authorization server explicitly lists
    /// `"client_credentials"` in `grant_types_supported` — so we never try it
    /// against a server that won't accept it.
    pub(super) async fn try_client_credentials(&self) -> Result<String> {
        let auth_meta = self.auth_meta()?;

        if !auth_meta
            .grant_types_supported
            .iter()
            .any(|g| g == "client_credentials")
        {
            return Err(Error::OAuth(
                "Server does not support client_credentials grant".to_string(),
            ));
        }

        let client_id = self
            .client_id
            .read()
            .clone()
            .ok_or_else(|| Error::OAuth("No client ID for client_credentials".to_string()))?;

        let params = self.client_credentials_params(&client_id);

        // One clock reading dates the token this request returns; a clock that
        // cannot be read (before 1970) refuses before anything is sent
        // (MIK-8202).
        let now = super::issuance_clock()?;

        let response = self
            .client_for(&auth_meta.token_endpoint)?
            .post(&auth_meta.token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| oauth_request_error("Client credentials request failed", &e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            // Mirror the exchange_code/refresh_token paths: a rejected dynamic registration must be
            // purged so the next attempt re-registers. Fix 1's guard makes this a no-op for
            // configured-secret (static) clients.
            self.purge_client_id_if_invalid(&body);
            return Err(Error::OAuth(safe_oauth_http_error(
                "Client credentials failed",
                status,
                &body,
            )));
        }

        let token_response: TokenResponse = response.json().await.map_err(|e| {
            Error::OAuth(safe_reqwest_message(
                "Failed to parse credentials response",
                &e,
            ))
        })?;

        let token = token_from_answer(&auth_meta.token_endpoint, token_response, now)?;

        self.save_issued(&token).await?;
        *self.current_token.write() = Some(token.clone());

        info!(backend = %self.backend_name, "Token renewed via client_credentials");
        Ok(token.access_token)
    }

    /// RFC 8707 resource indicator for this backend.
    ///
    /// MCP's authorization spec (rev 2025-06-18) mandates Resource Indicators (RFC 8707): the
    /// `resource` parameter MUST be sent on both the authorization request and every token request
    /// so the authorization server can audience-bind the issued token to this specific MCP server.
    /// Omitting it makes strict providers reject the flow with `server_error` (see issue #369).
    ///
    /// Prefers the canonical identifier advertised by discovered protected-resource metadata (RFC
    /// 9728 `resource` field); falls back to the configured MCP endpoint URL when metadata
    /// discovery did not run or omitted it.
    pub(super) fn resource_indicator(&self) -> &str {
        self.resource_metadata
            .as_ref()
            .map_or(self.resource_url.as_str(), |m| m.resource.as_str())
    }

    /// Form parameters for the `authorization_code` → token exchange
    /// (RFC 6749 §4.1.3 + PKCE RFC 7636 + Resource Indicators RFC 8707).
    ///
    /// Pure builder so the request body — including the `resource` indicator
    /// (issue #369) — is unit-testable without a live token endpoint.
    pub(super) fn token_exchange_params(
        &self,
        code: &str,
        redirect_uri: &str,
        client_id: &str,
        code_verifier: &str,
    ) -> Vec<(&'static str, String)> {
        let mut params = vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.to_string()),
            ("redirect_uri", redirect_uri.to_string()),
            ("client_id", client_id.to_string()),
            ("code_verifier", code_verifier.to_string()),
        ];
        // Include client_secret when the provider requires it (Slack, Figma, …).
        if let Some(ref secret) = self.client_secret {
            params.push(("client_secret", secret.clone()));
        }
        // RFC 8707 Resource Indicator — must match the authorization request so
        // the AS issues an audience-bound token (issue #369).
        params.push(("resource", self.resource_indicator().to_string()));
        params
    }

    /// Form parameters for the `refresh_token` grant (RFC 6749 §6 + RFC 8707).
    pub(super) fn refresh_params(
        &self,
        refresh_token: &str,
        client_id: &str,
    ) -> Vec<(&'static str, String)> {
        let mut params = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh_token.to_string()),
            ("client_id", client_id.to_string()),
        ];
        if let Some(ref secret) = self.client_secret {
            params.push(("client_secret", secret.clone()));
        }
        // RFC 8707 Resource Indicator — keep the refreshed token audience-bound
        // to this MCP server, matching the original grant (issue #369).
        params.push(("resource", self.resource_indicator().to_string()));
        params
    }

    /// Form parameters for the `client_credentials` grant (RFC 6749 §4.4 +
    /// RFC 8707). No `client_secret` is added here: this path historically
    /// authenticates public/dynamically-registered clients without one.
    pub(super) fn client_credentials_params(&self, client_id: &str) -> Vec<(&'static str, String)> {
        let mut params = vec![
            ("grant_type", "client_credentials".to_string()),
            ("client_id", client_id.to_string()),
        ];
        let scope_str = self.scopes.join(" ");
        if !scope_str.is_empty() {
            params.push(("scope", scope_str));
        }
        // RFC 8707 Resource Indicator — audience-bind the client_credentials
        // token to this MCP server, matching the other grants (issue #369).
        params.push(("resource", self.resource_indicator().to_string()));
        params
    }

    /// Exchange authorization code for tokens
    pub(super) async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<TokenInfo> {
        let auth_meta = self.auth_meta()?;

        let client_id = self
            .client_id
            .read()
            .clone()
            .ok_or_else(|| Error::OAuth("No client ID".to_string()))?;

        let params = self.token_exchange_params(code, redirect_uri, &client_id, code_verifier);

        // One clock reading dates the token this request returns; a clock that
        // cannot be read (before 1970) refuses before anything is sent
        // (MIK-8202).
        let now = super::issuance_clock()?;

        let response = self
            .client_for(&auth_meta.token_endpoint)?
            .post(&auth_meta.token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| oauth_request_error("Token request failed", &e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            // #143 — structured telemetry: token exchange failure event.
            warn!(
                event = "oauth.token_exchange.failure",
                backend = %self.backend_name,
                http_status = status.as_u16(),
                "OAuth token exchange failed"
            );
            self.purge_client_id_if_invalid(&body);
            return Err(Error::OAuth(safe_oauth_http_error(
                "Token exchange failed",
                status,
                &body,
            )));
        }

        let token_response: TokenResponse = response.json().await.map_err(|e| {
            Error::OAuth(safe_reqwest_message("Failed to parse token response", &e))
        })?;

        // #143 — structured telemetry: token exchange success event.
        info!(
            event = "oauth.token_exchange.success",
            backend = %self.backend_name,
            has_refresh_token = token_response.refresh_token.is_some(),
            expires_in = token_response.expires_in,
            "OAuth token exchange succeeded"
        );

        token_from_answer(&auth_meta.token_endpoint, token_response, now)
    }

    /// Refresh an access token: at most one exchange per stored credential in
    /// the process, with the stored refresh token, never with one an earlier
    /// exchange may have consumed (MIK-8018).
    ///
    /// The stored record is the only source of the refresh token: a missing
    /// record, or one without a refresh token (spent, or never issued), needs a
    /// login, and an in-memory copy is never a fallback.
    pub(super) async fn refresh_token(&self) -> Result<String> {
        use super::refresh_flight::{Refreshed, StoredCredential, refresh_stored};
        if self.auth_metadata.is_none() {
            return Err(Error::OAuth("OAuth not initialized".to_string()));
        }
        let key = self.credential_key()?;
        let at = StoredCredential {
            storage: &self.storage,
            key: &key,
            resource_url: &self.resource_url,
            label: &self.backend_name,
        };
        match refresh_stored(self, at).await? {
            Refreshed::Adopted(access) => Ok(access),
            Refreshed::Exchanged(token) => {
                let access = token.access_token.clone();
                *self.current_token.write() = Some(token);
                info!(backend = %self.backend_name, "Token refreshed successfully");
                Ok(access)
            }
            Refreshed::Rejected { status, body } => {
                self.purge_client_id_if_invalid(&body);
                Err(Error::OAuth(safe_oauth_http_error(
                    "Token refresh failed",
                    status,
                    &body,
                )))
            }
            Refreshed::LoginRequired => Err(Error::AuthorizationRequired {
                backend: self.backend_name.clone(),
            }),
        }
    }

    /// Test-only: the cross-process lock `save_issued` takes before it
    /// stores a login's token (`hold_across_processes`), so a row can hold it
    /// as another gateway process would (MIK-8339 LOGINDL.18b).
    #[cfg(test)]
    pub(crate) fn credential_lock_path_for_test(&self) -> std::path::PathBuf {
        let key = self
            .credential_key()
            .expect("a test client has a credential key");
        self.storage
            .token_path(&key, &self.resource_url)
            .with_extension("refresh.lock")
    }

    /// Test-only: [`save_issued`](Self::save_issued) without the
    /// `client_credentials` exchange before it, so a row on a paused clock
    /// reaches the lease wait without a real socket (MIK-8619 T2).
    #[cfg(test)]
    pub(crate) async fn save_issued_for_test(&self, token: &TokenInfo) -> Result<()> {
        self.save_issued(token).await
    }

    /// Test-only: [`save_issued_until`](Self::save_issued_until) without the
    /// login's browser, callback and exchange before it, so a row on a paused
    /// clock reaches the lease wait without real sockets (MIK-8619 T8). A
    /// fresh cancel never fires; `None` keeps the authorization window.
    #[cfg(test)]
    pub(crate) async fn save_issued_until_for_test(&self, token: &TokenInfo) -> Result<()> {
        self.save_issued_until(
            token,
            &tokio_util::sync::CancellationToken::new(),
            None,
        )
        .await
    }

    /// Test-only: the cached token lapses now, in memory and in storage, as
    /// if its lifetime had passed (MIK-8269): a row that needs a lapsed token
    /// asks for one instead of sleeping out a short-lived token.
    #[cfg(test)]
    pub(crate) async fn age_token_for_test(&self) {
        let now = crate::clock::unix_secs().expect("the test clock reads after 1970");
        let aged = {
            let mut slot = self.current_token.write();
            let Some(token) = slot.as_mut() else { return };
            token.expires_at = Some(now);
            token.clone()
        };
        self.save_issued(&aged).await.expect("the aged token saves");
    }

    /// Save a token a login or a client-credentials grant issued, under the
    /// credential's refresh flight (MIK-8018 FU-A.1): never interleaved with
    /// an exchange's save or compare-and-clear of the same record.
    async fn save_issued(&self, token: &TokenInfo) -> Result<()> {
        let key = self.credential_key()?;
        let token_path = self.storage.token_path(&key, &self.resource_url);
        let flight = super::refresh_flight::Flight::of(&token_path);
        let _guard = flight.lock.lock().await;
        let _across = super::refresh_flight::hold_across_processes(&token_path).await?;
        self.store_issued_locked(&key, token)
    }

    /// [`save_issued`](Self::save_issued) for a login's Lead stage
    /// (MIK-8339): the waits for the credential's in-process flight and its
    /// cross-process lock observe the Lead's `cancel` (a restart or stop:
    /// `AuthorizationCancelled`) and end at [`OAUTH_AUTHORIZATION_WINDOW`]
    /// (`AuthorizationIncomplete`), cancel first. Once both locks are held the
    /// write runs to completion: a cancel never leaves half a credential.
    async fn save_issued_until(
        &self,
        token: &TokenInfo,
        cancel: &tokio_util::sync::CancellationToken,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<()> {
        let key = self.credential_key()?;
        let token_path = self.storage.token_path(&key, &self.resource_url);
        let flight = super::refresh_flight::Flight::of(&token_path);
        let held = async {
            let guard = flight.lock.lock().await;
            let across = super::refresh_flight::hold_across_processes(&token_path).await?;
            Ok::<_, Error>((guard, across))
        };
        let (_guard, _across) = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                return Err(Error::AuthorizationCancelled {
                    backend: self.backend_name().to_string(),
                });
            }
            () = tokio::time::sleep_until(match deadline {
                Some(deadline) => crate::oauth::login_gate::stage_end(OAUTH_AUTHORIZATION_WINDOW, deadline),
                None => tokio::time::Instant::now() + OAUTH_AUTHORIZATION_WINDOW,
            }) => {
                return Err(Error::AuthorizationIncomplete {
                    backend: self.backend_name().to_string(),
                    window_secs: OAUTH_AUTHORIZATION_WINDOW.as_secs(),
                });
            }
            held = held => held?,
        };
        self.store_issued_locked(&key, token)
    }

    /// Store a login's `token` with the credential's locks held, and repair a
    /// damaged refresh-state sidecar (MIK-8091).
    fn store_issued_locked(&self, key: &str, token: &TokenInfo) -> Result<()> {
        let key = key.to_string();
        self.storage.save(&key, &self.resource_url, token)?;
        // A token a login issues was never marked in flight, so a damaged
        // sidecar's lost marker cannot name it (MIK-8091). Rewrite the sidecar
        // clean, keeping the rotation observation, or every fresh token would
        // be retired at its first refresh.
        let state = self.storage.load_refresh_state(&key, &self.resource_url);
        if state.damaged {
            let repaired = crate::oauth::storage::RefreshState {
                damaged: false,
                ..state
            };
            if let Err(error) = self
                .storage
                .save_refresh_state(&key, &self.resource_url, &repaired)
            {
                // The login stands: refusing it over a state file would leave
                // the user with nothing. The next refresh still fails closed;
                // the path names what to remove so the repair can happen.
                let backend = self.backend_name.as_str();
                let path = self.storage.refresh_state_path(&key, &self.resource_url);
                let path = path.display();
                warn!(backend = %backend, path = %path, %error, "Could not repair the refresh state after a login; remove this path (a file or a directory) so the next login rebuilds it");
            }
        }
        Ok(())
    }

    /// The stored token instead of a refresh, when it is unexpired and either
    /// differs from this client's cached one or this client's has expired
    /// (MIK-8018 FU-A.3): another client already refreshed.
    fn adopt_if_fresher(&self, stored: Option<&TokenInfo>) -> Option<String> {
        let stored = stored.filter(|token| !token.is_expired())?;
        let fresher = self.current_token.read().as_ref().is_none_or(|cached| {
            cached.is_expired()
                || cached.access_token != stored.access_token
                || cached.expires_at != stored.expires_at
                || cached.refresh_token != stored.refresh_token
        });
        if fresher {
            self.adopt_stored_login()
        } else {
            None
        }
    }

    /// [`authorize_until`](Self::authorize_until) bounded by a detached
    /// step's one `deadline` (MIK-8339): the callback wait and token save end
    /// at `min(their window, deadline)`; client registration and the code
    /// exchange, which have no window of their own, end at the deadline.
    pub(crate) async fn authorize_until_by(
        &self,
        cancel: &tokio_util::sync::CancellationToken,
        listeners: Option<tokio_util::sync::DropGuard>,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<String> {
        let auth_meta = self.auth_meta()?;

        // Generate PKCE parameters
        let (code_verifier, code_challenge) = generate_pkce();

        // Generate state for CSRF protection
        let state = generate_state();

        // Start callback server FIRST to get the actual callback URL
        // This must happen BEFORE client registration so we know the port
        let mut callback_server = callback::start_callback_server(
            state.clone(),
            self.callback_host.as_deref(),
            self.callback_port,
            self.callback_path.as_deref(),
        )
        .await?;
        if let Some(guard) = listeners {
            callback_server.hold_until_closed(guard);
        }
        let callback_url = callback_server.callback_url.clone();
        let cancelled = || Error::AuthorizationCancelled {
            backend: self.backend_name().to_string(),
        };

        // Now ensure we have a client ID, passing the actual callback URL for
        // registration. A cancel during registration ends it there: no
        // browser opens, and the listener is closed before this returns.
        let registered = tokio::select! {
            biased;
            () = cancel.cancelled() => Err(cancelled()),
            () = crate::oauth::login_gate::past(deadline) => Err(self.incomplete()),
            registered = self.ensure_client_id_with_redirect(&callback_url) => registered,
        };
        // A cancel that lands as registration completes still wins.
        let registered = registered.and_then(|id| {
            if cancel.is_cancelled() {
                Err(cancelled())
            } else {
                Ok(id)
            }
        });
        let client_id = match registered {
            Ok(client_id) => client_id,
            Err(e) => {
                callback_server.stop().await;
                return Err(e);
            }
        };

        // Build authorization URL with the ACTUAL callback URL
        let auth_url = self.build_authorize_url(
            &auth_meta.authorization_endpoint,
            &client_id,
            &callback_url,
            &state,
            &code_challenge,
        )?;

        // Open browser
        let auth_url_str = auth_url.to_string();
        info!(url = %auth_url_str, "Opening browser for authorization");

        if !(self.open_browser)(&auth_url_str) {
            warn!("Failed to open browser automatically");
        }
        // Always, on stderr (MIK-8197): a launcher that started can still be
        // blocked (an endpoint-security tool may stop it), and stdout is the
        // stdio transport's JSON-RPC stream.
        eprintln!("\nIf no browser opened, authorize this client by visiting:\n{auth_url_str}\n");

        // Wait for callback
        let (actual_callback_url, callback_result) = callback_server
            .wait_within(
                deadline.map_or(OAUTH_AUTHORIZATION_WINDOW, |deadline| {
                    crate::oauth::login_gate::stage_end(OAUTH_AUTHORIZATION_WINDOW, deadline)
                        .saturating_duration_since(tokio::time::Instant::now())
                }),
                cancel,
            )
            .await
            .map_err(|unanswered| {
                let backend = self.backend_name().to_string();
                match unanswered {
                    callback::Unanswered::Window => Error::AuthorizationIncomplete {
                        backend,
                        window_secs: OAUTH_AUTHORIZATION_WINDOW.as_secs(),
                    },
                    callback::Unanswered::Cancelled => Error::AuthorizationCancelled { backend },
                }
            })??;

        // RFC 9207, before the code is redeemed: a code that came from another
        // authorization server must not be sent to this one's token endpoint.
        validate_issuer(callback_result.iss.as_deref(), &auth_meta.issuer).map_err(|mismatch| {
            warn!(
                event = "oauth.callback.issuer_mismatch",
                "authorization response named an issuer other than the recorded one"
            );
            Error::OAuth(mismatch)
        })?;

        // Exchange code for token. Cancel first (MIK-8339): a restart or stop
        // ends a login stalled here. The exchange itself is bounded by the
        // OAuth client's own request timeout (destination.rs), and by a
        // detached step's deadline.
        let token = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(cancelled()),
            () = crate::oauth::login_gate::past(deadline) => return Err(self.incomplete()),
            token = self.exchange_code(&callback_result.code, &actual_callback_url, &code_verifier) => token?,
        };

        // Store and cache the token, under the same cancel and the window.
        self.save_issued_until(&token, cancel, deadline).await?;
        *self.current_token.write() = Some(token.clone());

        Ok(token.access_token)
    }
}

/// The MCP backend's side of a refresh under the credential's flight.
impl super::refresh_flight::RefreshCaller for OAuthClient {
    fn adopt(&self, stored: Option<&TokenInfo>) -> Option<String> {
        self.adopt_if_fresher(stored)
    }

    fn request(
        &self,
        _stored: &TokenInfo,
        sent: &str,
    ) -> Result<super::refresh_flight::RefreshRequest> {
        let auth_meta = self.auth_meta()?;
        let key = self.credential_key()?;
        self.reload_registered_client_id(&key);
        let client_id = self
            .client_id
            .read()
            .clone()
            .ok_or_else(|| Error::OAuth("No client ID".to_string()))?;
        Ok(super::refresh_flight::RefreshRequest {
            params: self.refresh_params(sent, &client_id),
            http: self.refresh_client_for(&auth_meta.token_endpoint)?,
            endpoint: auth_meta.token_endpoint.clone(),
            destination: self.destination,
            route: self.refresh_route,
            finish: Box::new(std::convert::identity),
        })
    }
}
