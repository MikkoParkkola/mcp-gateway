// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The OAuth grants: authorization code exchange, refresh and client credentials, and their parameter builders.

use super::super::callback;
use super::super::storage::TokenInfo;
use crate::security::http_diagnostics::oauth_request_error;
use crate::security::{safe_oauth_http_error, safe_reqwest_message};
use crate::{Error, Result};
use tracing::{info, warn};
use url::Url;

use super::{OAuthClient, TokenResponse, generate_pkce, generate_state, validate_issuer};

impl OAuthClient {
    /// Attempt client-credentials grant (headless re-auth, no browser required).
    ///
    /// Returns `Ok(token)` only when the authorization server explicitly lists
    /// `"client_credentials"` in `grant_types_supported` — so we never try it
    /// against a server that won't accept it.
    pub(super) async fn try_client_credentials(&self) -> Result<String> {
        let auth_meta = self
            .auth_metadata
            .as_ref()
            .ok_or_else(|| Error::OAuth("OAuth not initialized".to_string()))?;

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

        let token = TokenInfo::from_response(
            token_response.access_token,
            token_response.token_type,
            token_response.refresh_token,
            token_response.expires_in,
            token_response.scope,
        );

        self.storage
            .save(&self.credential_key()?, &self.resource_url, &token)?;
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
        let auth_meta = self
            .auth_metadata
            .as_ref()
            .ok_or_else(|| Error::OAuth("OAuth not initialized".to_string()))?;

        let client_id = self
            .client_id
            .read()
            .clone()
            .ok_or_else(|| Error::OAuth("No client ID".to_string()))?;

        let params = self.token_exchange_params(code, redirect_uri, &client_id, code_verifier);

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

        Ok(TokenInfo::from_response(
            token_response.access_token,
            token_response.token_type,
            token_response.refresh_token,
            token_response.expires_in,
            token_response.scope,
        ))
    }

    /// Refresh an access token
    pub(super) async fn refresh_token(&self, refresh_token: &str) -> Result<String> {
        let auth_meta = self
            .auth_metadata
            .as_ref()
            .ok_or_else(|| Error::OAuth("OAuth not initialized".to_string()))?;

        let client_id = self
            .client_id
            .read()
            .clone()
            .ok_or_else(|| Error::OAuth("No client ID".to_string()))?;

        let params = self.refresh_params(refresh_token, &client_id);

        let response = self
            .client_for(&auth_meta.token_endpoint)?
            .post(&auth_meta.token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| oauth_request_error("Token refresh failed", &e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            self.purge_client_id_if_invalid(&body);
            return Err(Error::OAuth(safe_oauth_http_error(
                "Token refresh failed",
                status,
                &body,
            )));
        }

        let token_response: TokenResponse = response.json().await.map_err(|e| {
            Error::OAuth(safe_reqwest_message("Failed to parse refresh response", &e))
        })?;

        let token = TokenInfo::from_response(
            token_response.access_token,
            token_response.token_type,
            // No new refresh token means keep the one sent (RFC 6749 section 6);
            // dropping it would end headless renewal at the next expiry (MIK-8021).
            token_response
                .refresh_token
                .or_else(|| Some(refresh_token.to_string())),
            token_response.expires_in,
            token_response.scope,
        );

        // Store and cache
        self.storage
            .save(&self.credential_key()?, &self.resource_url, &token)?;
        *self.current_token.write() = Some(token.clone());

        info!(backend = %self.backend_name, "Token refreshed successfully");
        Ok(token.access_token)
    }

    /// Build the OAuth 2.0 authorization-request URL (RFC 6749 §4.1.1 + PKCE
    /// RFC 7636 + Resource Indicators RFC 8707).
    ///
    /// Pure and side-effect free so the query parameters — critically the
    /// `resource` indicator required by the MCP auth spec (issue #369) — are
    /// unit-testable without standing up a browser or callback server.
    pub(super) fn build_authorize_url(
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
        let auth_meta = self
            .auth_metadata
            .as_ref()
            .ok_or_else(|| Error::OAuth("OAuth not initialized".to_string()))?;

        // Generate PKCE parameters
        let (code_verifier, code_challenge) = generate_pkce();

        // Generate state for CSRF protection
        let state = generate_state();

        // Start callback server FIRST to get the actual callback URL
        // This must happen BEFORE client registration so we know the port
        let callback_server = callback::start_callback_server(
            state.clone(),
            self.callback_host.as_deref(),
            self.callback_port,
            self.callback_path.as_deref(),
        )
        .await?;
        let callback_url = callback_server.callback_url.clone();

        // Now ensure we have a client ID, passing the actual callback URL for registration
        let client_id = match self.ensure_client_id_with_redirect(&callback_url).await {
            Ok(client_id) => client_id,
            Err(e) => {
                callback_server.stop();
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
            println!("\nPlease authorize this client by visiting:\n{auth_url_str}\n");
        }

        // Wait for callback
        let (actual_callback_url, callback_result) = callback_server.wait_for_callback().await?;

        // RFC 9207, before the code is redeemed: a code that came from another
        // authorization server must not be sent to this one's token endpoint.
        validate_issuer(callback_result.iss.as_deref(), &auth_meta.issuer).map_err(|mismatch| {
            warn!(
                event = "oauth.callback.issuer_mismatch",
                "authorization response named an issuer other than the recorded one"
            );
            Error::OAuth(mismatch)
        })?;

        // Exchange code for token
        let token = self
            .exchange_code(&callback_result.code, &actual_callback_url, &code_verifier)
            .await?;

        // Store and cache the token
        self.storage
            .save(&self.credential_key()?, &self.resource_url, &token)?;
        *self.current_token.write() = Some(token.clone());

        Ok(token.access_token)
    }
}
