// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Dynamic client registration: obtaining, validating and purging the client id.

use crate::security::http_diagnostics::oauth_request_error;
use crate::security::ssrf::is_ssrf_refusal;
use crate::security::{safe_oauth_http_error, safe_reqwest_message};
use crate::{Error, Result};
use tracing::{debug, error, info, warn};

use super::{
    ClientIdSource, ClientRegistrationResponse, OAuthClient, generate_client_id, registration_body,
};

impl OAuthClient {
    /// Ensure we have a client ID, registering with the specific redirect URI
    pub(super) async fn ensure_client_id_with_redirect(
        &self,
        redirect_uri: &str,
    ) -> Result<String> {
        // Check if we already have one
        if let Some(id) = self.client_id.read().clone() {
            return Ok(id);
        }

        let auth_meta = self
            .auth_metadata
            .as_ref()
            .ok_or_else(|| Error::OAuth("OAuth not initialized".to_string()))?;

        // Try dynamic registration if supported
        if let Some(ref reg_endpoint) = auth_meta.registration_endpoint {
            match self.register_client(reg_endpoint, redirect_uri).await {
                Ok(client_id) => {
                    // Persist immediately: registration succeeded even if the
                    // browser authorize step below never completes. Without this
                    // every connection re-registers and opens a new OAuth tab.
                    let credential_key = self.credential_key()?;
                    // Polled, so this login's cancel can end a wait on another
                    // process's repair lock (MIK-8344).
                    match self
                        .storage
                        .save_client_id_polled(
                            &credential_key,
                            &self.resource_url,
                            &client_id,
                            crate::oauth::storage::REPAIR_LOCK_BOUND,
                        )
                        .await
                    {
                        Ok(persisted) => {
                            // First-writer-wins: a co-located instance may have
                            // registered concurrently; adopt the authoritative
                            // on-disk id so both instances converge on one.
                            *self.client_id.write() = Some(persisted.clone());
                            *self.client_id_source.write() = Some(ClientIdSource::Registered);
                            return Ok(persisted);
                        }
                        Err(e) => {
                            // Do NOT silently swallow: a lost write re-opens the "new client_id
                            // every restart" churn bug. The in-memory id is still valid for THIS
                            // session, so the live auth proceeds, but the operator must see that
                            // persistence failed.
                            let client_file = self
                                .storage
                                .client_path(&credential_key, &self.resource_url);
                            error!(
                                backend = %self.backend_name,
                                error = %e,
                                path = %client_file.display(),
                                "Failed to persist registered client_id; it will be re-registered \
                                 on next restart (auth churn until the write path is fixed)"
                            );
                            *self.client_id.write() = Some(client_id.clone());
                            *self.client_id_source.write() = Some(ClientIdSource::Registered);
                            return Ok(client_id);
                        }
                    }
                }
                Err(e) if is_ssrf_refusal(&e) => return Err(e),
                Err(e) => {
                    debug!(error = %e, "Dynamic registration failed, using generated ID");
                }
            }
        }

        // Generate a client ID
        let generated = generate_client_id();
        *self.client_id.write() = Some(generated.clone());
        *self.client_id_source.write() = Some(ClientIdSource::Registered);
        Ok(generated)
    }

    /// Purge a stored `client_id` when the authorization server rejects it.
    ///
    /// OAuth 2.0 signals an unrecognized client with an `invalid_client` error
    /// in the token-endpoint response body. When that happens the persisted
    /// registration is stale (revoked, expired, garbage-collected); we drop it
    /// from memory and disk so the next attempt re-registers rather than looping
    /// on `invalid_client` forever with no recovery inside the product.
    pub(super) fn purge_client_id_if_invalid(&self, response_body: &str) {
        if !response_body.contains("invalid_client") {
            return;
        }
        // Guard on provenance, not `client_secret` presence: a PUBLIC operator-configured client
        // (client_id set, no secret — e.g. a native/PKCE-only app registration) is just as much
        // operator config as a confidential one, and the old `client_secret.is_some()` guard did
        // not protect it (Defect 2, MIK-6750 r7). Only a client_id whose provenance is positively
        // known to be `Registered` — Dynamic Client Registration, a generated DCR fallback, or a
        // loaded prior registration — is safe to purge and re-register.
        if *self.client_id_source.read() != Some(ClientIdSource::Registered) {
            warn!(
                backend = %self.backend_name,
                "Client rejected with invalid_client; not purging (client_id provenance is not a dynamic registration)"
            );
            return;
        }
        warn!(
            backend = %self.backend_name,
            "Server rejected client_id (invalid_client); purging stored registration so the next attempt re-registers"
        );
        *self.client_id.write() = None;
        *self.client_id_source.write() = None;
        // A local, so the coverage grade can see these lines run (MIK-7725).
        let backend = &self.backend_name;
        match self.credential_key() {
            Ok(key) => {
                if let Err(e) = self.storage.delete_client_id(&key, &self.resource_url) {
                    warn!(backend = %backend, error = %e, "Failed to delete stale client_id file");
                }
            }
            Err(e) => {
                warn!(backend = %backend, error = %e, "Cannot locate stale client_id file without a discovered issuer");
            }
        }
    }

    /// Register a new client dynamically with the specified redirect URI
    pub(super) async fn register_client(
        &self,
        endpoint: &str,
        redirect_uri: &str,
    ) -> Result<String> {
        // Built by the free function above, not inline. Inline, the body a test
        // asserts and the body the gateway sends are two objects that merely
        // resemble each other — and this exact split shipped once already this
        // release, in a discovery document every test passed against.
        let body = registration_body(&self.backend_name, redirect_uri);

        let response = self
            .client_for(endpoint)?
            .post(endpoint)
            .json(&body)
            .send()
            .await
            .map_err(|e| oauth_request_error("Client registration failed", &e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::OAuth(safe_oauth_http_error(
                "Client registration failed",
                status,
                &body,
            )));
        }

        let reg_response: ClientRegistrationResponse = response.json().await.map_err(|e| {
            Error::OAuth(safe_reqwest_message(
                "Failed to parse registration response",
                &e,
            ))
        })?;

        info!(client_id = %reg_response.client_id, "Registered OAuth client");
        Ok(reg_response.client_id)
    }
}

#[cfg(test)]
#[path = "registration_tests.rs"]
mod tests;
