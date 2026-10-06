// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Backend OAuth client construction, split out of `lifecycle.rs` to keep
//! that file from growing.

use std::sync::Arc;

use tracing::info;

use super::Backend;
use crate::oauth::{OAuthClient, OAuthClientConfig, TokenStorage};
use crate::{Error, Result};

impl Backend {
    /// Create OAuth client if OAuth is configured for this backend, under
    /// `destination`: the policy the start that builds it read once, so the
    /// client and its transport cannot be built under two different policies.
    pub(super) fn create_oauth_client(
        &self,
        resource_url: &str,
        destination: crate::security::ssrf::DestinationPolicy,
    ) -> Result<Option<OAuthClient>> {
        let oauth_config = match &self.config.oauth {
            Some(cfg) if cfg.enabled => cfg,
            _ => return Ok(None),
        };

        // F3 sink-side guard. Config::validate() rejects this pairing at load,
        // but programmatic `Backend::new*()` and hot-reload `apply_patch()` build
        // backends from a raw BackendConfig without revalidating. Enforce again
        // here -- the last chokepoint before an OAuth client is created -- so an
        // enabled backend OAuth client is never spun up alongside
        // identity_propagation. The backend OAuth persists a gateway-held token
        // during initialize(), authenticating the transport session as the
        // gateway before any per-request per-user override, silently defeating
        // per-user propagation. Fail closed at the sink.
        if self.config.identity_propagation.is_some() {
            return Err(Error::ConfigValidation(format!(
                "backend '{}' cannot combine identity_propagation with its own enabled oauth \
                 client: the backend oauth persists a gateway-held token during initialize(), \
                 authenticating the transport session as the gateway before the per-request \
                 credential override -- silently defeating per-user propagation (F3).",
                self.name
            )));
        }

        info!(backend = %self.name, "Initializing OAuth client");

        let http_client = crate::oauth::client::destination::http_client(destination)?;

        #[cfg(test)]
        let seam = self.oauth_test_seam.lock().clone();
        #[cfg(test)]
        let storage = match &seam {
            Some(seam) => TokenStorage::new(seam.storage_dir.clone()),
            None => TokenStorage::default_location(),
        };
        #[cfg(not(test))]
        let storage = TokenStorage::default_location();

        // Get or create token storage
        let storage = Arc::new(
            storage.map_err(|e| Error::OAuth(format!("Failed to create token storage: {e}")))?,
        );

        // Create OAuth client
        let oauth = OAuthClient::with_destination(
            destination,
            http_client,
            self.name.clone(),
            resource_url.to_string(),
            oauth_config.scopes.clone(),
            storage,
            OAuthClientConfig {
                client_id: oauth_config.client_id.clone(),
                client_secret: oauth_config.client_secret.clone(),
                callback_host: oauth_config.callback_host.clone(),
                callback_port: oauth_config.callback_port,
                callback_path: oauth_config.callback_path.clone(),
                token_refresh_buffer_secs: oauth_config.token_refresh_buffer_secs,
            },
        )
        .with_login_gate(Arc::clone(&self.login_gate));

        #[cfg(test)]
        let oauth = match seam {
            Some(seam) => oauth.with_open_browser(seam.open_browser),
            None => oauth,
        };

        Ok(Some(oauth))
    }
}
