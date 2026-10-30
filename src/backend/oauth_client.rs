// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Backend OAuth client construction, split out of `lifecycle.rs` to keep
//! that file from growing.

use std::sync::Arc;
#[cfg(any(test, feature = "webui"))]

use tracing::info;

use super::Backend;
#[cfg(any(test, feature = "webui"))]
use crate::oauth::client::sign_in::SignIn;
use crate::oauth::{OAuthClient, OAuthClientConfig, TokenStorage};
use crate::{Error, Result};

/// What [`Backend::slot_gateway_credentials`] answers: the slot's credential
/// kind, its static headers and its OAuth client.
type SlotGatewayCredentials = (
    Option<crate::transport::SlotCredential>,
    std::collections::HashMap<String, String>,
    Option<OAuthClient>,
);

impl Backend {
    /// A slot's credential kind (a per-user slot's; `None` for the shared
    /// one) and the gateway's own credentials its transport is built with:
    /// the static headers and the OAuth client. A required binding's
    /// per-user slot (`LentOnly`) carries neither, as the per-user
    /// listener's transport is built.
    pub(super) fn slot_gateway_credentials(
        &self,
        key: &super::PoolKey,
        http_url: &str,
        built_under: crate::security::ssrf::DestinationPolicy,
    ) -> Result<SlotGatewayCredentials> {
        let slot =
            matches!(key, super::PoolKey::PerUser { .. }).then(|| self.per_user_slot_credential());
        if slot == Some(crate::transport::SlotCredential::LentOnly) {
            return Ok((slot, std::collections::HashMap::new(), None));
        }
        Ok((
            slot,
            self.config.headers.clone(),
            self.create_oauth_client(http_url, built_under)?,
        ))
    }

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
        .with_login_gate(Arc::clone(&self.login_gate))
        .with_sign_in_status(Arc::clone(&self.sign_in_status));

        #[cfg(test)]
        let oauth = match seam {
            Some(seam) => oauth.with_open_browser(seam.open_browser),
            None => oauth,
        };

        Ok(Some(oauth))
    }
}

impl Backend {
    /// This backend's sign-in as an operator acts on it: one in-memory
    /// snapshot, with no storage read, refresh or network call.
    #[cfg(any(test, feature = "webui"))]
    pub(crate) fn sign_in(&self) -> SignIn {
        self.sign_in_given(self.shared_entry().auth_wait.get())
    }

    /// [`Backend::sign_in`] for a wait already read, so one caller never
    /// sees two answers to one question. Order: no `oauth` block, then an
    /// unchecked issuer, then a wait over a held token, then the token cases.
    #[cfg(any(test, feature = "webui"))]
    fn sign_in_given(&self, waiting: bool) -> SignIn {
        if !self
            .config
            .oauth
            .as_ref()
            .is_some_and(|oauth| oauth.enabled)
        {
            return if waiting {
                SignIn::WaitingElsewhere
            } else {
                SignIn::NotOAuth
            };
        }
        match self.sign_in_status.snapshot() {
            SignIn::SignedIn { .. } if waiting => SignIn::Expired,
            held => held,
        }
    }

    /// Whether this backend needs a person to sign in. The one place the
    /// predicate is evaluated; the server row and the overview both call it.
    #[cfg(any(test, feature = "webui"))]
    pub(crate) fn needs_sign_in(&self) -> bool {
        let waiting = self.shared_entry().auth_wait.get();
        waiting || self.sign_in_given(waiting).needs_a_person()
    }
}

#[cfg(feature = "webui")]
impl Backend {
    /// The client a person's sign-in runs on, its issuer resolved. A test's
    /// installed client stands in for the one a start would build.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend has no `oauth` block or no HTTP
    /// endpoint, or discovery fails.
    pub(crate) async fn sign_in_client(&self) -> Result<Arc<OAuthClient>> {
        #[cfg(test)]
        if let Some(client) = self.installed_oauth_client.lock().clone() {
            return Ok(client);
        }
        let crate::config::TransportConfig::Http { http_url, .. } = &self.config.transport else {
            return Err(Error::Config(format!(
                "backend '{}' has no HTTP endpoint to sign in to",
                self.name
            )));
        };
        let Some(mut client) = self.create_oauth_client(http_url, self.destination())? else {
            return Err(Error::Config(format!(
                "backend '{}' has no oauth block",
                self.name
            )));
        };
        client.initialize().await?;
        Ok(Arc::new(client))
    }

    /// Whether this backend is configured for OAuth sign-in.
    pub(crate) fn has_oauth(&self) -> bool {
        self.config
            .oauth
            .as_ref()
            .is_some_and(|oauth| oauth.enabled)
    }
}

#[cfg(all(test, feature = "webui"))]
impl Backend {
    /// Test-only: the OAuth client the sign-in flow uses, in place of the one
    /// a start would build.
    pub(crate) fn install_oauth_client_for_test(&self, client: OAuthClient) {
        *self.installed_oauth_client.lock() = Some(Arc::new(client));
    }

    /// Test-only: the installed client's in-memory token.
    pub(crate) fn installed_client_token_for_test(&self) -> Option<crate::oauth::TokenInfo> {
        let client = self.installed_oauth_client.lock().clone()?;
        client.cached_token_for_test()
    }

    /// Test-only: record that this backend's slot now waits on a sign-in,
    /// bumping the wait's generation.
    pub(crate) fn note_auth_wait(&self) {
        self.shared_entry().set_auth_wait();
    }
}
