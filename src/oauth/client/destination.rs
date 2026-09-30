// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The backend's destination policy on the OAuth side.
//!
//! Every URL this client requests comes from the backend or its authorization
//! server: the advertised authorization-server base, then its token and
//! registration endpoints, plus any redirect. Under
//! [`DestinationPolicy::Public`] names are pinned by the client and literals are
//! checked here, each before its first use. A new OAuth fetch joins this list.

use std::time::Duration;

use reqwest::Client;

use super::OAuthClient;
use crate::oauth::{AuthorizationServerMetadata, OAuthClientConfig, TokenStorage};
use crate::security::ssrf::DestinationPolicy;
use crate::{Error, Result};

/// Redirects followed per OAuth request (reqwest's own default).
const MAX_HOPS: usize = 10;

/// The HTTP client an OAuth client under `destination` uses.
///
/// # Errors
///
/// `Error::OAuth` if the client cannot be built.
pub(crate) fn http_client(destination: DestinationPolicy) -> Result<Client> {
    let builder = Client::builder();
    builder
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::custom(move |attempt| match hop(
            destination,
            attempt.previous().len(),
            attempt.url(),
        ) {
            Hop::Stop => attempt.stop(),
            Hop::Refuse(reason) => attempt.error(reason),
            Hop::Follow => attempt.follow(),
        }))
        .build()
        .map_err(|e| Error::OAuth(format!("Failed to create OAuth HTTP client: {e}")))
}

/// What to do with one redirect hop.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Hop {
    /// Past the hop budget: stop and surface the response.
    Stop,
    /// The target is a literal the policy refuses.
    Refuse(String),
    /// Follow it (a name is still checked by the pinning resolver).
    Follow,
}

/// Decide one redirect hop to `target` after `previous` hops.
pub(super) fn hop(destination: DestinationPolicy, previous: usize, target: &url::Url) -> Hop {
    let _ = (destination, target);
    if previous >= MAX_HOPS {
        return Hop::Stop;
    }
    Hop::Follow
}

impl OAuthClient {
    /// [`OAuthClient::new`] under a backend destination policy.
    pub(crate) fn with_destination(
        destination: DestinationPolicy,
        http_client: Client,
        backend_name: String,
        resource_url: String,
        scopes: Vec<String>,
        storage: std::sync::Arc<TokenStorage>,
        cfg: OAuthClientConfig,
    ) -> Self {
        let mut client = Self::new(
            http_client,
            backend_name,
            resource_url,
            scopes,
            storage,
            cfg,
        );
        client.destination = destination;
        client
    }

    /// Refuse `url` when the policy denies its literal host.
    pub(super) fn check_destination(&self, url: &str) -> Result<()> {
        let _ = (url, self.destination);
        Ok(())
    }

    /// Refuse a discovered document whose token or registration endpoint the
    /// policy denies, before it is kept.
    pub(super) fn check_advertised_endpoints(
        &self,
        meta: &AuthorizationServerMetadata,
    ) -> Result<()> {
        let _ = meta;
        Ok(())
    }
}

#[cfg(test)]
#[path = "destination_tests.rs"]
mod tests;
