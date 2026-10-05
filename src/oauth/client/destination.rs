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
    let builder = match destination {
        DestinationPolicy::Configured => Client::builder(),
        policy @ (DestinationPolicy::Public | DestinationPolicy::Private) => {
            crate::security::ssrf::pinned_client_builder_for(policy)
        }
    };
    finish(builder, destination)
}

/// The client a `Configured` OAuth client uses for `http://` on a loopback
/// host (#3007's rule, per request: the authorization server is known only
/// after discovery). Never proxied: an inherited `HTTP_PROXY` would carry the
/// client secret or refresh token off the machine in cleartext.
///
/// # Errors
///
/// `Error::OAuth` if the client cannot be built.
pub(super) fn loopback_client() -> Result<Client> {
    finish(Client::builder().no_proxy(), DestinationPolicy::Configured)
}

/// `builder` with the OAuth timeout and the redirect policy for `destination`.
fn finish(builder: reqwest::ClientBuilder, destination: DestinationPolicy) -> Result<Client> {
    builder
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::custom(move |attempt| match hop(
            destination,
            attempt.previous().len(),
            attempt.url(),
        ) {
            // As reqwest's default policy: too many redirects is an error.
            Hop::Stop => attempt.error("too many redirects"),
            // Typed as the resolver's refusal, so every send site maps it to
            // `-32600 SSRF blocked` rather than a generic OAuth failure.
            Hop::Refuse(reason) => attempt.error(crate::security::ssrf::SsrfDenied::new(reason)),
            Hop::Follow => attempt.follow(),
        }))
        .build()
        .map_err(|e| Error::OAuth(format!("Failed to create OAuth HTTP client: {e}")))
}

/// What to do with one redirect hop.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Hop {
    /// Past the hop budget: refuse, as reqwest's default policy does.
    Stop,
    /// The target is a literal the policy refuses.
    Refuse(String),
    /// Follow it (a name is still checked by the pinning resolver).
    Follow,
}

/// Decide one redirect hop to `target` after `previous` hops.
pub(super) fn hop(destination: DestinationPolicy, previous: usize, target: &url::Url) -> Hop {
    if previous >= MAX_HOPS {
        return Hop::Stop;
    }
    // Under every policy: a 307/308 re-POSTs the client secret or refresh
    // token, so a hop is held to the rule its first request was.
    if !crate::gateway::is_tls_or_loopback(target) {
        return Hop::Refuse(cleartext_refusal("redirect target"));
    }
    // The bare "SSRF blocked: ..." message, not the error's Display, which
    // adds a "Protocol error: " prefix the refusal would then carry twice.
    destination
        .literal_refusal(target)
        .map_or(Hop::Follow, Hop::Refuse)
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

    /// The client for a request to `url`: under `Configured`, `http://` on a
    /// loopback host goes through the unproxied [`loopback_client`]. The other
    /// policies' pinned client ignores the environment's proxy already.
    pub(super) fn client_for(&self, url: &str) -> Result<&Client> {
        let loopback_cleartext = self.destination == DestinationPolicy::Configured
            && url::Url::parse(url).is_ok_and(|u| {
                u.scheme() == "http"
                    && crate::gateway::is_loopback_host(u.host_str().unwrap_or_default())
            });
        if !loopback_cleartext {
            return Ok(&self.http_client);
        }
        self.loopback_client.as_ref().ok_or_else(|| {
            Error::OAuth("the unproxied loopback OAuth client is unavailable".into())
        })
    }

    /// Refuse `url`, the authorization server's `what`, when it is cleartext
    /// off this machine (under every policy: it carries the client secret, a
    /// code or a refresh token, or decides where they go), or when the policy
    /// denies its literal host.
    ///
    /// The refusal is the destination-policy one, so no fallback walks past it
    /// (MIK-7701): not the resource-metadata fallback, not re-authorization,
    /// not background renewal.
    pub(super) fn check_destination(&self, url: &str, what: &str) -> Result<()> {
        let parsed =
            url::Url::parse(url).map_err(|e| Error::OAuth(format!("Invalid OAuth URL: {e}")))?;
        if !crate::gateway::is_tls_or_loopback(&parsed) {
            return Err(Error::Protocol(cleartext_refusal(what)));
        }
        if self.destination == DestinationPolicy::Configured {
            return Ok(());
        }
        self.destination.check_literal(&parsed)
    }

    /// Refuse a discovered document whose token or registration endpoint the
    /// policy denies, before it is kept.
    pub(super) fn check_advertised_endpoints(
        &self,
        meta: &AuthorizationServerMetadata,
    ) -> Result<()> {
        self.check_destination(&meta.token_endpoint, "token_endpoint")?;
        match &meta.registration_endpoint {
            Some(registration) => self.check_destination(registration, "registration_endpoint"),
            None => Ok(()),
        }
    }
}

/// The refusal for a cleartext OAuth URL off this machine. It names the
/// endpoint, never the URL: the URL came from a document the backend served.
fn cleartext_refusal(what: &str) -> String {
    format!(
        "{}: OAuth {what} is cleartext http:// to a host off this machine; the \
         authorization server must use https:// (or http:// on a loopback host)",
        crate::security::ssrf::SSRF_BLOCKED
    )
}

#[cfg(test)]
#[path = "destination_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "cleartext_tests.rs"]
mod cleartext_tests;
