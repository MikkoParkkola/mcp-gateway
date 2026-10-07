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
    let (builder, route) = match destination {
        DestinationPolicy::Configured => (Client::builder(), Route::EnvironmentProxy),
        policy @ (DestinationPolicy::Public | DestinationPolicy::Private) => (
            crate::security::ssrf::pinned_client_builder_for(policy),
            Route::Direct,
        ),
    };
    finish(builder, destination, route)
}

/// Whether a client may send through the environment's proxy.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Route {
    /// `HTTP(S)_PROXY` applies: a hop to `http://` loopback would be carried
    /// to the proxy in cleartext, so it is refused ([`OAuthClient::client_for`]
    /// sends a first request there through the direct client instead).
    EnvironmentProxy,
    /// No environment proxy: the pinned clients and [`loopback_client`].
    Direct,
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
    finish(
        Client::builder().no_proxy(),
        DestinationPolicy::Configured,
        Route::Direct,
    )
}

/// `builder` with the OAuth timeout and the redirect policy for `destination`
/// and `route`.
fn finish(
    builder: reqwest::ClientBuilder,
    destination: DestinationPolicy,
    route: Route,
) -> Result<Client> {
    builder
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::custom(move |attempt| match hop(
            destination,
            attempt.previous().len(),
            attempt.url(),
        ) {
            // `hop` let only loopback through as `http://`; through a proxy it
            // would leave the machine after all.
            Hop::Follow if route == Route::EnvironmentProxy && attempt.url().scheme() == "http" => {
                attempt.error(crate::security::ssrf::SsrfDenied::new(format!(
                    "{}: an OAuth redirect to http:// loopback would go through the \
                     environment proxy, off this machine",
                    crate::security::ssrf::SSRF_BLOCKED
                )))
            }
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
    ///
    /// A backstop as well: a cleartext URL off this machine is refused here,
    /// at send time, whatever checked it before.
    pub(super) fn client_for(&self, url: &str) -> Result<&Client> {
        if !url::Url::parse(url).is_ok_and(|u| crate::gateway::is_tls_or_loopback(&u)) {
            return Err(Error::Protocol(cleartext_refusal("endpoint")));
        }
        if !self.loopback_cleartext(url) {
            return Ok(&self.http_client);
        }
        self.loopback_client.as_ref().ok_or_else(|| {
            Error::OAuth("the unproxied loopback OAuth client is unavailable".into())
        })
    }

    /// As [`Self::client_for`], for a refresh-token request: the same route,
    /// with redirects off (MIK-8018). A followed redirect would re-send the
    /// refresh token and client secret to the target, and a connect error
    /// after a followed hop cannot be told from one before anything was sent.
    pub(super) fn refresh_client_for(&self, url: &str) -> Result<Client> {
        if !url::Url::parse(url).is_ok_and(|u| crate::gateway::is_tls_or_loopback(&u)) {
            return Err(Error::Protocol(cleartext_refusal("endpoint")));
        }
        let loopback = self.loopback_cleartext(url);
        let slot = &self.refresh_clients[usize::from(loopback)];
        if let Some(client) = slot.get() {
            return Ok(client.clone());
        }
        let builder = if loopback {
            Client::builder().no_proxy()
        } else {
            match self.destination {
                DestinationPolicy::Configured => Client::builder(),
                policy => crate::security::ssrf::pinned_client_builder_for(policy),
            }
        };
        let built = builder
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Error::OAuth(format!("Failed to create OAuth HTTP client: {e}")))?;
        Ok(slot.get_or_init(|| built).clone())
    }

    /// `http://` on a loopback host under `Configured`: the unproxied route.
    fn loopback_cleartext(&self, url: &str) -> bool {
        self.destination == DestinationPolicy::Configured
            && url::Url::parse(url).is_ok_and(|u| {
                u.scheme() == "http"
                    && crate::gateway::is_loopback_host(u.host_str().unwrap_or_default())
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
        // The authorization endpoint is where the user signs in: their own
        // password goes there, through the browser.
        self.check_destination(&meta.authorization_endpoint, "authorization_endpoint")?;
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
