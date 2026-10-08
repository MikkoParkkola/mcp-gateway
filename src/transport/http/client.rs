// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The backend HTTP transport's client.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use reqwest::Client;
use url::Url;

use super::{RedirectDecision, evaluate_redirect_for};
use crate::security::ssrf::DestinationPolicy;
use crate::{Error, Result};

/// A pooled client whose every redirect passes [`evaluate_redirect_for`].
///
/// Under [`DestinationPolicy::Public`] it starts from the pinned builder:
/// each name is resolved once and checked, and `HTTP(S)_PROXY` from the
/// environment is ignored, since a proxy would resolve the name instead.
///
/// An `http://` loopback origin is never proxied under any policy: cleartext
/// (an OAuth bearer included) is allowed there only because it never leaves
/// the machine, and an inherited `HTTP_PROXY` would carry it off.
pub(crate) fn build(
    base_origin: Url,
    timeout: Duration,
    destination: DestinationPolicy,
    redirects_followed: Arc<AtomicU64>,
) -> Result<Client> {
    let loopback_cleartext = base_origin.scheme() == "http"
        && crate::gateway::is_loopback_host(base_origin.host_str().unwrap_or_default());
    let builder = match destination {
        DestinationPolicy::Configured if loopback_cleartext => Client::builder().no_proxy(),
        DestinationPolicy::Configured => Client::builder(),
        policy @ (DestinationPolicy::Public | DestinationPolicy::Private) => {
            crate::security::ssrf::pinned_client_builder_for(policy)
        }
    };
    builder
        .timeout(timeout)
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Duration::from_secs(30))
        .tcp_nodelay(true)
        .redirect(reqwest::redirect::Policy::custom(
            move |attempt| match evaluate_redirect_for(
                destination,
                &base_origin,
                attempt.url(),
                attempt.previous().len(),
            ) {
                RedirectDecision::Stop => attempt.stop(),
                RedirectDecision::Reject(msg) => attempt.error(msg),
                RedirectDecision::Follow => {
                    redirects_followed.fetch_add(1, Ordering::SeqCst);
                    attempt.follow()
                }
            },
        ))
        .build()
        .map_err(|e| Error::Transport(e.to_string()))
}
