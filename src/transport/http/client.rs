// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The backend HTTP transport's client.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use reqwest::Client;
use url::Url;

use super::{RedirectDecision, evaluate_redirect};
use crate::security::ssrf::DestinationPolicy;
use crate::{Error, Result};

/// A pooled client whose every redirect passes [`evaluate_redirect`].
///
/// Under [`DestinationPolicy::Public`] it starts from the pinned builder:
/// each name is resolved once and checked, and `HTTP(S)_PROXY` from the
/// environment is ignored, since a proxy would resolve the name instead.
pub(super) fn build(
    base_origin: Url,
    timeout: Duration,
    destination: DestinationPolicy,
    redirects_followed: Arc<AtomicU64>,
) -> Result<Client> {
    let builder = match destination {
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
            move |attempt| match evaluate_redirect(
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
