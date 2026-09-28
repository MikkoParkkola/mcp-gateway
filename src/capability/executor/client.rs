// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The executor's HTTP client: direct and pinned, or through the operator's
//! `capabilities.egress_proxy` (#1881).

use std::time::Duration;

use reqwest::Client;

use crate::security::validate_url_not_ssrf;

/// Build a pooled HTTP client suitable for capability execution.
///
/// Matches the pooling parameters used by `HttpTransport` so all outbound HTTP
/// shares the same connection-management strategy and avoids per-request FD
/// creation.
///
/// With no `proxy`, every name is resolved once and pinned (MIK-4019) and
/// `HTTP(S)_PROXY` from the environment is ignored, since a proxy would
/// resolve the name instead of the pin. With a `proxy`, every call goes to it
/// and the proxy resolves destinations: the pin is not installed, because it
/// would refuse the proxy itself on the private address a proxy normally has.
/// Each redirect hop is literal-checked either way.
///
/// # Panics
///
/// Panics if the reqwest client cannot be created (invalid TLS config, etc.).
pub(super) fn build(proxy: Option<&url::Url>) -> Client {
    let builder = match proxy {
        None => crate::security::ssrf::pinned_client_builder(),
        Some(url) => Client::builder().no_proxy().proxy(
            reqwest::Proxy::all(url.as_str()).expect("capabilities.egress_proxy validated at load"),
        ),
    };
    builder
        .timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 {
                return attempt.stop();
            }
            if let Err(e) = validate_url_not_ssrf(attempt.url().as_str()) {
                return attempt.error(e.to_string());
            }
            attempt.follow()
        }))
        .build()
        .expect("Failed to create HTTP client")
}
