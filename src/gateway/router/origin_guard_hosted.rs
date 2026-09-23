// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The hosted consent journey's two openings in the origin guard (MIK-6745
//! design §6.4). Neither applies outside `/accounts/v1/`: without that bound
//! `/mcp` would become reachable on the Open `WebUI` origin.

use axum::http::{HeaderMap, Method};

use super::super::accounts::CALLBACK;
use super::{same_origin, strip_port};
use crate::config::Config;

const PREFIX: &str = "/accounts/v1/";

/// `accounts.hosted.public_origin`, lower-cased as `public_url_parts` does.
#[derive(Clone)]
pub(super) struct HostedOrigin {
    host: String,
    origin: String,
}

impl HostedOrigin {
    /// Snapshotted from the startup config, the same one that mounts routes.
    pub(super) fn from_config(config: &Config) -> Option<Self> {
        let hosted = config.accounts.as_ref()?.hosted.as_ref()?;
        let url = url::Url::parse(&hosted.public_origin).ok()?;
        Some(Self {
            host: url.host_str()?.to_ascii_lowercase(),
            origin: url.origin().ascii_serialization().to_ascii_lowercase(),
        })
    }
}

/// What one request may use of the hosted opening.
pub(super) struct HostedScope<'a> {
    origin: Option<&'a HostedOrigin>,
    navigation: bool,
}

/// The scope for one request: the hosted origin only under the prefix, and
/// the callback navigation only for the exact top-level document GET.
pub(super) fn scope<'a>(
    hosted: Option<&'a HostedOrigin>,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
) -> HostedScope<'a> {
    let origin = hosted.filter(|_| path.starts_with(PREFIX));
    let header_is = |name: &str, want: &str| {
        headers
            .get(name)
            .is_some_and(|value| value.as_bytes() == want.as_bytes())
    };
    let navigation = origin.is_some()
        && method == Method::GET
        && path == CALLBACK
        && header_is("sec-fetch-mode", "navigate")
        && header_is("sec-fetch-dest", "document");
    HostedScope { origin, navigation }
}

impl HostedScope<'_> {
    /// `Host` names the hosted origin, under the prefix.
    pub(super) fn admits_host(&self, host: &str) -> bool {
        self.origin
            .is_some_and(|hosted| hosted.host.eq_ignore_ascii_case(strip_port(host)))
    }

    /// `Origin` is the hosted origin, under the prefix (same-origin `DELETE`
    /// from the completion page).
    pub(super) fn admits_origin(&self, origin: &str) -> bool {
        let candidate = origin.trim_end_matches('/').to_ascii_lowercase();
        self.origin
            .is_some_and(|hosted| same_origin(&hosted.origin, &candidate))
    }

    /// The provider's cross-site redirect back, addressed to the hosted host.
    /// Every other cross-site request keeps today's refusal.
    pub(super) fn exempts_fetch_site(&self, authority: Option<&str>) -> bool {
        self.navigation && authority.is_some_and(|authority| self.admits_host(authority))
    }
}
