// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Where a configured backend connection may go (`security.posture`).
//!
//! `Configured` is the `standard` behaviour: the operator's backend URLs are
//! trusted and connected as written. `Public` is `hardened`: every address a
//! backend connection reaches must clear the deny list, so hostnames are
//! resolved once and pinned (`pinned_client_builder`), and IP literals, which
//! never reach a resolver, are checked by [`DestinationPolicy::check_literal`]
//! wherever a URL is about to be used: transport start, and every URL an
//! OAuth authorization server advertises (its base, token and registration
//! endpoints, and every redirect hop). A new OAuth fetch joins that list.
//!
//! `Private` is `hardened` for a backend named in
//! `security.hardened.private_backends`: as `Public`, except that loopback,
//! RFC 1918 and unique-local addresses are reachable. Link-local, and
//! the cloud metadata addresses, never are. Every check asks [`DestinationPolicy::denies`].

use std::net::IpAddr;

use crate::security::posture::SecurityPosture;
use crate::{Error, Result};

/// Destination policy for one backend's outbound connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DestinationPolicy {
    /// Connect as configured; nothing pinned (`standard`).
    Configured,
    /// Only public addresses; names pinned, literals checked (`hardened`).
    Public,
    /// As `Public`, plus loopback, RFC 1918 and unique-local (`hardened`, a
    /// backend listed in `security.hardened.private_backends`).
    Private,
}

impl DestinationPolicy {
    /// The policy a posture puts on configured backends.
    pub(crate) fn for_posture(posture: SecurityPosture) -> Self {
        match posture {
            SecurityPosture::Hardened => Self::Public,
            _ => Self::Configured,
        }
    }

    /// Whether a connection under this policy may not reach `addr`.
    pub(crate) fn denies(self, addr: IpAddr) -> bool {
        // RED STUB: `Private` behaves as `Public` until 4c lands.
        match self {
            Self::Configured => false,
            Self::Public | Self::Private => super::is_private_or_reserved(addr),
        }
    }

    /// Refuse `url` when its host is an IP literal this policy denies.
    /// A hostname passes: the pinning resolver checks what it resolves to.
    ///
    /// # Errors
    ///
    /// `Error::Protocol("SSRF blocked: ...")` (-32600).
    pub(crate) fn check_literal(self, url: &url::Url) -> Result<()> {
        let Some(host) = url.host_str() else {
            return Ok(());
        };
        match host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
        {
            Ok(addr) if self.denies(addr) => Err(Error::Protocol(format!(
                "SSRF blocked: host targets private/reserved address {addr}"
            ))),
            _ => Ok(()),
        }
    }
}

impl DestinationPolicy {
    /// The proxy-time check of a configured backend URL (with
    /// `trust_configured_backends` off). A backend listed in
    /// `security.hardened.private_backends` is held to its own policy, or it
    /// would connect and then have every call refused; every other backend
    /// keeps the full URL validation.
    ///
    /// # Errors
    ///
    /// `Error::Protocol("SSRF blocked: ...")` (-32600), or an invalid URL.
    pub(crate) fn check_configured_url(self, url: &str) -> Result<()> {
        // RED STUB: every backend keeps the full validation until 4c lands.
        let _ = self;
        super::validate_url_not_ssrf(url)
    }
}

#[cfg(test)]
#[path = "destination_tests.rs"]
mod tests;
