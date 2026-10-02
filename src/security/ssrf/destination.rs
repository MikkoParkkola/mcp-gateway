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
//! [`ALWAYS_DENIED`], never are. Every check asks [`DestinationPolicy::denies`].

use std::net::{IpAddr, Ipv6Addr};

use crate::security::posture::SecurityPosture;
use crate::{Error, Result};

/// Never reachable, even inside a range `Private` allows: the AWS IPv6
/// instance-metadata service, inside `fc00::/7` (operator decision 8).
pub(crate) const ALWAYS_DENIED: [IpAddr; 1] = [IpAddr::V6(Ipv6Addr::new(
    0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254,
))];

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
        match self {
            Self::Configured => false,
            Self::Public => super::is_private_or_reserved(addr),
            Self::Private => {
                ALWAYS_DENIED.contains(&addr)
                    || (super::is_private_or_reserved(addr) && !private_reachable(addr))
            }
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
                "SSRF blocked: host targets {}",
                super::denied_address(addr)
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
        match self {
            Self::Private => {
                let parsed = url::Url::parse(url)
                    .map_err(|e| Error::Protocol(format!("SSRF check: invalid URL: {e}")))?;
                if parsed.host_str().is_none() {
                    return Err(Error::Protocol("SSRF check: URL has no host".to_string()));
                }
                self.check_literal(&parsed)
            }
            Self::Configured | Self::Public => super::validate_url_not_ssrf(url),
        }
    }
}

/// What `Private` reaches beyond `Public`: loopback, RFC 1918 and unique-local.
/// Only an IPv4-mapped address is judged by the IPv4 it embeds; every other
/// encoding (compatible, NAT64, 6to4, Teredo) stays denied.
fn private_reachable(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.is_loopback() || v4.is_private(),
            None => v6.is_loopback() || v6.segments()[0] & 0xFE00 == 0xFC00,
        },
    }
}

#[cfg(test)]
#[path = "destination_tests.rs"]
mod tests;
