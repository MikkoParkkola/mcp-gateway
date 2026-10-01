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

use crate::Result;
use crate::security::posture::SecurityPosture;

/// Destination policy for one backend's outbound connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DestinationPolicy {
    /// Connect as configured; nothing pinned (`standard`).
    Configured,
    /// Only public addresses; names pinned, literals checked (`hardened`).
    Public,
}

impl DestinationPolicy {
    /// The policy a posture puts on configured backends.
    pub(crate) fn for_posture(posture: SecurityPosture) -> Self {
        match posture {
            SecurityPosture::Hardened => Self::Public,
            _ => Self::Configured,
        }
    }

    /// Refuse `url` when its host is an IP literal this policy denies.
    /// A hostname passes: the pinning resolver checks what it resolves to.
    ///
    /// # Errors
    ///
    /// `Error::Protocol("SSRF blocked: ...")` (-32600).
    pub(crate) fn check_literal(self, url: &url::Url) -> Result<()> {
        match (self, url.host_str()) {
            (Self::Public, Some(host)) => super::check_host_not_ssrf(host),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
#[path = "destination_tests.rs"]
mod tests;
