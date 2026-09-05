// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT

//! MCP Protocol types (version 2025-11-25)

pub mod cacheable;
pub mod continuation;
pub mod era;
pub mod extensions;
pub mod headers;
mod messages;
pub mod meta;
pub mod mrtr;
mod negotiate;
pub mod param_headers;
pub mod subscriptions;
pub mod tasks;
pub mod trace;
mod types;

pub use messages::*;
pub use negotiate::*;
pub use types::*;

/// MCP Protocol version (latest)
pub const PROTOCOL_VERSION: &str = "2025-11-25";

/// Every legacy MCP protocol revision `initialize` can negotiate, newest first
/// so negotiation prefers the newest common one.
///
/// These are revisions the specification defines, and nothing else.
/// `2024-10-07` was listed here from the first negotiation commit (`e12431a0`,
/// 2026-01-26) until 4.0.0. It is not a revision the specification has ever
/// defined. It was inert for negotiation — `negotiate_version` matches exactly,
/// and no conforming client can ask for a revision that does not exist — but
/// `server/discover` publishes this list as the gateway's own statement of what
/// it speaks, which turns an unused constant into a claim.
/// `2026-07-28` is deliberately ABSENT and stays that way. The 2026-07-28
/// lifecycle scopes `initialize` to "2025-11-25 and earlier", so the
/// handshake negotiates legacy revisions only, and a modern client — which
/// states its revision in per-request `_meta` instead — does not reach it.
/// A dual-era server answers `initialize` for legacy clients and serves them
/// the negotiated legacy revision. Listing the modern revision here would
/// have a retired handshake negotiate a revision that has no handshake, and
/// `server/discover` would publish a claim only the stateless path makes
/// good. `MODERN_VERSIONS` (`protocol::meta`) carries it instead, for that
/// path, which can actually serve it.
pub const SUPPORTED_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// Negotiate the best protocol version between client and server
/// Returns the highest version supported by both parties
#[must_use]
pub fn negotiate_version(client_version: &str) -> &'static str {
    // If client requests a version we support, use it
    for &version in SUPPORTED_VERSIONS {
        if version == client_version {
            return version;
        }
    }
    // Fallback to latest version (client should handle incompatibility)
    PROTOCOL_VERSION
}

#[cfg(test)]
mod tests {
    use super::SUPPORTED_VERSIONS;
    use crate::protocol::meta::MODERN_VERSIONS;

    /// The release gate is the `server.modern_protocol` default, and only that.
    ///
    /// A reading that keeps recurring treats `2026-07-28` joining
    /// `SUPPORTED_VERSIONS` as a second half of the gate. It is not: the
    /// 2026-07-28 lifecycle scopes `initialize` to "2025-11-25 and earlier", so
    /// adding it would have a retired handshake negotiate a revision that has
    /// none. Prose said so three times and was rewritten twice; asserting it
    /// against the constants puts the check where such an edit would land.
    #[test]
    fn handshake_and_modern_path_keep_separate_version_lists() {
        assert!(
            !SUPPORTED_VERSIONS.contains(&"2026-07-28"),
            "the legacy handshake must not offer a revision that has no handshake"
        );
        assert!(
            MODERN_VERSIONS.contains(&"2026-07-28"),
            "the stateless path is what serves the modern revision"
        );
    }
}
