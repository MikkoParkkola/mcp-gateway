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

/// Every MCP protocol revision this gateway speaks, newest first so negotiation
/// prefers the newest common one.
///
/// These are revisions the specification defines, and nothing else.
/// `2024-10-07` was listed here from the first negotiation commit (`e12431a0`,
/// 2026-01-26) until 4.0.0. It is not a revision the specification has ever
/// defined. It was inert for negotiation — `negotiate_version` matches exactly,
/// and no conforming client can ask for a revision that does not exist — but
/// `server/discover` publishes this list as the gateway's own statement of what
/// it speaks, which turns an unused constant into a claim.
/// `2026-07-28` is deliberately ABSENT and stays that way. The 2026-07-28
/// lifecycle scopes `initialize` to "2025-11-25 and earlier", so a modern
/// client never sends it — the same page records a modern client against a
/// legacy server failing because `initialize` is an unrecognised method. A
/// dual-era server answers `initialize` only for legacy clients and serves them
/// the negotiated legacy revision. Listing the modern revision here would have
/// a retired handshake negotiate a revision that has none, and the client would
/// be told yes and then served 2025 semantics — a worse failure than refusing,
/// because it is silent. `MODERN_VERSIONS` (`protocol::meta`) carries it
/// instead, for the stateless path that can actually serve it.
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
