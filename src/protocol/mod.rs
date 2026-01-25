//! MCP Protocol types (version 2024-11-05)

mod messages;
mod types;

pub use messages::*;
pub use types::*;

/// MCP Protocol version (latest)
pub const PROTOCOL_VERSION: &str = "2024-11-05";

/// All supported MCP Protocol versions (newest first for negotiation priority)
pub const SUPPORTED_VERSIONS: &[&str] = &["2024-11-05", "2024-10-07"];

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
