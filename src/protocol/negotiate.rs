//! Protocol version negotiation helpers.
//!
//! Shared logic for negotiating MCP protocol versions between the gateway
//! (client) and backend servers. Used by both stdio and HTTP transports.

use super::SUPPORTED_VERSIONS;
use tracing::debug;

/// Parse supported protocol versions from an MCP error message.
///
/// Common formats:
/// - `"Unsupported protocol version: 2025-11-25. Supported versions: 2025-06-18, 2025-03-26"`
/// - `"Bad Request: Unsupported protocol version (supported versions: 2025-06-18)"`
/// - `"supported: 2025-06-18, 2024-11-05"`
#[must_use]
pub fn parse_supported_versions_from_error(error_msg: &str) -> Option<Vec<String>> {
    let lower = error_msg.to_lowercase();
    let patterns = ["supported versions:", "supported:"];

    for pattern in &patterns {
        if let Some(start) = lower.find(pattern) {
            let rest = &error_msg[start + pattern.len()..];

            // Extract until closing paren or end of string
            let rest = rest.find(')').map_or(rest, |end| &rest[..end]);

            let versions: Vec<String> = rest
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            if !versions.is_empty() {
                return Some(versions);
            }
        }
    }

    None
}

/// Find the highest protocol version supported by both gateway and server.
///
/// Iterates `SUPPORTED_VERSIONS` (newest first) and returns the first match.
#[must_use]
pub fn negotiate_best_version(server_versions: &[String]) -> Option<&'static str> {
    for &client_version in SUPPORTED_VERSIONS {
        if server_versions.iter().any(|v| v == client_version) {
            debug!(
                negotiated = client_version,
                "Found compatible protocol version"
            );
            return Some(client_version);
        }
    }
    None
}

/// Check if an error message indicates a protocol version mismatch.
#[must_use]
pub fn is_version_mismatch_error(error_msg: &str) -> bool {
    let lower = error_msg.to_lowercase();
    lower.contains("unsupported protocol version")
        || lower.contains("protocol version")
        || lower.contains("version not supported")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_supported_versions_from_error ──────────────────────────────────

    #[test]
    fn parse_rust_mcp_sdk_format() {
        let msg = "Unsupported protocol version: 2025-11-25. Supported versions: 2025-06-18, 2025-03-26, 2024-11-05";
        let versions = parse_supported_versions_from_error(msg).unwrap();
        assert_eq!(versions, vec!["2025-06-18", "2025-03-26", "2024-11-05"]);
    }

    #[test]
    fn parse_parenthesized_format() {
        let msg = "Bad Request: Unsupported protocol version (supported versions: 2025-06-18, 2024-11-05)";
        let versions = parse_supported_versions_from_error(msg).unwrap();
        assert_eq!(versions, vec!["2025-06-18", "2024-11-05"]);
    }

    #[test]
    fn parse_short_format() {
        let msg = "supported: 2025-06-18";
        let versions = parse_supported_versions_from_error(msg).unwrap();
        assert_eq!(versions, vec!["2025-06-18"]);
    }

    #[test]
    fn parse_no_match_returns_none() {
        let msg = "Some unrelated error message";
        assert!(parse_supported_versions_from_error(msg).is_none());
    }

    #[test]
    fn parse_case_insensitive() {
        let msg = "SUPPORTED VERSIONS: 2025-06-18";
        let versions = parse_supported_versions_from_error(msg).unwrap();
        assert_eq!(versions, vec!["2025-06-18"]);
    }

    // ── negotiate_best_version ───────────────────────────────────────────────

    #[test]
    fn negotiate_picks_highest_mutual_version() {
        let server = vec![
            "2024-11-05".to_string(),
            "2025-03-26".to_string(),
            "2025-06-18".to_string(),
        ];
        assert_eq!(negotiate_best_version(&server), Some("2025-06-18"));
    }

    #[test]
    fn negotiate_picks_only_common_version() {
        let server = vec!["2024-10-07".to_string()];
        assert_eq!(negotiate_best_version(&server), Some("2024-10-07"));
    }

    #[test]
    fn negotiate_no_match_returns_none() {
        let server = vec!["1999-01-01".to_string()];
        assert!(negotiate_best_version(&server).is_none());
    }

    // ── is_version_mismatch_error ────────────────────────────────────────────

    #[test]
    fn detects_unsupported_protocol_version() {
        assert!(is_version_mismatch_error(
            "Unsupported protocol version: 2025-11-25"
        ));
    }

    #[test]
    fn detects_generic_protocol_version_error() {
        assert!(is_version_mismatch_error("protocol version mismatch"));
    }

    #[test]
    fn ignores_unrelated_error() {
        assert!(!is_version_mismatch_error("Method not found"));
    }
}
