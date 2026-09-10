// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

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

            // Shape-filtered, not merely non-empty. Everything here is
            // backend-controlled text: without a closing paren `rest` runs to
            // the end of the body, so a token can be trailing JSON syntax, an
            // error page, or a credential the gateway itself sent and the
            // backend quoted back. A caller that puts these in a diagnostic
            // must be handed version tokens or nothing.
            let versions: Vec<String> = rest
                .split(',')
                // Trimmed to digits at both ends: a version at the end of a
                // JSON body arrives wearing the object's syntax
                // (`2025-06-18"}`), and whatever survives the trim can still
                // only be the version characters themselves.
                .map(|s| s.trim_matches(|c: char| !c.is_ascii_digit()))
                .filter(|s| is_version_token(s))
                .map(str::to_string)
                .collect();

            if !versions.is_empty() {
                return Some(versions);
            }
        }
    }

    None
}

/// Is this a protocol version as the spec writes them -- a four-digit year,
/// month and day, hyphen separated?
///
/// Deliberately structural rather than a membership test against
/// `SUPPORTED_VERSIONS`: a backend naming a version this gateway does not speak
/// is information the operator needs, while a backend naming anything that is
/// not a version at all is text nobody may repeat.
fn is_version_token(token: &str) -> bool {
    token.len() == 10
        && token.bytes().enumerate().all(|(index, byte)| match index {
            4 | 7 => byte == b'-',
            _ => byte.is_ascii_digit(),
        })
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

    /// A JSON rejection body with no closing paren: the scan runs to the end
    /// of the body, so the last token arrives wearing the object's syntax.
    #[test]
    fn json_syntax_after_the_last_version_is_not_a_version() {
        let msg = r#"{"error":{"message":"Unsupported protocol version. supported versions: 2025-06-18"},"id":null}"#;
        let versions = parse_supported_versions_from_error(msg).expect("a version list");
        assert_eq!(versions, vec!["2025-06-18"]);
    }

    /// Why the filter exists: everything past the marker is backend-controlled
    /// text, and a backend has been known to quote back material the gateway
    /// sent it. A caller may repeat version tokens and nothing else.
    #[test]
    fn backend_text_after_the_marker_is_not_carried() {
        let msg = "Unsupported protocol version. supported: 2025-06-18, whatever-the-backend-chose-to-echo";
        let versions = parse_supported_versions_from_error(msg).expect("a version list");
        assert_eq!(versions, vec!["2025-06-18"]);
    }

    /// A body that names no version at all yields nothing, so a proxy error
    /// page cannot be mistaken for a negotiation invitation.
    #[test]
    fn a_marker_with_no_version_yields_nothing() {
        let msg = "Gateway timeout. supported: please contact your administrator";
        assert!(parse_supported_versions_from_error(msg).is_none());
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
        let server = vec!["2024-11-05".to_string()];
        assert_eq!(negotiate_best_version(&server), Some("2024-11-05"));
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
