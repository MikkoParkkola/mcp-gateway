//! Per-agent identity verification (OWASP ASI03 — Identity and Privilege Abuse).
//!
//! Closes the gap where any valid session token grants the same access regardless
//! of which agent is calling.  This module provides identity *plumbing*: extraction,
//! optional enforcement, and structured audit logging.  Full IAM is out of scope.
//!
//! # Extraction precedence
//!
//! 1. `X-Agent-ID` HTTP header (preferred — explicit, simple to set in any client).
//! 2. `agent_id` JWT claim in the `Authorization: Bearer <jwt>` token (when the
//!    token is a decodable JWT; unsigned/opaque tokens are silently skipped).
//! 3. `agent_id` query parameter (lowest precedence; convenient for debugging).
//!
//! # Configuration
//!
//! ```yaml
//! security:
//!   agent_identity:
//!     enabled: false       # opt-in; extraction is a no-op when false
//!     require_id: false    # when true, requests without an agent_id are rejected
//!     known_agents: []     # optional allowlist of accepted agent IDs
//! ```
//!
//! When `known_agents` is non-empty and `require_id` is true, only listed agents
//! are accepted.  When `known_agents` is empty the allowlist check is skipped.

use serde::{Deserialize, Serialize};

// ── Configuration ─────────────────────────────────────────────────────────────

/// Per-agent identity configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AgentIdentityConfig {
    /// Enable agent identity extraction and enforcement.  Default: `false`.
    pub enabled: bool,
    /// When `true`, requests without a resolvable `agent_id` are rejected.
    /// Only meaningful when `enabled = true`.  Default: `false`.
    pub require_id: bool,
    /// Optional allowlist of accepted agent IDs.
    ///
    /// When non-empty and `require_id = true`, any `agent_id` not in this list
    /// is rejected.  When empty the allowlist check is skipped entirely.
    #[serde(default)]
    pub known_agents: Vec<String>,
}

// ── AgentIdentity ─────────────────────────────────────────────────────────────

/// Resolved identity for the calling agent.
///
/// Extracted from one of: `X-Agent-ID` header, JWT `agent_id` claim, or
/// `agent_id` query parameter.  Carried as request extension through the
/// dispatch pipeline and recorded in every tool-invocation audit log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIdentity {
    /// Caller-supplied agent identifier (not authenticated — treat as a label,
    /// not a security principal, unless combined with mTLS or JWT verification).
    pub id: String,
    /// Source from which the identity was extracted (for audit traceability).
    pub source: IdentitySource,
}

/// Origin of the extracted agent identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentitySource {
    /// Extracted from the `X-Agent-ID` HTTP header.
    Header,
    /// Extracted from the `agent_id` claim in a JWT bearer token.
    JwtClaim,
    /// Extracted from the `agent_id` query parameter.
    QueryParam,
}

impl std::fmt::Display for IdentitySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Header => f.write_str("header"),
            Self::JwtClaim => f.write_str("jwt_claim"),
            Self::QueryParam => f.write_str("query_param"),
        }
    }
}

// ── Extraction ────────────────────────────────────────────────────────────────

/// Extract an agent identity from the request's HTTP headers and optional query string.
///
/// Returns `None` when no agent identity is present.  Extraction order:
/// 1. `X-Agent-ID` header
/// 2. `agent_id` JWT claim (unsigned decode only — no signature verification here)
/// 3. `agent_id` query parameter
///
/// Empty strings are treated as absent.
#[must_use]
pub fn extract_agent_identity(
    headers: &axum::http::HeaderMap,
    query: Option<&str>,
    bearer_token: Option<&str>,
) -> Option<AgentIdentity> {
    // 1. X-Agent-ID header (highest precedence)
    if let Some(id) = extract_from_header(headers) {
        return Some(AgentIdentity {
            id,
            source: IdentitySource::Header,
        });
    }

    // 2. JWT claim (no-op on opaque tokens)
    if let Some(id) = bearer_token.and_then(extract_jwt_agent_id) {
        return Some(AgentIdentity {
            id,
            source: IdentitySource::JwtClaim,
        });
    }

    // 3. Query parameter (lowest precedence)
    if let Some(id) = query.and_then(extract_from_query) {
        return Some(AgentIdentity {
            id,
            source: IdentitySource::QueryParam,
        });
    }

    None
}

/// Validate an optional identity against the config.
///
/// Returns `Ok(())` when:
/// - `config.enabled` is `false` (feature disabled — pass-through).
/// - Identity is present and (if `known_agents` is non-empty) is in the allowlist.
/// - `require_id` is `false` and identity is absent.
///
/// Returns `Err(reason)` when:
/// - `require_id` is `true` and no identity was extracted.
/// - `known_agents` is non-empty and the identity is not in the list.
pub fn validate_agent_identity(
    identity: Option<&AgentIdentity>,
    config: &AgentIdentityConfig,
) -> Result<(), String> {
    if !config.enabled {
        return Ok(());
    }

    let Some(identity) = identity else {
        if config.require_id {
            return Err(
                "Request rejected: agent_identity.require_id is true but no agent ID was \
                 provided. Set the X-Agent-ID header."
                    .to_string(),
            );
        }
        return Ok(());
    };

    if !config.known_agents.is_empty() && !config.known_agents.contains(&identity.id) {
        return Err(format!(
            "Agent '{}' is not in the known_agents allowlist",
            identity.id
        ));
    }

    Ok(())
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn extract_from_header(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("x-agent-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

/// Decode a JWT payload without verifying the signature and extract `agent_id`.
///
/// This is intentionally unsigned-only: identity is extracted for *audit*,
/// not for authorization.  Cryptographic verification is left to the JWT
/// middleware layer (key server / OAuth) which runs before this code.
fn extract_jwt_agent_id(token: &str) -> Option<String> {
    // JWT structure: header.payload.signature — payload is base64url(JSON)
    let payload_b64 = token.split('.').nth(1)?;
    let decoded = base64_url_decode(payload_b64)?;
    let json: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    json.get("agent_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
}

fn extract_from_query(query: &str) -> Option<String> {
    query
        .split('&')
        .find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k == "agent_id").then_some(v)
        })
        .filter(|s| !s.is_empty())
        .map(percent_decode)
}

/// Minimal base64url decoder (no padding required — standard JWT payloads omit it).
fn base64_url_decode(input: &str) -> Option<Vec<u8>> {
    use std::collections::VecDeque;

    // Convert base64url → base64 standard
    let mut b64: String = input.replace('-', "+").replace('_', "/");
    // Re-add padding
    match b64.len() % 4 {
        2 => b64.push_str("=="),
        3 => b64.push('='),
        _ => {}
    }

    // Manual base64 decode to avoid adding a dependency
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    #[allow(clippy::cast_possible_truncation)] // alphabet has exactly 64 entries; i ≤ 63 < u8::MAX
    let decode_table: [u8; 256] = {
        let mut t = [0xFFu8; 256];
        for (i, &c) in alphabet.iter().enumerate() {
            t[c as usize] = i as u8;
        }
        t['=' as usize] = 0;
        t
    };

    let bytes = b64.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf = VecDeque::new();

    for &byte in bytes {
        let val = decode_table[byte as usize];
        if val == 0xFF {
            return None; // invalid character
        }
        buf.push_back(val);
        if buf.len() == 4 {
            let (b0, b1, b2, b3) = (
                buf.pop_front().unwrap(),
                buf.pop_front().unwrap(),
                buf.pop_front().unwrap(),
                buf.pop_front().unwrap(),
            );
            out.push((b0 << 2) | (b1 >> 4));
            out.push((b1 << 4) | (b2 >> 2));
            out.push((b2 << 6) | b3);
        }
    }

    Some(out)
}

/// Percent-decode a query parameter value (`%XX` sequences only; `+` kept as-is).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2]))
        {
            out.push((hi << 4 | lo) as char);
            i += 3;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use axum::http::HeaderMap;

    use super::*;

    // ── extract_agent_identity ────────────────────────────────────────────────

    #[test]
    fn extract_from_x_agent_id_header() {
        // GIVEN: request with X-Agent-ID header
        let mut headers = HeaderMap::new();
        headers.insert("x-agent-id", "agent-abc-123".parse().unwrap());
        // WHEN: extract identity
        let identity = extract_agent_identity(&headers, None, None);
        // THEN: identity is extracted from header
        assert_eq!(
            identity,
            Some(AgentIdentity {
                id: "agent-abc-123".to_string(),
                source: IdentitySource::Header,
            })
        );
    }

    #[test]
    fn extract_no_agent_id_returns_none() {
        // GIVEN: request with no agent identification
        let headers = HeaderMap::new();
        // WHEN: extract identity
        let identity = extract_agent_identity(&headers, None, None);
        // THEN: no identity
        assert_eq!(identity, None);
    }

    #[test]
    fn extract_from_query_param() {
        // GIVEN: request with agent_id query parameter
        let headers = HeaderMap::new();
        // WHEN: extract identity from query string
        let identity = extract_agent_identity(&headers, Some("agent_id=agent-q1&other=val"), None);
        // THEN: identity extracted from query
        assert_eq!(
            identity,
            Some(AgentIdentity {
                id: "agent-q1".to_string(),
                source: IdentitySource::QueryParam,
            })
        );
    }

    #[test]
    fn extract_header_takes_precedence_over_query() {
        // GIVEN: both header and query param set
        let mut headers = HeaderMap::new();
        headers.insert("x-agent-id", "header-agent".parse().unwrap());
        // WHEN: extract identity
        let identity = extract_agent_identity(&headers, Some("agent_id=query-agent"), None);
        // THEN: header wins
        let resolved = identity.unwrap();
        assert_eq!(resolved.source, IdentitySource::Header);
        assert_eq!(resolved.id, "header-agent");
    }

    #[test]
    fn extract_whitespace_only_header_returns_none() {
        // GIVEN: X-Agent-ID header with only whitespace (trimmed to empty by our logic)
        let mut headers = HeaderMap::new();
        headers.insert("x-agent-id", "   ".parse().unwrap());
        // WHEN: extract
        let identity = extract_agent_identity(&headers, None, None);
        // THEN: treated as absent (our extractor trims and rejects blank values)
        assert_eq!(identity, None);
    }

    #[test]
    fn extract_from_jwt_claim() {
        // GIVEN: a JWT with agent_id claim (header.payload.signature)
        // payload = {"agent_id": "agent-jwt-1", "sub": "test"}
        let payload = r#"{"agent_id":"agent-jwt-1","sub":"test"}"#;
        let b64 = to_base64url(payload.as_bytes());
        let token = format!("eyJhbGciOiJub25lIn0.{b64}.signature");
        let headers = HeaderMap::new();
        // WHEN: extract identity
        let identity = extract_agent_identity(&headers, None, Some(&token));
        // THEN: extracted from JWT claim
        assert_eq!(
            identity,
            Some(AgentIdentity {
                id: "agent-jwt-1".to_string(),
                source: IdentitySource::JwtClaim,
            })
        );
    }

    #[test]
    fn extract_jwt_without_agent_id_claim() {
        // GIVEN: JWT with no agent_id claim
        let payload = r#"{"sub":"user","iat":1234567890}"#;
        let b64 = to_base64url(payload.as_bytes());
        let token = format!("eyJhbGciOiJub25lIn0.{b64}.sig");
        let headers = HeaderMap::new();
        // WHEN: extract
        let identity = extract_agent_identity(&headers, None, Some(&token));
        // THEN: none
        assert_eq!(identity, None);
    }

    // ── validate_agent_identity ───────────────────────────────────────────────

    #[test]
    fn validate_passes_when_feature_disabled() {
        // GIVEN: agent_identity.enabled = false
        let config = AgentIdentityConfig {
            enabled: false,
            ..Default::default()
        };
        // WHEN: validate with no identity
        // THEN: always passes
        assert!(validate_agent_identity(None, &config).is_ok());
    }

    #[test]
    fn validate_anonymous_allowed_when_require_id_false() {
        // GIVEN: enabled, require_id = false
        let config = AgentIdentityConfig {
            enabled: true,
            require_id: false,
            ..Default::default()
        };
        // WHEN: no identity
        // THEN: allowed (anonymous mode)
        assert!(validate_agent_identity(None, &config).is_ok());
    }

    #[test]
    fn validate_rejects_when_require_id_and_no_identity() {
        // GIVEN: enabled, require_id = true
        let config = AgentIdentityConfig {
            enabled: true,
            require_id: true,
            ..Default::default()
        };
        // WHEN: no identity provided
        let result = validate_agent_identity(None, &config);
        // THEN: rejected with descriptive error
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("require_id"));
    }

    #[test]
    fn validate_known_agents_allowlist_passes_for_listed_agent() {
        // GIVEN: known_agents allowlist with one entry
        let config = AgentIdentityConfig {
            enabled: true,
            require_id: true,
            known_agents: vec!["agent-allowed".to_string()],
        };
        let identity = AgentIdentity {
            id: "agent-allowed".to_string(),
            source: IdentitySource::Header,
        };
        // WHEN: validate known agent
        // THEN: passes
        assert!(validate_agent_identity(Some(&identity), &config).is_ok());
    }

    #[test]
    fn validate_known_agents_allowlist_rejects_unknown_agent() {
        // GIVEN: non-empty allowlist
        let config = AgentIdentityConfig {
            enabled: true,
            require_id: true,
            known_agents: vec!["agent-allowed".to_string()],
        };
        let identity = AgentIdentity {
            id: "rogue-agent".to_string(),
            source: IdentitySource::Header,
        };
        // WHEN: validate agent not in allowlist
        let result = validate_agent_identity(Some(&identity), &config);
        // THEN: rejected
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("rogue-agent"));
    }

    #[test]
    fn validate_empty_known_agents_skips_allowlist_check() {
        // GIVEN: enabled, require_id = true, known_agents = []
        let config = AgentIdentityConfig {
            enabled: true,
            require_id: true,
            known_agents: vec![],
        };
        let identity = AgentIdentity {
            id: "any-agent".to_string(),
            source: IdentitySource::Header,
        };
        // WHEN: any agent ID is presented with empty allowlist
        // THEN: passes (no filter applied)
        assert!(validate_agent_identity(Some(&identity), &config).is_ok());
    }

    // ── percent_decode ────────────────────────────────────────────────────────

    #[test]
    fn percent_decode_handles_encoded_chars() {
        assert_eq!(percent_decode("agent%2Dv2"), "agent-v2");
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("a%20b"), "a b");
    }

    // ── test helpers ─────────────────────────────────────────────────────────

    /// Minimal base64url encoder for test fixture construction.
    fn to_base64url(input: &[u8]) -> String {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in input.chunks(3) {
            let b0 = chunk[0];
            let b1 = *chunk.get(1).unwrap_or(&0);
            let b2 = *chunk.get(2).unwrap_or(&0);
            out.push(alphabet[((b0 >> 2) & 0x3F) as usize] as char);
            out.push(alphabet[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
            out.push(alphabet[(((b1 & 0xF) << 2) | (b2 >> 6)) as usize] as char);
            out.push(alphabet[(b2 & 0x3F) as usize] as char);
        }
        // Strip padding and convert base64 → base64url
        out.trim_end_matches('=')
            .replace('+', "-")
            .replace('/', "_")
    }
}
