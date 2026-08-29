// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT

//! The standard request headers of MCP 2026-07-28, and the check that has to
//! happen before the gateway acts on one.
//!
//! The revision mirrors selected JSON-RPC body fields into HTTP headers *"so
//! that intermediaries (load balancers, gateways, observability tooling) can
//! route and inspect requests without parsing the body"*. This gateway is that
//! intermediary, which is the upside. The rule attached to it is the cost:
//!
//! > Servers **that process the request body** **MUST** reject requests where
//! > the values specified in the headers do not match the corresponding values
//! > in the request body. This prevents potential security vulnerabilities when
//! > different components in the network rely on different sources of truth
//! > (e.g., a load balancer routing on the header value while the MCP server
//! > executes based on the body value).
//!
//! Note the condition. A pure relay is not bound by it; this gateway executes
//! at the meta-tool chokepoint, so it is. **Routing may read a header. Acting
//! may not — not until the header and the body have been shown to agree.**
//!
//! The comparison lives in one place on purpose. Written out three times, two
//! of them drift, and the difference between two versions of this check is a
//! bypass rather than a bug.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

/// Marks a header value as Base64-encoded UTF-8. Case-sensitive, and the
/// specification says so explicitly.
const SENTINEL_PREFIX: &str = "=?base64?";
/// Closes a sentinel-encoded value.
const SENTINEL_SUFFIX: &str = "?=";

/// The methods that carry a name, and therefore require `Mcp-Name`.
///
/// Exactly these three, from the specification's Standard Request Headers
/// table. Requiring the header everywhere rejects valid requests — a
/// `tools/list` has no name to mirror — and that is the likelier mistake,
/// because "required for compliance" reads as "required on everything".
#[must_use]
pub fn mcp_name_required(method: &str) -> bool {
    matches!(method, "tools/call" | "resources/read" | "prompts/get")
}

/// Decode a header value that may be sentinel-encoded.
///
/// A plain value is returned as-is. A sentinel-wrapped value is Base64-decoded
/// and must be valid UTF-8. Anything malformed returns `None` — **not** the raw
/// string, and not a lossy conversion.
///
/// That matters because an attacker writes this string and the result is
/// compared against the request body. Falling back to the raw value on a bad
/// decode would compare the wrapper instead of the payload; a lossy UTF-8
/// conversion would compare something the client never sent. Both turn a
/// mismatch into a match, which is the one direction that must never happen.
#[must_use]
pub fn decode_header_value(value: &str) -> Option<String> {
    let Some(inner) = value
        .strip_prefix(SENTINEL_PREFIX)
        .and_then(|rest| rest.strip_suffix(SENTINEL_SUFFIX))
    else {
        // Not sentinel-shaped, so it is a plain value. A value that *starts*
        // like a sentinel without closing like one is malformed rather than
        // plain — otherwise `=?base64?` alone would sail through as literal.
        if value.starts_with(SENTINEL_PREFIX) {
            return None;
        }
        return Some(value.to_string());
    };

    if inner.is_empty() {
        return None;
    }
    let bytes = BASE64.decode(inner).ok()?;
    String::from_utf8(bytes).ok()
}

/// Why a request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderMismatch {
    /// Which field disagreed, named so the client can fix it.
    pub field: &'static str,
    /// What the header said.
    pub header: Option<String>,
    /// What the body said.
    pub body: Option<String>,
}

impl std::fmt::Display for HeaderMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} header {:?} does not match body {:?}",
            self.field, self.header, self.body
        )
    }
}

/// The header and body values of one request, ready to be compared.
///
/// Borrowed rather than owned: this is built per request on the hot path, and
/// the comparison needs no allocation beyond decoding a sentinel.
#[derive(Debug)]
pub struct HeaderCheck<'a> {
    /// `MCP-Protocol-Version`. Required on every modern POST.
    pub header_protocol_version: Option<&'a str>,
    /// `_meta["io.modelcontextprotocol/protocolVersion"]`.
    pub body_protocol_version: Option<&'a str>,
    /// `Mcp-Method`. Required on every modern request.
    pub header_method: Option<&'a str>,
    /// The JSON-RPC `method`.
    pub body_method: &'a str,
    /// `Mcp-Name`, possibly sentinel-encoded.
    pub header_name: Option<&'a str>,
    /// `params.name` or `params.uri`.
    pub body_name: Option<&'a str>,
}

impl HeaderCheck<'_> {
    /// Compare every mirrored field, and say which one disagreed.
    ///
    /// # Errors
    ///
    /// Returns the first field whose header and body do not agree, or whose
    /// required header is absent or undecodable.
    pub fn validate(&self) -> Result<(), HeaderMismatch> {
        let Some(version) = self.header_protocol_version else {
            return Err(HeaderMismatch {
                field: "MCP-Protocol-Version",
                header: None,
                body: self.body_protocol_version.map(str::to_string),
            });
        };
        if Some(version) != self.body_protocol_version {
            return Err(HeaderMismatch {
                field: "MCP-Protocol-Version",
                header: Some(version.to_string()),
                body: self.body_protocol_version.map(str::to_string),
            });
        }

        let Some(method) = self.header_method else {
            return Err(HeaderMismatch {
                field: "Mcp-Method",
                header: None,
                body: Some(self.body_method.to_string()),
            });
        };
        if method != self.body_method {
            return Err(HeaderMismatch {
                field: "Mcp-Method",
                header: Some(method.to_string()),
                body: Some(self.body_method.to_string()),
            });
        }

        if !mcp_name_required(self.body_method) {
            // No name to mirror. A header sent anyway is not a mismatch — the
            // specification requires the header for three methods and says
            // nothing that forbids it elsewhere, and refusing on it would
            // reject a client that is merely generous.
            return Ok(());
        }

        let Some(raw) = self.header_name else {
            return Err(HeaderMismatch {
                field: "Mcp-Name",
                header: None,
                body: self.body_name.map(str::to_string),
            });
        };
        // Decoded before comparison, which the specification requires in as
        // many words. Comparing raw would reject every non-ASCII tool name.
        let Some(decoded) = decode_header_value(raw) else {
            return Err(HeaderMismatch {
                field: "Mcp-Name",
                header: Some(raw.to_string()),
                body: self.body_name.map(str::to_string),
            });
        };
        if Some(decoded.as_str()) != self.body_name {
            return Err(HeaderMismatch {
                field: "Mcp-Name",
                header: Some(decoded),
                body: self.body_name.map(str::to_string),
            });
        }

        Ok(())
    }
}
