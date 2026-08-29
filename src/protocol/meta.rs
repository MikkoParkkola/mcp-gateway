// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT

//! Per-request protocol metadata (MCP 2026-07-28), and telling the eras apart.
//!
//! The revision deleted the `initialize` handshake, so a request has to say for
//! itself what it is. It does that in `params._meta`, under reverse-DNS keys:
//!
//! ```json
//! "_meta": {
//!   "io.modelcontextprotocol/protocolVersion": "2026-07-28",
//!   "io.modelcontextprotocol/clientCapabilities": {},
//!   "io.modelcontextprotocol/clientInfo": { "name": "…", "version": "…" }
//! }
//! ```
//!
//! Version and capabilities are **required**; a request missing either is
//! malformed and gets `-32602`, with HTTP `400` on the HTTP path.
//!
//! ## Why absence cannot simply mean "malformed"
//!
//! A 2025 client sends none of these fields. So does a 2026 client that forgot
//! one. Under a rule of "no protocol fields means malformed", every legacy
//! client this gateway serves would start receiving `-32602`.
//!
//! So the rule is about **declaration**, not presence: a request that carries at
//! least one protocol field has declared itself modern, and is then held to all
//! of them. A request carrying none has declared nothing and is served as
//! legacy. The cost of that choice is bounded and named: a 2026 client that
//! omits *both* required fields is treated as a 2025 client rather than told its
//! request was malformed. Breaking every existing client to improve one error
//! message is the worse trade.
//!
//! `_meta` is a general-purpose extension field — tracing and vendor extensions
//! live there too — so only the `io.modelcontextprotocol/*` protocol keys count
//! as a declaration. A 2025 client that sends a trace context has not thereby
//! become a broken 2026 client.

use serde_json::Value;

/// `_meta` key: the protocol version a request is written against. Required.
pub const KEY_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
/// `_meta` key: the capabilities the client declares for this request. Required.
pub const KEY_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
/// `_meta` key: who the client says it is. Optional, and **self-asserted**.
pub const KEY_CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";
/// `_meta` key: the minimum log level to emit for this request. Optional.
pub const KEY_LOG_LEVEL: &str = "io.modelcontextprotocol/logLevel";
/// `_meta` key: who the server says it is, on every result.
pub const KEY_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

/// The protocol fields a modern request carries.
#[derive(Debug, Clone)]
pub struct RequestFields {
    /// The revision this request is written against.
    pub protocol_version: String,
    /// What the client declared it can receive. A server **MUST NOT** rely on a
    /// capability absent from here.
    pub client_capabilities: Value,
    /// The client's self-reported name, for logs and displays.
    ///
    /// **Never an authorization input.** The specification says clients *SHOULD
    /// identify themselves*, which is identification, not authentication: any
    /// caller can write any name here. Authorization stays with the
    /// authenticated credential.
    pub client_info_name: Option<String>,
    /// The minimum level to emit `notifications/message` at for this request.
    /// `None` means emit none at all.
    pub log_level: Option<String>,
}

/// What a request declared itself to be.
#[derive(Debug)]
pub enum RequestShape {
    /// Carries the protocol fields, and all the required ones.
    Modern(Box<RequestFields>),
    /// Declares no protocol fields. A 2025 client.
    Legacy,
    /// Declared itself modern and then omitted a required field.
    Malformed {
        /// The required keys that were absent, named so the error can say which.
        missing: Vec<&'static str>,
    },
}

/// Decide what a request declared itself to be, from its `params`.
#[must_use]
pub fn classify_request(params: Option<&Value>) -> RequestShape {
    let Some(meta) = params
        .and_then(|p| p.get("_meta"))
        .and_then(Value::as_object)
    else {
        return RequestShape::Legacy;
    };

    let version = meta.get(KEY_PROTOCOL_VERSION);
    let capabilities = meta.get(KEY_CLIENT_CAPABILITIES);

    // Declaration, not presence: only the protocol keys count. `_meta` also
    // carries tracing and vendor extensions, and a 2025 client that sends a
    // trace context has not declared an era.
    if version.is_none() && capabilities.is_none() {
        return RequestShape::Legacy;
    }

    let mut missing = Vec::new();
    if version.is_none() {
        missing.push(KEY_PROTOCOL_VERSION);
    }
    if capabilities.is_none() {
        missing.push(KEY_CLIENT_CAPABILITIES);
    }
    if !missing.is_empty() {
        return RequestShape::Malformed { missing };
    }

    // A version that is present but not a string is as unusable as an absent
    // one, and saying "missing" of a field that is there would misdirect
    // whoever reads the error.
    let Some(protocol_version) = version.and_then(Value::as_str) else {
        return RequestShape::Malformed {
            missing: vec![KEY_PROTOCOL_VERSION],
        };
    };

    RequestShape::Modern(Box::new(RequestFields {
        protocol_version: protocol_version.to_string(),
        client_capabilities: capabilities.cloned().unwrap_or(Value::Null),
        client_info_name: meta
            .get(KEY_CLIENT_INFO)
            .and_then(|i| i.get("name"))
            .and_then(Value::as_str)
            .map(str::to_string),
        log_level: meta
            .get(KEY_LOG_LEVEL)
            .and_then(Value::as_str)
            .map(str::to_string),
    }))
}

/// Revisions the **stateless** path can serve.
///
/// Deliberately separate from `SUPPORTED_VERSIONS`, which is the list a legacy
/// `initialize` negotiates over. The two sets are not the same thing and only
/// coincide by accident: a 2025 revision cannot be served statelessly, and
/// 2026-07-28 cannot be reached through a handshake that revision deleted.
pub const MODERN_VERSIONS: &[&str] = &["2026-07-28"];

/// Methods this revision removed. Refused on the modern path, served on the
/// legacy one — the gateway's own backend health probe is a `ping`, and every
/// 2025 client has one too.
pub const REMOVED_IN_2026_07_28: &[&str] = &[
    "ping",
    "logging/setLevel",
    "notifications/roots/list_changed",
];
