// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Load refusals for `secrets:` rules a backend cannot deliver where they say.
//!
//! A rule is applied on the backend's own send, which puts an `argument` rule
//! in the tool call's arguments and a `header` rule on the call's request
//! headers. A rule that send cannot honour, or could honour only by sending
//! the secret somewhere unsafe, is refused here, naming the backend and the
//! rule, never the value. Each is judged on the backend's EFFECTIVE config, as
//! startup registers it: a `personal_managed` account compiles to a required
//! binding.
//!
//! The text of each refusal comes from [`refusal`], which the upgrade guide
//! quotes; a test pins the two together.

use reqwest::header::HeaderName;

use super::{BackendConfig, Config, TransportConfig};
use crate::secret_injection::{CredentialRule, InjectTarget};
use crate::{Error, Result};

/// Headers the gateway's transports set themselves; a rule naming one would
/// be overwritten or would displace the protocol's own. Every `Mcp-` header is
/// the protocol's too.
const PROTOCOL_HEADERS: &[&str] = &[
    "accept",
    "connection",
    "content-length",
    "content-type",
    "host",
    "last-event-id",
    "transfer-encoding",
];

/// Why a rule is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// `inject_as: query`, on any transport.
    Query,
    /// A header on a stdio backend.
    StdioHeader,
    /// A header on a backend whose identity binding is required.
    RequiredBinding,
    /// A header the gateway or the backend's own credential already sets.
    OwnedHeader,
    /// A header name that is not a valid HTTP header name.
    InvalidHeaderName,
    /// Two header rules naming the same header, compared case-insensitively.
    DuplicateHeader,
    /// Any rule on an A2A backend.
    A2a,
    /// An argument rule on an A2A backend's `message`.
    A2aMessage,
}

/// The refusal's text for `backend`'s `rule`, which injects `header` (the
/// rule's `inject_key`; read only by the header refusals).
#[must_use]
pub(crate) fn refusal(kind: Refusal, backend: &str, rule: &str, header: &str) -> String {
    let head = format!("backend '{backend}' secret rule '{rule}'");
    match kind {
        Refusal::Query => format!(
            "{head} injects into a URL query parameter: the gateway sends no secret in a \
             URL, where proxy and access logs keep it; use inject_as: header"
        ),
        Refusal::StdioHeader => format!(
            "{head} injects a header on a stdio backend, which has no request headers; use \
             inject_as: argument or the backend's env"
        ),
        Refusal::RequiredBinding => format!(
            "{head} injects a header, but its identity binding is required, so its \
             per-user sends carry only the subscriber's own credential; remove the rule and \
             supply the credential through the per-user binding"
        ),
        Refusal::OwnedHeader => format!(
            "{head} injects the header '{header}', which the gateway or this backend's own \
             credential already sets; inject a header the server reads that nothing else sets"
        ),
        Refusal::InvalidHeaderName => {
            format!("{head} injects '{header}', which is not a valid HTTP header name")
        }
        Refusal::DuplicateHeader => format!(
            "{head} injects the header '{header}', which another of its rules injects too \
             (header names ignore case); keep one"
        ),
        Refusal::A2a => format!(
            "{head} is on an A2A backend, whose bridge forwards only the message and its own \
             headers, so the rule never reached the agent; put the agent's credential in the \
             backend's headers"
        ),
        Refusal::A2aMessage => format!(
            "{head} is on an A2A backend and injects the argument 'message', which replaces \
             the caller's message with the secret; put the agent's credential in the \
             backend's headers"
        ),
    }
}

/// Refuse every backend's undeliverable rules, each judged on the config the
/// backend runs with.
pub(super) fn validate(config: &Config) -> Result<()> {
    let bound = super::account_bindings::compile(config)?;
    for (name, backend) in &config.backends {
        if backend.secrets.is_empty() {
            continue;
        }
        let effective = bound.get(name).map(|binding| binding.effective(backend));
        check(name, effective.as_ref().unwrap_or(backend))?;
    }
    Ok(())
}

/// The first refusal among `backend`'s rules.
fn check(name: &str, backend: &BackendConfig) -> Result<()> {
    let refuse = |kind, rule: &CredentialRule| {
        Err(Error::ConfigValidation(refusal(
            kind,
            name,
            &rule.name,
            &rule.inject_key,
        )))
    };
    let mut headers: Vec<&str> = Vec::new();
    for rule in &backend.secrets {
        if is_a2a(&backend.transport) {
            let message =
                matches!(rule.inject_as, InjectTarget::Argument) && rule.inject_key == "message";
            return refuse(
                if message {
                    Refusal::A2aMessage
                } else {
                    Refusal::A2a
                },
                rule,
            );
        }
        match rule.inject_as {
            InjectTarget::Argument => {}
            InjectTarget::Query => return refuse(Refusal::Query, rule),
            InjectTarget::Header => {
                if matches!(backend.transport, TransportConfig::Stdio { .. }) {
                    return refuse(Refusal::StdioHeader, rule);
                }
                if HeaderName::from_bytes(rule.inject_key.as_bytes()).is_err() {
                    return refuse(Refusal::InvalidHeaderName, rule);
                }
                if owned_header(backend, &rule.inject_key) {
                    return refuse(Refusal::OwnedHeader, rule);
                }
                if backend
                    .identity_propagation
                    .as_ref()
                    .is_some_and(|binding| binding.required)
                {
                    return refuse(Refusal::RequiredBinding, rule);
                }
                if headers
                    .iter()
                    .any(|seen| seen.eq_ignore_ascii_case(&rule.inject_key))
                {
                    return refuse(Refusal::DuplicateHeader, rule);
                }
                headers.push(&rule.inject_key);
            }
        }
    }
    Ok(())
}

/// Whether `header` is set by the gateway's transports or by `backend`'s own
/// credential: a static header, OAuth, identity propagation, an account, or
/// the Basic credential a URL's userinfo becomes.
fn owned_header(backend: &BackendConfig, header: &str) -> bool {
    let header = header.to_ascii_lowercase();
    if header.starts_with("mcp-") || PROTOCOL_HEADERS.contains(&header.as_str()) {
        return true;
    }
    if backend
        .headers
        .keys()
        .any(|configured| configured.eq_ignore_ascii_case(&header))
    {
        return true;
    }
    header == "authorization"
        && (backend.oauth.is_some()
            || backend.identity_propagation.is_some()
            || backend.account.is_some()
            || url_has_userinfo(&backend.transport))
}

/// Whether the backend's URL carries userinfo, which its HTTP client sends as
/// a Basic `Authorization` header.
fn url_has_userinfo(transport: &TransportConfig) -> bool {
    let url = match transport {
        TransportConfig::Http { http_url, .. } => http_url,
        TransportConfig::WebSocket { ws_url, .. } => ws_url,
        TransportConfig::Stdio { .. } => return false,
        #[cfg(feature = "a2a")]
        TransportConfig::A2a { .. } => return false,
    };
    url::Url::parse(url).is_ok_and(|url| !url.username().is_empty() || url.password().is_some())
}

/// Whether `transport` is an A2A bridge.
#[cfg(feature = "a2a")]
const fn is_a2a(transport: &TransportConfig) -> bool {
    matches!(transport, TransportConfig::A2a { .. })
}

/// Whether `transport` is an A2A bridge: never, in a build without A2A.
#[cfg(not(feature = "a2a"))]
const fn is_a2a(_transport: &TransportConfig) -> bool {
    false
}

#[cfg(test)]
#[path = "secret_rules_tests.rs"]
mod tests;
