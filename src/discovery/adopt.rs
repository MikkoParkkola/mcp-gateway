// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Whether a server found in a client config can become a gateway backend
//! without losing or leaking anything: the one rule the shadow radar, the
//! discovery route and `discover --write` share, so none of them offers an
//! adoption another refuses.
//!
//! A find is adoptable when the gateway would run it exactly as the client
//! does. Its `env` and `headers` values then fall in two kinds: a template
//! (`${NAME}`, anywhere in the value), copied as written and expanded by the
//! gateway as before, and a literal (no `${`), which goes to the secret
//! store, never into gateway.yaml.

use crate::config::{TransportConfig, has_literal_default, is_reference};

use super::DiscoveredServer;

/// Why a find is not adoptable. Each comes with the client field it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdoptRefusal {
    /// A value only the client can resolve or reproduce: `${input:...}`, a
    /// non-string value, a `${` the gateway would not expand, or a template
    /// the gateway would read as a secret reference before expanding it.
    NeedsClientOnlySecret,
    /// `${NAME:-default}` with a non-empty default: the default is a literal
    /// that would be written into gateway.yaml as text.
    LiteralDefault,
    /// A URL carrying a credential: a user name or password, or a query
    /// parameter named like one.
    CredentialInUrl,
}

/// Query parameter names, matched case-insensitively as substrings, that
/// carry a credential: `access_token`, `apikey`, `X-Amz-Signature`.
const CREDENTIAL_QUERY_NAMES: &[&str] = &[
    "token",
    "key",
    "secret",
    "password",
    "passwd",
    "auth",
    "sig",
    "credential",
    "session",
];

/// Every reason `server` is not adoptable, each with the client field it
/// names (`env.API_KEY`, `args[2]`, `url`), in a stable order. Empty when it
/// is adoptable.
pub(crate) fn refusals(server: &DiscoveredServer) -> Vec<(AdoptRefusal, String)> {
    let mut refused: Vec<(AdoptRefusal, String)> = server
        .uncarried
        .iter()
        .map(|field| (AdoptRefusal::NeedsClientOnlySecret, field.clone()))
        .collect();
    let env = server.env.expose().iter().map(|(k, v)| ("env", k, v));
    let headers = server
        .headers
        .expose()
        .iter()
        .map(|(k, v)| ("headers", k, v));
    for (map, key, value) in env.chain(headers) {
        if !value.contains("${") {
            continue;
        }
        if has_literal_default(value) {
            refused.push((AdoptRefusal::LiteralDefault, format!("{map}.{key}")));
        } else if is_reference(value) {
            // A load reads `file:${HOME}/t` as a file reference first.
            refused.push((AdoptRefusal::NeedsClientOnlySecret, format!("{map}.{key}")));
        }
    }
    if url(&server.transport).is_some_and(carries_credential) {
        refused.push((AdoptRefusal::CredentialInUrl, "url".to_string()));
    }
    refused
}

fn url(transport: &TransportConfig) -> Option<&str> {
    match transport {
        TransportConfig::Http { http_url, .. } => Some(http_url),
        TransportConfig::WebSocket { ws_url, .. } => Some(ws_url),
        _ => None,
    }
}

/// A URL that does not parse carries nothing the parser could see; the
/// load refuses it on its own.
fn carries_credential(raw: &str) -> bool {
    let Ok(url) = url::Url::parse(raw) else {
        return false;
    };
    if !url.username().is_empty() || url.password().is_some() {
        return true;
    }
    url.query_pairs().any(|(name, _)| {
        let name = name.to_ascii_lowercase();
        CREDENTIAL_QUERY_NAMES
            .iter()
            .any(|credential| name.contains(credential))
    })
}

#[cfg(test)]
#[path = "adopt_tests.rs"]
mod tests;
