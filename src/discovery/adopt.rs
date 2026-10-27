// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Whether a server found in a client config can become a gateway backend
//! without losing or leaking anything. The shadow radar applies it today;
//! the discovery route and `discover --write` are to call it as well, so
//! none of them offers an adoption another refuses.
//!
//! A find is adoptable when the gateway would run it exactly as the client
//! does. Its `env` and `headers` values then fall in two kinds: a template
//! (`${NAME}`, anywhere in the value), copied as written and expanded by the
//! gateway as before, and a literal (no `${`), which goes to the secret
//! store, never into gateway.yaml.

use crate::config::{Config, TransportConfig, has_literal_default, is_reference};

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
    /// A URL carrying a credential: a user name or password, a query
    /// parameter named like one, or a fragment.
    CredentialInUrl,
    /// Credentials the client sends in cleartext to a host off this machine,
    /// which a gateway load refuses for an enabled backend.
    CleartextCredential,
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
    "bearer",
    "pwd",
    "jwt",
];

/// Every reason `server` is not adoptable, each with the client field it
/// names (`env.API_KEY`, `args[2]`, `url`), sorted by field. Empty when it
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
    // A URL that does not parse is already uncarried by the scanner.
    if let Some(parsed) = url(&server.transport).and_then(|raw| url::Url::parse(raw).ok()) {
        if carries_credential(&parsed) {
            refused.push((AdoptRefusal::CredentialInUrl, "url".to_string()));
        } else if Config::reject_cleartext_credentials(
            &server.name,
            &server.to_backend_config(),
            &parsed,
        )
        .is_err()
        {
            refused.push((AdoptRefusal::CleartextCredential, "url".to_string()));
        }
    }
    // By field name: a client file's key order is not one to depend on.
    refused.sort_by(|a, b| a.1.cmp(&b.1));
    refused
}

fn url(transport: &TransportConfig) -> Option<&str> {
    match transport {
        TransportConfig::Http { http_url, .. } => Some(http_url),
        TransportConfig::WebSocket { ws_url, .. } => Some(ws_url),
        _ => None,
    }
}

fn carries_credential(url: &url::Url) -> bool {
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
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
