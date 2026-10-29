// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Whether a server found in a client config can become a gateway backend
//! without losing or leaking anything. The shadow radar applies it today;
//! the discovery route and `discover --write` are to call it as well, so
//! none of them offers an adoption another refuses.
//!
//! A find is adoptable when the gateway would run it exactly as the client
//! does. Its `env` and `headers` values then fall in two kinds: a template
//! (`${NAME}`, alone or after one auth scheme word such as `Bearer `), copied
//! as written and expanded by the gateway as before, and a literal (no `${`),
//! which goes to the secret store, never into gateway.yaml. Literal text
//! beside a template refuses: it may be a secret, and only the whole value
//! can move to the store.

use crate::config::secret_ref::{has_literal_default, literal_outside_templates};
use crate::config::{Config, TransportConfig, is_reference};

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
    /// A URL that may carry a credential: a user name or password, a query
    /// string, or a fragment.
    CredentialInUrl,
    /// Credentials the client sends in cleartext to a host off this machine,
    /// which a gateway load refuses for an enabled backend.
    CleartextCredential,
    /// Literal text beside a template (`sk-${SUFFIX}`): it would reach
    /// gateway.yaml as text, and it may be a secret.
    LiteralInTemplate,
}

impl AdoptRefusal {
    /// The stable reason code.
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::NeedsClientOnlySecret => "needs_client_only_secret",
            Self::LiteralDefault => "literal_default",
            Self::CredentialInUrl => "credential_in_url",
            Self::CleartextCredential => "cleartext_credential",
            Self::LiteralInTemplate => "literal_in_template",
        }
    }
}

/// The literal text a template value may carry: one auth scheme word and a
/// space, before the template.
const SCHEME_PREFIXES: &[&str] = &["Bearer ", "Basic ", "Token ", "Bot "];

/// Whether the text of `value` outside its templates is nothing, or one
/// scheme prefix in front of them.
fn only_scheme_beside_templates(value: &str) -> bool {
    let outside = literal_outside_templates(value);
    outside.is_empty()
        || (SCHEME_PREFIXES.contains(&outside.as_str()) && value.starts_with(&outside))
}

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
        if key.contains("${") {
            // The client expands a name the gateway would send literally.
            refused.push((AdoptRefusal::NeedsClientOnlySecret, format!("{map}.{key}")));
            continue;
        }
        if !value.contains("${") {
            continue;
        }
        if has_literal_default(value) {
            refused.push((AdoptRefusal::LiteralDefault, format!("{map}.{key}")));
        } else if is_reference(value) {
            // A load reads `file:${HOME}/t` as a file reference first.
            refused.push((AdoptRefusal::NeedsClientOnlySecret, format!("{map}.{key}")));
        } else if !only_scheme_beside_templates(value) {
            refused.push((AdoptRefusal::LiteralInTemplate, format!("{map}.{key}")));
        }
    }
    // A stdio command or working directory the gateway would run as
    // written: checked here too, whichever producer built the find.
    if let TransportConfig::Stdio { command, cwd, .. } = &server.transport {
        let relative = |dir: &str| std::path::Path::new(dir).is_relative();
        for (field, bad) in [
            ("command", command.contains("${")),
            (
                "cwd",
                cwd.as_deref()
                    .is_some_and(|dir| dir.contains("${") || relative(dir)),
            ),
        ] {
            let named = |f: &str| f == field || (field == "command" && f.starts_with("args["));
            if bad && !server.uncarried.iter().any(|f| named(f)) {
                refused.push((AdoptRefusal::NeedsClientOnlySecret, field.to_string()));
            }
        }
    }
    // Checked here, not only by the client config scanner: an environment
    // find never passes through it.
    let parsed = match url(&server.transport) {
        None => None,
        Some(raw) => match url::Url::parse(raw) {
            Ok(parsed)
                if !raw.contains("${")
                    && matches!(parsed.scheme(), "http" | "https" | "ws" | "wss") =>
            {
                Some(parsed)
            }
            _ => {
                if !server.uncarried.iter().any(|field| field == "url") {
                    refused.push((AdoptRefusal::NeedsClientOnlySecret, "url".to_string()));
                }
                None
            }
        },
    };
    if let Some(parsed) = parsed {
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
        TransportConfig::Stdio { .. } => None,
        #[cfg(feature = "a2a")]
        TransportConfig::A2a { .. } => None,
    }
}

/// A query counts whatever its names: no list of names can tell a secret
/// from an ordinary parameter, and adoption would copy the value into
/// gateway.yaml as text. (The cleartext guard counts a query for the same
/// reason; here loopback is no exemption, since the risk is the file, not
/// the wire.)
fn carries_credential(url: &url::Url) -> bool {
    !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
}

/// A find made ready for gateway.yaml: the backend, disabled, with its
/// literal env and header values taken out, and those literals in the order
/// their store references fill them back in.
#[cfg(feature = "webui")]
pub(crate) struct Adoption {
    pub(crate) backend: crate::config::BackendConfig,
    pub(crate) literals: Vec<Literal>,
}

/// One literal value, bound for the secret store.
#[cfg(feature = "webui")]
pub(crate) struct Literal {
    /// A header rather than an env value.
    pub(crate) header: bool,
    pub(crate) key: String,
    pub(crate) value: crate::wiped_bytes::WipedBytes,
}

#[cfg(feature = "webui")]
impl Literal {
    /// `env.KEY` or `headers.KEY`: the client field it came from.
    pub(crate) fn field(&self) -> String {
        format!(
            "{}.{}",
            if self.header { "headers" } else { "env" },
            self.key
        )
    }
}

/// `server` as an adopted backend. A template and an empty value stay as
/// written; every other value is a literal and leaves the backend, env
/// before headers, each sorted by key, so the order is the same on every
/// run. Call it only for a find [`refusals`] accepts.
#[cfg(feature = "webui")]
pub(crate) fn adoption(server: &DiscoveredServer) -> Adoption {
    let mut backend = server.to_backend_config();
    backend.enabled = false;
    let mut literals = Vec::new();
    for (header, map) in [(false, &mut backend.env), (true, &mut backend.headers)] {
        let mut keys: Vec<String> = map
            .iter()
            .filter(|(_, value)| !value.is_empty() && !value.contains("${"))
            .map(|(key, _)| key.clone())
            .collect();
        keys.sort();
        for key in keys {
            if let Some(value) = map.remove(&key) {
                literals.push(Literal {
                    header,
                    key,
                    value: crate::wiped_bytes::WipedBytes::new(value.into_bytes()),
                });
            }
        }
    }
    Adoption { backend, literals }
}

#[cfg(test)]
#[path = "adopt_tests.rs"]
mod tests;
