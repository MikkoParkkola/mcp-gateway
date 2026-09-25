// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A key in the config file that nothing reads is a load error (C1).
//!
//! The figment extract tolerates extra keys, so `key_server: {enabeld: true}`
//! used to load with the key server off. The check runs over the YAML file
//! alone: the env layer lands `MCP_GATEWAY_*` as root keys, and a strict
//! merged document would refuse every deployment that sets one.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

use serde_ignored::Path as KeyPath;

use super::Config;
use crate::{Error, Result};

/// Keys that were removed, with the reason. A retired key is refused like any
/// other, with its explanation in place of "fix the spelling".
const RETIRED_BACKEND_KEYS: &[(&str, &str)] = &[(
    "idle_timeout",
    "backend idle hibernation was never implemented, so the key never had an \
     effect; use `stop_when_idle_for` on a `command` backend, or delete it",
)];

/// Every key a `backends.<name>` mapping may carry.
///
/// `BackendConfig.transport` is `#[serde(flatten)]` over an untagged enum, so
/// serde buffers the leftover keys and `serde_ignored` never sees them. This
/// list closes that hole by hand; `known_backend_keys_match_struct` fails when
/// it drifts from `BackendConfig` and `TransportConfig`.
const KNOWN_BACKEND_KEYS: &[&str] = &[
    // BackendConfig
    "description",
    "enabled",
    "stop_when_idle_for",
    "timeout",
    "env",
    "headers",
    "oauth",
    "secrets",
    "passthrough",
    "allow_cleartext_credentials",
    "runtime_profile",
    "identity_propagation",
    "account",
    // TransportConfig::Stdio and ::Http
    "command",
    "cwd",
    "protocol_version",
    "http_url",
    "streamable_http",
];

/// `TransportConfig::A2a` fields, which exist only with the `a2a` feature.
const A2A_BACKEND_KEYS: &[&str] = &["a2a_url", "a2a_agent_card_path"];

/// Refuse the config file at `path` if it carries a key nothing reads.
///
/// Every key is reported in one error, sorted. A file that cannot be read or
/// parsed is left to the figment extract, which already reported it.
pub(super) fn refuse_unrecognised_keys(path: Option<&Path>) -> Result<()> {
    let _ = path;
    let path: Option<&Path> = None;
    let Some(path) = path else { return Ok(()) };
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Ok(());
    };
    let mut found = ignored_by_serde(&raw);
    found.extend(unread_backend_keys(&raw));
    if found.is_empty() {
        return Ok(());
    }
    Err(Error::ConfigValidation(refusal(path, &found)))
}

/// Paths `Config`'s own deserializer skipped.
///
/// Figment stays authoritative for type errors: a parse that fails here keeps
/// the paths collected before the failure and drops the error.
fn ignored_by_serde(raw: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let _: std::result::Result<Config, _> =
        serde_ignored::deserialize(serde_yaml::Deserializer::from_str(raw), |key| {
            found.insert(dotted(&key));
        });
    found
}

/// `auth.api_keys[0].bakends`: dots between mapping keys, brackets for an index.
fn dotted(key: &KeyPath<'_>) -> String {
    match key {
        KeyPath::Root => String::new(),
        KeyPath::Seq { parent, index } => format!("{}[{index}]", dotted(parent)),
        KeyPath::Map { parent, key } => match dotted(parent) {
            prefix if prefix.is_empty() => key.clone(),
            prefix => format!("{prefix}.{key}"),
        },
        KeyPath::Some { parent }
        | KeyPath::NewtypeStruct { parent }
        | KeyPath::NewtypeVariant { parent } => dotted(parent),
    }
}

/// `backends.<name>.<key>` for every key outside [`KNOWN_BACKEND_KEYS`].
fn unread_backend_keys(raw: &str) -> BTreeSet<String> {
    let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(raw) else {
        return BTreeSet::new();
    };
    let Some(backends) = doc.get("backends").and_then(serde_yaml::Value::as_mapping) else {
        return BTreeSet::new();
    };
    let mut found = BTreeSet::new();
    for (name, fields) in backends {
        let (Some(name), Some(fields)) = (name.as_str(), fields.as_mapping()) else {
            continue;
        };
        for key in fields.keys().filter_map(serde_yaml::Value::as_str) {
            if !is_backend_key(key) {
                found.insert(format!("backends.{name}.{key}"));
            }
        }
    }
    found
}

fn is_backend_key(key: &str) -> bool {
    KNOWN_BACKEND_KEYS.contains(&key) || (cfg!(feature = "a2a") && A2A_BACKEND_KEYS.contains(&key))
}

/// The feature a key needs when this build lacks it. Refusing such a key as a
/// misspelling would send the operator hunting for a typo that is not there.
fn missing_feature(key: &str, leaf: &str) -> Option<&'static str> {
    if !cfg!(feature = "cost-governance") && key == "cost_governance" {
        return Some("cost-governance");
    }
    if !cfg!(feature = "a2a") && key.starts_with("backends.") && A2A_BACKEND_KEYS.contains(&leaf) {
        return Some("a2a");
    }
    None
}

fn refusal(path: &Path, found: &BTreeSet<String>) -> String {
    let keys: Vec<&str> = found.iter().map(String::as_str).collect();
    let mut message = format!(
        "Unrecognised config key(s) in {}: {}.",
        path.display(),
        keys.join(", ")
    );
    let mut misspelt = false;
    for key in found {
        let leaf = key.rsplit('.').next().unwrap_or(key);
        let retired = RETIRED_BACKEND_KEYS
            .iter()
            .find(|(name, _)| key.starts_with("backends.") && *name == leaf);
        if let Some((_, why)) = retired {
            let _ = write!(message, " `{key}` is retired: {why}.");
        } else if let Some(feature) = missing_feature(key, leaf) {
            let _ = write!(
                message,
                " `{key}` is valid but this binary was built without feature \"{feature}\"."
            );
        } else {
            misspelt = true;
        }
    }
    if misspelt {
        message.push_str(" 4.0 refuses keys it does not read; fix the spelling or delete the key.");
    }
    message
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{A2A_BACKEND_KEYS, KNOWN_BACKEND_KEYS};
    use crate::config::{BackendConfig, TransportConfig};
    use crate::identity_propagation::IdentityPropagationConfig;

    /// Drift guard for the hand list: every key a `BackendConfig` serializes,
    /// across every transport variant, is on the list, and every list entry is
    /// a key some variant serializes.
    #[test]
    fn known_backend_keys_match_struct() {
        let identity: IdentityPropagationConfig = serde_yaml::from_str(
            "{strategy: token_exchange, audience: a, session_mode: stateless}",
        )
        .expect("identity propagation sample parses");
        let mut transports = vec![
            TransportConfig::Stdio {
                command: "c".into(),
                cwd: None,
                protocol_version: None,
            },
            TransportConfig::default(),
        ];
        #[cfg(feature = "a2a")]
        transports.push(TransportConfig::A2a {
            a2a_url: "u".into(),
            a2a_agent_card_path: None,
        });
        let mut serialized = BTreeSet::new();
        for transport in transports {
            let backend = BackendConfig {
                transport,
                runtime_profile: Some("p".into()),
                identity_propagation: Some(identity.clone()),
                account: Some("a".into()),
                ..BackendConfig::default()
            };
            let value = serde_yaml::to_value(&backend).expect("backend serializes");
            let fields = value.as_mapping().expect("backend is a mapping");
            serialized.extend(fields.keys().filter_map(|k| k.as_str().map(str::to_owned)));
        }
        let mut listed: BTreeSet<String> =
            KNOWN_BACKEND_KEYS.iter().map(|k| (*k).to_owned()).collect();
        if cfg!(feature = "a2a") {
            listed.extend(A2A_BACKEND_KEYS.iter().map(|k| (*k).to_owned()));
        }
        assert_eq!(
            serialized, listed,
            "KNOWN_BACKEND_KEYS drifted from BackendConfig"
        );
    }
}
