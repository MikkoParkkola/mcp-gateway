// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A key in the config file that nothing reads is a load error (C1).
//!
//! Two kinds of unread key load anyway (#2360): a retired key, which never had
//! an effect and now warns once, and an annotation, a key whose own name starts
//! with `_` or `x-`, which no config field does, so it cannot be a misspelling.
//!
//! The figment extract tolerates extra keys, so `key_server: {enabeld: true}`
//! used to load with the key server off. The check runs over the YAML file
//! alone: the env layer lands `MCP_GATEWAY_*` as root keys, and a strict
//! merged document would refuse every deployment that sets one.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use figment::{Figment, value::Value};
use serde_ignored::Path as KeyPath;

use super::Config;
use super::config_file::ConfigFile;
use crate::{Error, Result};

/// Backend keys removed in 4.0, with the reason. Each is a load error naming
/// `mcp-gateway upgrade`, which deletes it (MIK-8044).
const REMOVED_BACKEND_KEYS: &[(&str, &str)] = &[
    (
        "idle_timeout",
        "backend idle hibernation was never implemented, so the key never had an \
         effect; use `stop_when_idle_for` on a `command` backend, or delete it",
    ),
    (
        "circuit_breaker",
        "a per-backend breaker was never read; every backend's breaker uses \
         `failsafe.circuit_breaker`, so tune that and delete this block",
    ),
];

/// Keys outside `backends` removed in 4.0, by path segments, with the reason.
/// Each is a load error naming `mcp-gateway upgrade`, which deletes it
/// (MIK-8044). None ever had an effect.
const REMOVED_KEYS: &[(&[&str], &str)] = &[
    (
        &["server", "ws_port"],
        "the inbound WebSocket listener was removed in 4.0 and no WebSocket listener is \
         opened; it only echoed frames and never served MCP. Clients connect over HTTP \
         (POST /mcp). Remove server.ws_port",
    ),
    (
        &["server", "request_timeout"],
        "the server-wide request timeout was removed in 4.0; it was never enforced. \
         Calls are bounded by the per-backend `timeout`. Remove server.request_timeout",
    ),
    (
        &["marketplace"],
        "the `plugin` command was removed in 4.0, and nothing else read this block: no \
         gateway path loaded the plugins it installed. Remove the marketplace block",
    ),
    (
        &["cost_governance", "currency"],
        "every cost is stored and reported in USD; the key only labelled it. Remove \
         cost_governance.currency",
    ),
];

/// Keys retired in 4.0 that still load, with the reason, warned once (#2360).
/// The settings-automatic-first rows (MIK-8782, MIK-8783) are settings the
/// gateway now picks itself; each value is ignored, never honoured.
const RETIRED_KEYS: &[(&[&str], &str)] = &[
    (
        &["meta_mcp", "cache_tools"],
        "nothing ever read it, so tool lists were cached the same way whatever it said; \
         `meta_mcp.cache_ttl` sets how long they are kept. Delete it, or run `mcp-gateway upgrade`, \
         which removes it or says why it cannot",
    ),
    (
        &["capabilities", "stale_check_secs"],
        "the gateway re-checks the watched capability directories every 60 s by itself, \
         so a silent file watcher still heals. Delete it, or run `mcp-gateway upgrade`",
    ),
    (
        &["cache", "enabled"],
        "the response cache is always on and stores only results of tools their annotations \
         mark read-only; `cache.default_ttl` sets how long an entry lives and a restart clears it. \
         Delete it, or run `mcp-gateway upgrade`",
    ),
    (
        &["failsafe", "retry", "enabled"],
        "retry is always on for calls a tool's annotations permit to resend (`readOnlyHint` or \
         `idempotentHint`) and never for others; `failsafe.retry.max_attempts: 1` means one \
         attempt. Delete it, or run `mcp-gateway upgrade`",
    ),
    (
        &["failsafe", "circuit_breaker", "enabled"],
        "the backend circuit breaker is always on; `gateway_revive_server` closes one held open \
         on a healthy backend, and the health probe closes it on recovery. Delete it, or run \
         `mcp-gateway upgrade`",
    ),
    (
        &["auth", "client_circuit_breaker", "enabled"],
        "the `auth.client_circuit_breaker` section's presence turns the client breaker on, \
         whatever this key says. To keep it on with no other key, write \
         `client_circuit_breaker: {}`; to turn it off, delete the section",
    ),
    (
        &["security", "signature_chain", "max_links"],
        "a chain holds at most 8 links, a constant every hop agrees on. Delete it, or run \
         `mcp-gateway upgrade`",
    ),
    (
        &["server", "protocol_revision_window"],
        "the measurement window is an operator instrument: start the gateway with \
         `--protocol-revision-window record` or `MCP_GATEWAY_PROTOCOL_REVISION_WINDOW=record`. \
         Delete the key, or run `mcp-gateway upgrade`",
    ),
];

/// A key the file carries that nothing reads and that still loads.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ignored {
    /// Retired in 4.0 and still loads; warned once with the reason.
    Retired(&'static str),
    /// Removed in 4.0; refused with the reason. Kept here, not with the keys
    /// nothing knows, so the refusal can say why and what deletes it.
    Removed(&'static str),
    /// A `_` or `x-` key: the operator's own note, never a setting.
    Annotation,
}

/// Unread keys that load, by dotted path.
type IgnoredKeys = BTreeMap<String, Ignored>;

/// Whether a mapping key is an annotation. No config field and no backend key
/// starts with `_` or `x-` (`annotation_prefixes_name_no_real_key`), so such a
/// key is never a misspelling of one.
fn is_annotation(key: &str) -> bool {
    key.starts_with('_') || key.starts_with("x-")
}

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
    "max_frame_bytes",
    "timeout",
    "env",
    "headers",
    "oauth",
    "secrets",
    "passthrough",
    "input_schema_enforcement",
    "allow_flagged_tools",
    "allowed_tools",
    "allow_cleartext_credentials",
    "runtime_profile",
    "identity_propagation",
    "account",
    "signature_chain",
    "chain_origins",
    "chain_signer",
    // TransportConfig::Stdio, ::Http and ::WebSocket
    "command",
    "cwd",
    "protocol_version",
    "http_url",
    "streamable_http",
    "ws_url",
    // The one-key spelling the loader resolves to `http_url` or `ws_url`.
    "url",
];

/// `TransportConfig::A2a` fields, which exist only with the `a2a` feature.
const A2A_BACKEND_KEYS: &[&str] = &["a2a_url", "a2a_agent_card_path"];

/// `TransportConfig` variants in the order the untagged enum tries them, as
/// (key that selects it, transport name, its keys). The first variant whose
/// selecting key is present wins, and serde drops every key of the others.
const TRANSPORTS: &[(&str, &str, &[&str])] = &[
    ("command", "stdio", &["command", "cwd", "protocol_version"]),
    (
        "http_url",
        "http",
        &["http_url", "streamable_http", "protocol_version"],
    ),
    ("ws_url", "websocket", &["ws_url", "protocol_version"]),
    ("a2a_url", "a2a", A2A_BACKEND_KEYS),
];

/// Backend keys to refuse: `None` for a key nothing knows, `Some(selector)`
/// for a transport key the selected transport does not read.
type BackendFindings = BTreeMap<String, Option<&'static str>>;

/// Refuse the config file at `path` if it carries a key nothing reads.
///
/// `loaded` is the figment the config was just extracted from. Every key is
/// reported in one error, sorted. A file that cannot be read was already
/// reported by that extract.
pub(super) fn refuse_unrecognised_keys(
    source: Option<&ConfigFile>,
    loaded: &Figment,
) -> Result<()> {
    let Some(source) = source else { return Ok(()) };
    let (path, raw) = (source.path(), source.text());
    let file: Value = Config::yaml(Some(source))
        .extract()
        .map_err(super::load_error::from_figment)?;
    let mut ignored = IgnoredKeys::new();
    let mut found = ignored_by_serde(loaded, &file, &mut ignored)?;
    let backend = unread_backend_keys(raw, &mut ignored);
    found.extend(backend.keys().cloned());
    // Before the refusal, so a file that also carries a typo still says which
    // keys would have loaded. Once per key per config file: a refused reload is
    // retried every poll and must not repeat these.
    log_ignored(path, &ignored);
    let removed: Vec<(&str, &str)> = ignored
        .iter()
        .filter_map(|(key, kind)| match kind {
            Ignored::Removed(why) => Some((key.as_str(), *why)),
            _ => None,
        })
        .collect();
    let message = match (found.is_empty(), removed.is_empty()) {
        (true, true) => return Ok(()),
        (false, true) => refusal(path, &found, &backend),
        (true, false) => removed_refusal(path, &removed),
        (false, false) => format!(
            "{} {}",
            refusal(path, &found, &backend),
            removed_refusal(path, &removed)
        ),
    };
    Err(Error::ConfigValidation(message))
}

/// The refusal of keys removed in 4.0, each with why it went (MIK-8044).
/// UPGRADING quotes [`removed_reason`].
fn removed_refusal(path: &Path, removed: &[(&str, &str)]) -> String {
    let keys: Vec<&str> = removed.iter().map(|(key, _)| *key).collect();
    let mut message = format!(
        "Removed config key(s) in {}: {}.",
        path.display(),
        keys.join(", ")
    );
    for (key, why) in removed {
        let _ = write!(message, " {}", removed_reason(key, why));
    }
    message.push_str(" Run `mcp-gateway upgrade`, which deletes them, or delete them by hand.");
    message
}

/// One removed key's sentence in the refusal.
fn removed_reason(key: &str, why: &str) -> String {
    format!("`{key}` was removed in 4.0: {why}.")
}

/// The warning for a retired key that still loads; UPGRADING quotes it.
fn retired_warning(key: &str, why: &str) -> String {
    format!("`{key}` is ignored since 4.0: {why}.")
}

fn log_ignored(path: &Path, ignored: &IgnoredKeys) {
    for (key, kind) in ignored {
        if !super::log_once::first_time(&format!("strict_keys:{}:{key}", path.display())) {
            continue;
        }
        match kind {
            Ignored::Retired(why) => {
                tracing::warn!(config = %path.display(), "{}", retired_warning(key, why));
            }
            // Refused, and the refusal carries the reason.
            Ignored::Removed(_) => {}
            Ignored::Annotation => tracing::debug!(
                config = %path.display(),
                "`{key}` is an annotation (`_` or `x-` key) and is not read"
            ),
        }
    }
}

/// Paths `Config`'s own deserializer skipped that the file spells.
///
/// Runs over the very value the extract read, so type acceptance is the
/// extract's: a value only figment accepts (an enum given by index) cannot stop
/// this pass early and leave the keys after it unchecked. That value also
/// carries the env layer's `MCP_GATEWAY_*` keys, which are not the file's to
/// answer for, so only paths present in `file` are reported.
fn ignored_by_serde(
    loaded: &Figment,
    file: &Value,
    ignored: &mut IgnoredKeys,
) -> Result<BTreeSet<String>> {
    let merged: Value = loaded.extract().map_err(super::load_error::from_figment)?;
    let mut found = BTreeSet::new();
    let parsed: std::result::Result<Config, _> = serde_ignored::deserialize(&merged, |key| {
        if in_file(file, &key).is_none() {
            return;
        }
        // Classified on the real mapping keys, never the dotted rendering: a
        // key spelt `a._b` is one key named `a._b`, not an annotation.
        let path = dotted(&key);
        if let KeyPath::Map { key: leaf, .. } = &key
            && is_annotation(leaf)
        {
            ignored.insert(path, Ignored::Annotation);
        } else if let Some(kind) = segments(&key).and_then(|segs| {
            let is =
                |(p, _): &&(&[&str], &str)| segs.iter().map(String::as_str).eq(p.iter().copied());
            REMOVED_KEYS
                .iter()
                .find(is)
                .map(|(_, why)| Ignored::Removed(why))
                .or_else(|| {
                    RETIRED_KEYS
                        .iter()
                        .find(is)
                        .map(|(_, why)| Ignored::Retired(why))
                })
        }) {
            ignored.insert(path, kind);
        } else {
            found.insert(path);
        }
    });
    // Unreachable while the extract above succeeded on the same value; a
    // partial list is never reported as a clean file.
    parsed.map_err(|e| {
        Error::ConfigValidation(format!(
            "could not check config keys: {}",
            super::load_error::redact_message(&e.to_string())
        ))
    })?;
    Ok(found)
}

/// The node `key` names in `file`, if the file spells it.
fn in_file<'v>(file: &'v Value, key: &KeyPath<'_>) -> Option<&'v Value> {
    match key {
        KeyPath::Root => Some(file),
        KeyPath::Map { parent, key } => in_file(file, parent)?.as_dict()?.get(key.as_str()),
        KeyPath::Seq { parent, index } => in_file(file, parent)?.as_array()?.get(*index),
        KeyPath::Some { parent }
        | KeyPath::NewtypeStruct { parent }
        | KeyPath::NewtypeVariant { parent } => in_file(file, parent),
    }
}

/// The mapping keys from the root to `key`, or `None` through a list index.
fn segments(key: &KeyPath<'_>) -> Option<Vec<String>> {
    match key {
        KeyPath::Root => Some(Vec::new()),
        KeyPath::Seq { .. } => None,
        KeyPath::Map { parent, key } => {
            let mut segs = segments(parent)?;
            segs.push(key.clone());
            Some(segs)
        }
        KeyPath::Some { parent }
        | KeyPath::NewtypeStruct { parent }
        | KeyPath::NewtypeVariant { parent } => segments(parent),
    }
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

/// `backends.<name>.<key>` for every key outside [`KNOWN_BACKEND_KEYS`], and
/// for every key of a transport other than the one the backend selects. A
/// retired or annotation key directly under a backend goes to `ignored`.
fn unread_backend_keys(raw: &str, ignored: &mut IgnoredKeys) -> BackendFindings {
    // A repeated key fails the strict parse but loads, last value winning; the
    // loader's own reading is the fallback, so a repeat elsewhere in the file
    // cannot switch this check off (MIK-8044, B1).
    let Some(doc) = crate::yaml::from_str::<crate::yaml::Value>(raw)
        .ok()
        .or_else(|| {
            crate::yaml::from_str_loose(raw)
                .ok()
                .and_then(|dict| crate::yaml::to_value(dict).ok())
        })
    else {
        return BackendFindings::new();
    };
    let Some(backends) = doc.get("backends").and_then(crate::yaml::Value::as_mapping) else {
        return BackendFindings::new();
    };
    let mut found = BackendFindings::new();
    for (name, fields) in backends {
        let Some(name) = name.as_str() else {
            // No backend name can be read from a non-string key without
            // guessing how it would be spelled; refuse rather than skip.
            found.insert(format!("backends.{}", rendered(name)), None);
            continue;
        };
        let Some(fields) = fields.as_mapping() else {
            continue;
        };
        for key in fields.keys().filter(|k| k.as_str().is_none()) {
            found.insert(format!("backends.{name}.{}", rendered(key)), None);
        }
        let keys: Vec<&str> = fields
            .keys()
            .filter_map(crate::yaml::Value::as_str)
            .collect();
        // `url` selects what its scheme stands for, as the loader resolves it.
        let by_url = fields
            .get("url")
            .and_then(crate::yaml::Value::as_str)
            .and_then(super::backend_transport::transport_key_for);
        let selected = TRANSPORTS
            .iter()
            .filter(|(selector, ..)| is_backend_key(selector))
            .find(|(selector, ..)| keys.contains(selector) || by_url == Some(*selector));
        for key in keys {
            let path = format!("backends.{name}.{key}");
            if !is_backend_key(key) {
                if let Some((_, why)) = REMOVED_BACKEND_KEYS.iter().find(|(name, _)| *name == key) {
                    ignored.insert(path, Ignored::Removed(why));
                } else if is_annotation(key) {
                    ignored.insert(path, Ignored::Annotation);
                } else {
                    found.insert(path, None);
                }
            } else if let Some((selector, _, read)) = selected
                && !read.contains(&key)
                && TRANSPORTS.iter().any(|(.., other)| other.contains(&key))
            {
                found.insert(path, Some(*selector));
            }
        }
    }
    found
}

/// A non-string mapping key as the file spells it.
fn rendered(key: &crate::yaml::Value) -> String {
    crate::yaml::to_string(key).map_or_else(|_| "?".to_owned(), |text| text.trim_end().to_owned())
}

fn is_backend_key(key: &str) -> bool {
    KNOWN_BACKEND_KEYS.contains(&key) || (cfg!(feature = "a2a") && A2A_BACKEND_KEYS.contains(&key))
}

/// The feature a key needs when this build lacks it. Refusing such a key as a
/// misspelling would send the operator hunting for a typo that is not there.
fn missing_feature(key: &str, leaf: &str) -> Option<&'static str> {
    // A table, not a `match`: with every feature off a match folds into
    // `matches!` shape and clippy refuses that build.
    let built = [
        ("cost-governance", cfg!(feature = "cost-governance")),
        ("a2a", cfg!(feature = "a2a")),
        ("firewall", cfg!(feature = "firewall")),
    ];
    missing_feature_for(key, leaf, |feature| {
        built
            .iter()
            .find(|(name, _)| *name == feature)
            .is_none_or(|(_, on)| *on)
    })
}

/// [`missing_feature`] with the build's features as a predicate, so the
/// default build can test the entries a feature-less build would take.
fn missing_feature_for(
    key: &str,
    leaf: &str,
    enabled: impl Fn(&str) -> bool,
) -> Option<&'static str> {
    if !enabled("cost-governance") && key == "cost_governance" {
        return Some("cost-governance");
    }
    if !enabled("a2a") && key.starts_with("backends.") && A2A_BACKEND_KEYS.contains(&leaf) {
        return Some("a2a");
    }
    if !enabled("firewall") && (key == "security.firewall" || key.starts_with("security.firewall."))
    {
        return Some("firewall");
    }
    None
}

fn refusal(path: &Path, found: &BTreeSet<String>, backend: &BackendFindings) -> String {
    let keys: Vec<&str> = found.iter().map(String::as_str).collect();
    let mut message = format!(
        "Unrecognised config key(s) in {}: {}.",
        path.display(),
        keys.join(", ")
    );
    let mut misspelt = false;
    for key in found {
        let leaf = key.rsplit('.').next().unwrap_or(key);
        let unselected = backend.get(key).copied().flatten().and_then(|selector| {
            TRANSPORTS
                .iter()
                .find(|(name, ..)| *name == selector)
                .map(|(_, transport, _)| (selector, *transport))
        });
        if let Some((selector, transport)) = unselected {
            let _ = write!(
                message,
                " `{key}` is never read: `{selector}` selects the {transport} transport for that \
                 backend. Declare one transport per backend."
            );
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
#[path = "strict_keys_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "retired_settings_tests.rs"]
mod retired_settings_tests;
