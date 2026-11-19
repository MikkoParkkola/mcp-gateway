// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Load-time rules for `rate_limit` and `attribution`, and strict keys for a
//! capability, its providers and their `rate_limit`. Judged where every
//! reader of a capability file parses it (`parse_capability_text`).
//!
//! Strict keys are checked on the raw document before the typed parse, so a
//! misspelt key is named even when the typed parse would first fail on the
//! field it was meant to be. `metadata` and a provider's `config` stay
//! lenient; keys starting `_` or `x-` are the author's notes and always pass.

use std::path::Path;

use serde_json::Value;

use crate::{Error, Result};

use super::CapabilityDefinition;

/// Every top-level field of [`CapabilityDefinition`].
const CAPABILITY_KEYS: &[&str] = &[
    "attribution",
    "auth",
    "cache",
    "description",
    "fulcrum",
    "metadata",
    "name",
    "projection",
    "providers",
    "response_transform",
    "schema",
    "sha256",
    "transform",
    "visible_in_states",
    "webhooks",
];

/// Every field of a provider ([`super::ProviderConfig`]).
const PROVIDER_KEYS: &[&str] = &[
    "config",
    "cost_per_call",
    "rate_limit",
    "service",
    "timeout",
];

/// Every field of [`super::RateLimit`].
const RATE_LIMIT_KEYS: &[&str] = &["interval_ms"];

/// The bounds of `rate_limit.interval_ms`.
pub(crate) const INTERVAL_MS: std::ops::RangeInclusive<u64> = 1..=600_000;

fn refuse(file: &Path, message: impl std::fmt::Display) -> Error {
    Error::Config(format!("{}: {message}", file.display()))
}

fn is_note(key: &str) -> bool {
    key.starts_with('_') || key.starts_with("x-")
}

/// Refuse the first key of `map` that `accepted` does not list.
fn check_keys(file: &Path, map: &Value, accepted: &[&str], what: &str) -> Result<()> {
    let Some(map) = map.as_object() else {
        return Ok(());
    };
    for key in map.keys() {
        if is_note(key) || accepted.contains(&key.as_str()) {
            continue;
        }
        let hint = crate::gateway::did_you_mean(key, accepted, 3, 1)
            .unwrap_or_else(|| format!("Accepted keys: {}.", accepted.join(", ")));
        return Err(refuse(
            file,
            format!("key `{key}` is not a {what} field. {hint}"),
        ));
    }
    Ok(())
}

/// The providers of a raw document, each with the path an author reads.
fn raw_providers(document: &Value) -> Vec<(String, &Value)> {
    let mut out = Vec::new();
    let Some(providers) = document.get("providers").and_then(Value::as_object) else {
        return out;
    };
    for (name, provider) in providers {
        if name == "fallback" {
            let entries = match provider {
                Value::Array(entries) => entries.iter().collect(),
                single => vec![single],
            };
            for (i, entry) in entries.into_iter().enumerate() {
                out.push((format!("providers.fallback[{i}]"), entry));
            }
        } else {
            out.push((format!("providers.{name}"), provider));
        }
    }
    out
}

/// Strict keys on the raw document: the capability, each provider and each
/// provider's `rate_limit`.
pub(crate) fn check_raw(file: &Path, content: &str) -> Result<()> {
    // A document that is not YAML is the typed parse's to report.
    let Ok(document) = crate::yaml::from_str::<Value>(content) else {
        return Ok(());
    };
    check_keys(file, &document, CAPABILITY_KEYS, "capability")?;
    for (_, provider) in raw_providers(&document) {
        check_keys(file, provider, PROVIDER_KEYS, "capability provider")?;
        if let Some(rate) = provider.get("rate_limit") {
            check_keys(file, rate, RATE_LIMIT_KEYS, "rate_limit")?;
        }
    }
    Ok(())
}

/// The rules on a parsed definition: `rate_limit` bounds, REST only, a fixed
/// host; `attribution` non-empty, on an object output that declares it.
pub(crate) fn check_parsed(file: &Path, capability: &CapabilityDefinition) -> Result<()> {
    let providers = capability
        .providers
        .named
        .iter()
        .map(|(name, p)| (format!("providers.{name}"), p))
        .chain(
            capability
                .providers
                .fallback
                .iter()
                .enumerate()
                .map(|(i, p)| (format!("providers.fallback[{i}]"), p)),
        );
    for (at, provider) in providers {
        let Some(rate) = provider.rate_limit else {
            continue;
        };
        if !INTERVAL_MS.contains(&rate.interval_ms) {
            return Err(refuse(
                file,
                format!(
                    "{at}.rate_limit.interval_ms is {}; it must be a whole number of \
                     milliseconds from 1 to 600000",
                    rate.interval_ms
                ),
            ));
        }
        // REST is what dispatch runs it as: an unnamed or unlisted service
        // falls back to REST (`ProviderConfig::protocol_config`).
        // A process provider (cli, mcp) has no host to pace.
        if provider.protocol_config().protocol_name() != "rest"
            || matches!(provider.service.as_str(), "cli" | "mcp")
        {
            return Err(refuse(
                file,
                format!(
                    "{at}.rate_limit is for REST providers; this provider's service is {}",
                    provider.service
                ),
            ));
        }
        if templated_host(provider) {
            return Err(refuse(
                file,
                format!("{at}.rate_limit needs a fixed host; the endpoint's host is templated"),
            ));
        }
        // A URL with no host key would load paced on paper and unpaced in
        // fact: pacing counts by host.
        let url = crate::capability::pacing::configured_url(&provider.config);
        if crate::capability::pacing::host_key(&url).is_none() {
            return Err(refuse(
                file,
                format!("{at}.rate_limit needs a fixed host; its URL has none"),
            ));
        }
    }
    if let Some(text) = &capability.attribution {
        check_attribution(file, text, &capability.schema.output)?;
    }
    Ok(())
}

/// Whether the host part of the provider's endpoint holds a `{placeholder}`.
fn templated_host(provider: &super::ProviderConfig) -> bool {
    let url = if provider.config.endpoint.is_empty() {
        &provider.config.base_url
    } else {
        &provider.config.endpoint
    };
    let rest = url.split_once("://").map_or(url.as_str(), |(_, rest)| rest);
    rest.split('/')
        .next()
        .is_some_and(|authority| authority.contains('{'))
}

fn check_attribution(file: &Path, text: &str, output: &Value) -> Result<()> {
    if text.trim().is_empty() {
        return Err(refuse(file, "attribution is empty"));
    }
    // The same judgement publication makes: a root that is not an object
    // (a type list included) is published under `items`, where a credit
    // cannot be set.
    if crate::capability::output_root_is_wrapped(output) {
        let shown = match output.get("type") {
            Some(Value::String(ty)) => ty.clone(),
            Some(other) => other.to_string(),
            None => "untyped".to_owned(),
        };
        return Err(refuse(
            file,
            format!(
                "attribution is declared, so schema.output must be an object; this one is {shown}"
            ),
        ));
    }
    let declared = output
        .pointer("/properties/attribution/type")
        .and_then(Value::as_str)
        == Some("string");
    if declared {
        Ok(())
    } else {
        Err(refuse(
            file,
            "attribution is declared, so schema.output must declare an `attribution` string \
             property",
        ))
    }
}
