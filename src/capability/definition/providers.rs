// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A capability's `providers:` block.

use std::collections::HashMap;

use serde::de::DeserializeSeed;
use serde::{Deserialize, Deserializer, Serialize};

use super::ProviderConfig;
use super::process::ProcessConfig;

/// Provider configurations supporting both named and fallback arrays
#[derive(Debug, Clone, Default)]
pub struct ProvidersConfig {
    /// Named providers (primary, secondary, etc.)
    pub named: HashMap<String, ProviderConfig>,
    /// Fallback providers (ordered list)
    pub fallback: Vec<ProviderConfig>,
    /// Keys under a provider that no field reads, as dotted paths from
    /// `providers` (`providers.primary.config.methd`). Serde ignores them, so a
    /// misspelling would load silently; the validator reports each (CAP-012).
    pub unread_keys: Vec<String>,
    /// Typed `config` of each provider whose `service` runs a local process
    /// (`cli`, `mcp`; MIK-7782), keyed like `named` (`fallback[i]` for a
    /// fallback entry). Filled at load only, so a definition built any other
    /// way has none and cannot run a process.
    pub process: HashMap<String, ProcessConfig>,
    /// Whether the file these providers came from carried a pin that matched.
    /// Only `parse_capability_file` sets [`Integrity::Verified`]; a process
    /// provider of an `Unpinned` definition never runs (MIK-7782).
    pub integrity: Integrity,
}

/// Pin state of the file a definition was loaded from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Integrity {
    /// No pin, or not loaded from a file through the pin check.
    #[default]
    Unpinned,
    /// Loaded from a file whose `sha256:` pin matched its content.
    Verified,
}

impl ProvidersConfig {
    /// Check if empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.named.is_empty() && self.fallback.is_empty()
    }

    /// Check if contains a key
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.named.contains_key(key)
    }

    /// Get a named provider
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&ProviderConfig> {
        self.named.get(key)
    }
}

/// Serialized as before (`named`, `fallback`), except that a process-running
/// provider's `config` is its typed config, which serde would otherwise drop
/// (the `config` it deserialized from was taken out at load).
impl Serialize for ProvidersConfig {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{Error as _, SerializeStruct as _};
        let render = |key: &str, provider: &ProviderConfig| {
            let mut value = serde_json::to_value(provider).map_err(S::Error::custom)?;
            if let (Some(typed), Some(object)) = (self.process.get(key), value.as_object_mut()) {
                object.insert(
                    "config".to_owned(),
                    serde_json::to_value(typed).map_err(S::Error::custom)?,
                );
            }
            Ok::<_, S::Error>(value)
        };
        let mut named = serde_json::Map::new();
        for (key, provider) in &self.named {
            named.insert(key.clone(), render(key, provider)?);
        }
        let fallback = self
            .fallback
            .iter()
            .enumerate()
            .map(|(i, provider)| render(&format!("fallback[{i}]"), provider))
            .collect::<Result<Vec<_>, _>>()?;
        let mut out = serializer.serialize_struct("ProvidersConfig", 2)?;
        out.serialize_field("named", &named)?;
        out.serialize_field("fallback", &fallback)?;
        out.end()
    }
}

impl<'de> Deserialize<'de> for ProvidersConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_providers(deserializer)
    }
}

/// Custom deserializer for providers that handles both formats:
/// - Standard: { primary: {...}, secondary: {...} }
/// - With fallback array: { primary: {...}, fallback: [{...}, {...}] }
pub(super) fn deserialize_providers<'de, D>(deserializer: D) -> Result<ProvidersConfig, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{Error as _, MapAccess, Visitor};
    use std::fmt;

    struct ProvidersVisitor;

    impl<'de> Visitor<'de> for ProvidersVisitor {
        type Value = ProvidersConfig;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a map of provider configurations")
        }

        fn visit_map<M>(self, mut map: M) -> Result<ProvidersConfig, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut named = HashMap::new();
            let mut fallback = Vec::new();
            let mut unread_keys = Vec::new();
            let mut process = HashMap::new();

            while let Some(key) = map.next_key::<String>()? {
                if key == "fallback" {
                    // A list or a single provider. A malformed entry, null included,
                    // is an error, as it is for a named provider: dropping it would
                    // hide the declaration from the CAP-011 warning (MIK-7768).
                    let value: serde_json::Value = map.next_value()?;
                    let entries = match value {
                        serde_json::Value::Array(entries) => entries,
                        single => vec![single],
                    };
                    for (idx, entry) in entries.into_iter().enumerate() {
                        let at = format!("fallback[{idx}]");
                        let (provider, typed) = read_provider(&at, entry, &mut unread_keys)
                            .map_err(M::Error::custom)?;
                        if let Some(typed) = typed {
                            process.insert(at, typed);
                        }
                        fallback.push(provider);
                    }
                } else {
                    let value: serde_json::Value = map.next_value()?;
                    let (provider, typed) =
                        read_provider(&key, value, &mut unread_keys).map_err(M::Error::custom)?;
                    if let Some(typed) = typed {
                        process.insert(key.clone(), typed);
                    }
                    named.insert(key, provider);
                }
            }

            Ok(ProvidersConfig {
                named,
                fallback,
                unread_keys,
                process,
                integrity: Integrity::Unpinned,
            })
        }
    }

    deserializer.deserialize_map(ProvidersVisitor)
}

/// Read one provider from its buffered value.
///
/// A `cli` or `mcp` provider's `config` is taken out and parsed strictly into
/// its typed form (MIK-7782); the rest of the provider, and every other
/// service's whole provider, goes through the unread-key tracking below.
fn read_provider(
    name: &str,
    mut value: serde_json::Value,
    unread: &mut Vec<String>,
) -> Result<(ProviderConfig, Option<ProcessConfig>), String> {
    let service = value
        .get("service")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let typed = if matches!(service.as_str(), "cli" | "mcp") {
        let config = value
            .as_object_mut()
            .and_then(|provider| provider.remove("config"));
        ProcessConfig::from_provider(&service, config)
            .map_err(|e| format!("providers.{name}.config: {e}"))?
    } else {
        None
    };
    let provider = Tracked(name, unread)
        .deserialize(value)
        .map_err(|e| format!("providers.{name}: {e}"))?;
    Ok((provider, typed))
}

/// Deserialize one provider, recording every key it does not read.
///
/// Annotation keys (`_` or `x-` first, as in the gateway config) are the
/// author's own notes and are not recorded.
struct Tracked<'a>(&'a str, &'a mut Vec<String>);

impl<'de> DeserializeSeed<'de> for Tracked<'_> {
    type Value = ProviderConfig;

    fn deserialize<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<ProviderConfig, D::Error> {
        let Tracked(name, unread) = self;
        serde_ignored::deserialize(deserializer, |path| {
            let mut segments = Vec::new();
            let leaf = key_segments(&path, &mut segments);
            if !leaf.is_some_and(|k| k.starts_with('_') || k.starts_with("x-")) {
                unread.push(format!("providers.{name}.{}", segments.join(".")));
            }
        })
    }
}

/// Collect `path`'s segments as an author wrote them, and return its last
/// mapping key. Structured rather than parsed from the `Display` string: a key
/// may itself contain `.`, and `serde_ignored` renders the inside of an
/// `Option` as `?`, a segment no author typed.
fn key_segments(path: &serde_ignored::Path<'_>, out: &mut Vec<String>) -> Option<String> {
    use serde_ignored::Path;
    match path {
        Path::Root => None,
        Path::Seq { parent, index } => {
            key_segments(parent, out);
            out.push(index.to_string());
            None
        }
        Path::Map { parent, key } => {
            key_segments(parent, out);
            out.push(key.clone());
            Some(key.clone())
        }
        Path::Some { parent }
        | Path::NewtypeStruct { parent }
        | Path::NewtypeVariant { parent } => key_segments(parent, out),
    }
}
