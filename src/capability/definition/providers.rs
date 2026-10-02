// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A capability's `providers:` block.

use std::collections::HashMap;

use serde::de::DeserializeSeed;
use serde::{Deserialize, Deserializer, Serialize};

use super::ProviderConfig;

/// Provider configurations supporting both named and fallback arrays
#[derive(Debug, Clone, Default, Serialize)]
pub struct ProvidersConfig {
    /// Named providers (primary, secondary, etc.)
    pub named: HashMap<String, ProviderConfig>,
    /// Fallback providers (ordered list)
    pub fallback: Vec<ProviderConfig>,
    /// Keys under a provider that no field reads, as dotted paths from
    /// `providers` (`providers.primary.config.methd`). Serde ignores them, so a
    /// misspelling would load silently; the validator reports each (CAP-012).
    #[serde(skip)]
    pub unread_keys: Vec<String>,
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
                        let provider = Tracked(&at, &mut unread_keys)
                            .deserialize(entry)
                            .map_err(M::Error::custom)?;
                        fallback.push(provider);
                    }
                } else {
                    let provider = map.next_value_seed(Tracked(&key, &mut unread_keys))?;
                    named.insert(key, provider);
                }
            }

            Ok(ProvidersConfig {
                named,
                fallback,
                unread_keys,
            })
        }
    }

    deserializer.deserialize_map(ProvidersVisitor)
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
            // `serde_ignored` writes `?` for the inside of an `Option`
            // (`path_selector.?.typo`); an author never typed it.
            let path = path.to_string();
            let segments: Vec<&str> = path.split('.').filter(|s| *s != "?").collect();
            let leaf = segments.last().copied().unwrap_or_default();
            if !leaf.starts_with('_') && !leaf.starts_with("x-") {
                unread.push(format!("providers.{name}.{}", segments.join(".")));
            }
        })
    }
}
