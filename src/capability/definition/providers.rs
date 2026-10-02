// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A capability's `providers:` block.

use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize};

use super::ProviderConfig;

/// Provider configurations supporting both named and fallback arrays
#[derive(Debug, Clone, Default, Serialize)]
pub struct ProvidersConfig {
    /// Named providers (primary, secondary, etc.)
    pub named: HashMap<String, ProviderConfig>,
    /// Fallback providers (ordered list)
    pub fallback: Vec<ProviderConfig>,
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
                    for entry in entries {
                        fallback.push(serde_json::from_value(entry).map_err(M::Error::custom)?);
                    }
                } else {
                    let provider: ProviderConfig = map.next_value()?;
                    named.insert(key, provider);
                }
            }

            Ok(ProvidersConfig { named, fallback })
        }
    }

    deserializer.deserialize_map(ProvidersVisitor)
}
