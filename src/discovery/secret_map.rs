// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Environment variables and HTTP headers a discovered server carries (#1876).
//!
//! Both routinely hold credentials: API keys in `env`, bearer tokens in
//! `headers`. The values reach exactly one place, the backend written to the
//! owner-only gateway config (`SecretMap::expose` feeds
//! [`super::DiscoveredServer::to_backend_config`]). Everything else that
//! formats a discovered server (`Debug`, discovery JSON/YAML and shadow
//! reports, logs, errors) sees the keys only.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize, Serializer};

/// Placeholder emitted in place of every value outside the config writer.
pub const REDACTED: &str = "<redacted>";

/// A key-to-value map whose values never leave through `Debug` or `Serialize`.
#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct SecretMap(BTreeMap<String, String>);

impl SecretMap {
    /// Wrap `map`.
    #[must_use]
    pub fn new(map: BTreeMap<String, String>) -> Self {
        Self(map)
    }

    /// The keys, in order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }

    /// Whether the map is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The values themselves, for the config writer
    /// ([`super::DiscoveredServer::to_backend_config`]) only. Private to
    /// `discovery`: elsewhere the values are reachable only through that
    /// method, never around the redacting `Debug`/`Serialize` below.
    #[must_use]
    pub(super) fn expose(&self) -> &BTreeMap<String, String> {
        &self.0
    }
}

impl fmt::Debug for SecretMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.0.keys().map(|k| (k, REDACTED)))
            .finish()
    }
}

impl Serialize for SecretMap {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.0.keys().map(|k| (k, REDACTED)))
    }
}

impl FromIterator<(String, String)> for SecretMap {
    fn from_iter<I: IntoIterator<Item = (String, String)>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENTINEL: &str = "SENTINEL-1876-secret-value";

    fn map() -> SecretMap {
        [("API_KEY".to_string(), SENTINEL.to_string())]
            .into_iter()
            .collect()
    }

    #[test]
    fn debug_shows_keys_never_values() {
        let text = format!("{:?} {:#?}", map(), map());
        assert!(text.contains("API_KEY"), "{text}");
        assert!(!text.contains(SENTINEL), "{text}");
    }

    #[test]
    fn serialize_shows_keys_never_values() {
        let json = serde_json::to_string(&map()).unwrap();
        let yaml = serde_yaml::to_string(&map()).unwrap();
        for text in [json, yaml] {
            assert!(text.contains("API_KEY"), "{text}");
            assert!(!text.contains(SENTINEL), "{text}");
        }
    }

    #[test]
    fn expose_returns_the_values() {
        assert_eq!(map().expose()["API_KEY"], SENTINEL);
    }
}
