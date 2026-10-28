// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Request bodies of the backend add and edit routes, re-exported from
//! `backends` under their old path.

use std::collections::HashMap;

use serde::Deserialize;

/// Request body for `POST /ui/api/backends`.
#[derive(Debug, Deserialize)]
pub struct AddBackendRequest {
    /// Backend name / key.
    pub name: String,
    /// Explicit stdio command (overrides registry lookup).
    pub command: Option<String>,
    /// Explicit HTTP URL (overrides registry lookup).
    pub url: Option<String>,
    /// Human-readable description.
    pub description: Option<String>,
    /// Environment variables as `{ "KEY": "VALUE" }` map.
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Registry entry to add under `name` (the dashboard's registry mode). When
    /// absent, `name` itself is looked up in the registry.
    pub registry: Option<String>,
    /// The only tools the backend offers (`backends.<name>.allowed_tools`).
    /// Absent: every tool.
    #[serde(default)]
    pub allowed_tools: Option<Vec<String>>,
}

/// Request body for `PATCH /ui/api/backends/:name`.
#[derive(Debug, Deserialize)]
pub struct UpdateBackendRequest {
    /// New stdio command (replaces existing).
    pub command: Option<String>,
    /// New HTTP URL (replaces existing).
    pub url: Option<String>,
    /// New description.
    pub description: Option<String>,
    /// Env vars to merge (existing keys updated, new keys added; no deletion).
    pub env: Option<HashMap<String, String>>,
    /// Whether the backend is enabled.
    pub enabled: Option<bool>,
    /// Seconds of idleness after which the gateway stops this backend.
    ///
    /// Absent leaves the current setting alone. `0` clears it, meaning never
    /// stop — without an explicit clear the setting would be impossible to turn
    /// off from the panel once enabled.
    pub stop_when_idle_for_secs: Option<u64>,
    /// `allowed_tools`: absent keeps the current list, `null` removes it
    /// (every tool), a list replaces it.
    #[serde(default, deserialize_with = "present")]
    #[allow(
        clippy::option_option,
        reason = "three states on the wire: absent keeps, null clears, a list replaces"
    )]
    pub allowed_tools: Option<Option<Vec<String>>>,
}

/// A key that is present, `null` included, as `Some`; serde's default keeps
/// an absent key `None`, so a PATCH can tell "leave it" from "clear it".
#[allow(
    clippy::option_option,
    reason = "the absent/null distinction is the point of this deserializer"
)]
fn present<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}
