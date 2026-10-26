// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Where new secrets saved through the gateway go (ADR-028 rule 4).

use serde::{Deserialize, Serialize};

/// `secrets:`: the store new secrets saved through the gateway are written
/// to. Existing references of every kind keep resolving whatever it says.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct SecretsConfig {
    /// `auto` (default), `keychain` or `files`.
    pub store: SecretStoreChoice,
}

/// The `secrets.store` value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum SecretStoreChoice {
    /// The OS keychain where it answers, owner-only files otherwise.
    #[default]
    Auto,
    /// The OS keychain; refused when it is unavailable, never a silent switch.
    Keychain,
    /// A new owner-only file per secret under `<config dir>/secrets/`.
    Files,
}
