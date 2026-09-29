// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `security.signature_chain`: the gateway's Ed25519 chain identity and when it
//! emits its link (OWASP ASI07).

use serde::{Deserialize, Serialize};

/// When the origin link is emitted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainEmit {
    /// Only when the request carries a chain nonce.
    #[default]
    OnRequest,
    /// On every eligible result.
    Always,
}

const fn default_chain_max_links() -> usize {
    8
}

/// `security.signature_chain`: Ed25519 chain identity and emission policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureChainConfig {
    /// Secret reference resolving to a base64 32-byte Ed25519 seed.
    pub signing_key: String,
    /// Key id, 1..64 bytes.
    pub key_id: String,
    /// Emission mode.
    #[serde(default)]
    pub emit: ChainEmit,
    /// Maximum links accepted or produced in one chain.
    #[serde(default = "default_chain_max_links")]
    pub max_links: usize,
}

// The implementation commit wires both into config loading and reload.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "stub until the signature chain is wired")
)]
impl SignatureChainConfig {
    /// Resolve the secret reference and validate the seed and key id.
    pub(crate) fn resolve_with_env(
        &self,
        _overlay: &crate::config::EnvOverlay,
    ) -> crate::Result<Self> {
        Ok(self.clone())
    }

    /// Name of the first identity field that differs between the running and
    /// the reloaded section; a change to any of them requires a restart.
    pub(crate) fn restart_changed_field(
        _running: Option<&Self>,
        _reloaded: Option<&Self>,
    ) -> Option<&'static str> {
        None
    }
}

#[cfg(test)]
#[path = "signature_chain_config_tests.rs"]
mod signature_chain_config_tests;
