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
    /// Errors name the field, never the seed.
    pub(crate) fn resolve_with_env(
        &self,
        overlay: &crate::config::EnvOverlay,
    ) -> crate::Result<Self> {
        use base64::Engine as _;
        let invalid = |field: &str, rule: &str| {
            crate::Error::ConfigValidation(format!("security.signature_chain.{field} {rule}"))
        };
        if self.key_id.is_empty() || self.key_id.len() > 64 {
            return Err(invalid("key_id", "must be 1 to 64 bytes"));
        }
        let seed = crate::config::secret_ref::SecretRef::parse(&self.signing_key)
            .resolve("security.signature_chain.signing_key", overlay)?;
        let bytes = base64::engine::general_purpose::STANDARD.decode(seed.trim());
        if !bytes.is_ok_and(|bytes| bytes.len() == 32) {
            return Err(invalid(
                "signing_key",
                "must be a base64 32-byte Ed25519 seed",
            ));
        }
        Ok(Self {
            signing_key: seed,
            ..self.clone()
        })
    }

    /// Name of the first identity field that differs between the running and
    /// the reloaded section; a change to any of them requires a restart.
    /// Adding or removing the section changes the identity, so it reports
    /// `signing_key`.
    pub(crate) fn restart_changed_field(
        running: Option<&Self>,
        reloaded: Option<&Self>,
    ) -> Option<&'static str> {
        let (a, b) = match (running, reloaded) {
            (None, None) => return None,
            (Some(a), Some(b)) => (a, b),
            _ => return Some("signing_key"),
        };
        [
            ("signing_key", a.signing_key != b.signing_key),
            ("key_id", a.key_id != b.key_id),
            ("emit", a.emit != b.emit),
        ]
        .into_iter()
        .find_map(|(field, changed)| changed.then_some(field))
    }
}

#[cfg(test)]
#[path = "signature_chain_config_tests.rs"]
mod signature_chain_config_tests;
