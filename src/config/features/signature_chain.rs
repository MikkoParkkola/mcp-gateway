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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// SHA-256 of the resolved seed, set when the config loads (off the async
    /// worker) so reload compares key identities with no file I/O. Never the
    /// seed itself, never serialized.
    #[serde(skip)]
    pub(crate) resolved_identity: Option<[u8; 32]>,
}

// `signing_key` may be a literal seed, so `Debug` never prints it (CWE-532).
impl std::fmt::Debug for SignatureChainConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureChainConfig")
            .field("signing_key", &"<redacted>")
            .field("key_id", &self.key_id)
            .field("emit", &self.emit)
            .field("max_links", &self.max_links)
            .field(
                "resolved_identity",
                &self.resolved_identity.map(|_| "<recorded>"),
            )
            .finish()
    }
}

impl SignatureChainConfig {
    /// Resolve the secret reference, validate the seed and key id, and build
    /// the signer. The decoded seed lives only inside the signer; errors name
    /// the field, never the seed. A seed that no longer matches the identity
    /// recorded at load is refused, so the running config always describes the
    /// key that signs.
    pub(crate) fn resolve_with_env(
        &self,
        overlay: &crate::config::EnvOverlay,
    ) -> crate::Result<crate::security::signature_chain::ChainSigner> {
        use sha2::Digest as _;
        let seed = self.seed(overlay)?;
        let identity: [u8; 32] = sha2::Sha256::digest(&seed).into();
        if self
            .resolved_identity
            .is_some_and(|recorded| recorded != identity)
        {
            return Err(crate::Error::ConfigValidation(
                "security.signature_chain.signing_key changed while the gateway started".into(),
            ));
        }
        crate::security::signature_chain::ChainSigner::from_seed(&seed, &self.key_id)
    }

    /// Validate once and record the seed's identity for reload; a section that
    /// already carries one is returned unchanged.
    pub(crate) fn resolved(mut self, overlay: &crate::config::EnvOverlay) -> crate::Result<Self> {
        use sha2::Digest as _;
        if self.resolved_identity.is_some() {
            return Ok(self);
        }
        let seed = self.seed(overlay)?;
        crate::security::signature_chain::ChainSigner::from_seed(&seed, &self.key_id)?;
        self.resolved_identity = Some(sha2::Sha256::digest(&seed).into());
        Ok(self)
    }

    /// [`Self::resolved`] on an optional section, in place.
    pub(crate) fn resolve_section(
        section: &mut Option<Self>,
        overlay: &crate::config::EnvOverlay,
    ) -> crate::Result<()> {
        *section = section.take().map(|c| c.resolved(overlay)).transpose()?;
        Ok(())
    }

    fn seed(&self, overlay: &crate::config::EnvOverlay) -> crate::Result<Vec<u8>> {
        use base64::Engine as _;
        let invalid = |field: &str, rule: &str| {
            crate::Error::ConfigValidation(format!("security.signature_chain.{field} {rule}"))
        };
        if self.key_id.is_empty() || self.key_id.len() > 64 {
            return Err(invalid("key_id", "must be 1 to 64 bytes"));
        }
        // An origin link is itself one link, so zero could never be honoured.
        if self.max_links == 0 {
            return Err(invalid("max_links", "must be at least 1"));
        }
        let seed = crate::config::secret_ref::SecretRef::parse(&self.signing_key)
            .resolve("security.signature_chain.signing_key", overlay)?;
        match base64::engine::general_purpose::STANDARD.decode(seed.trim()) {
            Ok(bytes) if bytes.len() == 32 => Ok(bytes),
            _ => Err(invalid(
                "signing_key",
                "must be a base64 32-byte Ed25519 seed",
            )),
        }
    }

    /// Name of the first identity field that differs between the running and
    /// the reloaded section; a change to any of them requires a restart.
    /// `signing_key` compares the reference text and the resolved seed
    /// identity recorded at load, so a rotated `env:`/`file:` secret behind an
    /// unchanged reference is caught without reading it again. Adding or
    /// removing the section changes the identity, so it reports `signing_key`.
    pub(crate) fn restart_changed_field(
        running: Option<&Self>,
        reloaded: Option<&Self>,
    ) -> Option<&'static str> {
        let (a, b) = match (running, reloaded) {
            (None, None) => return None,
            (Some(a), Some(b)) => (a, b),
            _ => return Some("signing_key"),
        };
        let key_changed =
            a.signing_key != b.signing_key || a.resolved_identity != b.resolved_identity;
        [
            ("signing_key", key_changed),
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
