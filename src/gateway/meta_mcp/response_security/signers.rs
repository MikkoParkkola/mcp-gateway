// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The result-shaping signers and the chain identity, set once at startup
//! before the router serves calls.

use std::sync::Arc;

use crate::attestation::BnautAttestationSigner;
use crate::gateway::meta_mcp::MetaMcp;

/// Result-shaping signers, set once at startup before the router serves calls.
impl MetaMcp {
    /// Enable signed runtime provenance stamping (rung 1.2).
    ///
    /// When set, every aggregated tool result is stamped with a signed
    /// `_meta.provenance` receipt. Off by default; the field is `None` unless
    /// this is called, so the stamping branch never runs on the hot path
    /// otherwise.
    pub fn enable_provenance_stamping(&mut self, signer: BnautAttestationSigner) {
        self.provenance_signer = Some(Arc::new(signer));
    }

    /// Enable public (Ed25519) provenance stamping.
    ///
    /// When set alongside the HMAC signer, every stamped result also carries
    /// a publicly verifiable Ed25519 signature.
    pub(crate) fn enable_public_provenance(
        &mut self,
        signer: crate::trust::provenance_public::ProvenancePublicSigner,
    ) {
        self.public_provenance_signer = Some(Arc::new(signer));
    }

    /// The public provenance signer, when one is installed: Activity signs
    /// its export manifests with the same key.
    #[cfg(feature = "webui")]
    pub(crate) fn public_provenance_signer(
        &self,
    ) -> Option<Arc<crate::trust::provenance_public::ProvenancePublicSigner>> {
        self.public_provenance_signer.clone()
    }

    /// Whether a public provenance signer is installed (tests only).
    #[cfg(test)]
    pub(crate) fn public_provenance_installed(&self) -> bool {
        self.public_provenance_signer.is_some()
    }

    /// Enable ASI07 origin-link emission, with increment-3 defaults for the
    /// verification trust (no trusted keys, 8 links, 300 s window).
    pub(crate) fn set_chain_signer(
        &mut self,
        signer: crate::security::signature_chain::ChainSigner,
        emit: crate::config::ChainEmit,
    ) {
        self.chain_signer = Some(Arc::new(ChainIdentity {
            signer,
            emit,
            max_links: crate::security::signature_chain::MAX_CHAIN_LINKS,
            trusted_keys: std::collections::BTreeMap::new(),
            replay_window: 300,
        }));
    }

    /// Set what upstream chains are verified against (inc3 D3).
    pub(crate) fn set_chain_trust(
        &mut self,
        max_links: usize,
        trusted_keys: TrustedKeys,
        replay_window: u64,
    ) {
        if let Some(identity) = self.chain_signer.as_mut().and_then(Arc::get_mut) {
            identity.max_links = max_links;
            identity.trusted_keys = trusted_keys;
            identity.replay_window = replay_window;
        }
    }

    /// Enable shadow claim capture (rung 3.1).
    ///
    /// Only has an observable effect once `provenance_signer` is also
    /// `Some` — capture runs alongside stamping at the same chokepoint, not
    /// independently of it.
    pub fn enable_claim_capture(&mut self, sink: Arc<crate::trust::ClaimCaptureSink>) {
        self.claim_capture = Some(sink);
    }
}

/// `security.remote_server_signing.trusted_keys`.
pub(crate) type TrustedKeys = std::collections::BTreeMap<
    String,
    crate::security::remote_provenance::TrustedRemoteServerKeyConfig,
>;

/// This gateway's chain identity and what it verifies upstream chains
/// against (ASI07 increments 2 and 3).
pub(crate) struct ChainIdentity {
    pub(crate) signer: crate::security::signature_chain::ChainSigner,
    pub(crate) emit: crate::config::ChainEmit,
    /// [`crate::security::signature_chain::MAX_CHAIN_LINKS`] in production.
    pub(crate) max_links: usize,
    pub(crate) trusted_keys: TrustedKeys,
    /// `security.message_signing.replay_window`, seconds.
    pub(crate) replay_window: u64,
}
