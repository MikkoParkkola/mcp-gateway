// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The runtime provenance signer's key and its fail-closed install decision
//! (MIK-6905, MIK-6909).

/// The provenance signing key and its key id.
///
/// Read through the env overlay rather than `std::env`: env files load into an
/// in-memory overlay, so a key an env file assigns never reaches the process
/// environment and a `std::env` read would leave the signer uninstalled.
pub(super) fn provenance_key(env: &crate::config::EnvOverlay) -> (String, String) {
    (
        env.resolve(crate::attestation::ATTESTATION_SIGNING_KEY_ENV)
            .unwrap_or_default(),
        env.resolve(crate::attestation::ATTESTATION_KEY_ID_ENV)
            .unwrap_or_else(|| "gateway".to_string()),
    )
}

/// Decide whether to install a provenance-receipt signer for runtime
/// stamping (MIK-6905) — the unit-testable core of the bootstrap decision in
/// [`super::Gateway::build_meta_mcp`], which performs no process-environment reads
/// itself.
///
/// Fails closed: a key that is empty, or empty after trimming whitespace,
/// returns `None` (no signer installed, stamping stays disabled and output
/// is byte-identical to stamping-off) rather than installing a signer whose
/// signatures are trivially forgeable — an empty or whitespace-only HMAC key
/// is a known/low-entropy key, so anyone can compute a signature that a
/// validator sharing the same key would accept (MIK-6909 item 1).
///
/// The returned signer's key material is the HKDF-SHA256 receipt-domain
/// subkey ([`crate::attestation::RESULT_PROVENANCE_DOMAIN_INFO`]) derived
/// from `signing_key`, not `signing_key` itself — domain-separated from
/// inbound attestation-token verification so a leak in one channel cannot
/// forge the other (MIK-6909 item 2).
#[must_use]
pub(super) fn resolve_provenance_signer(
    signing_key: &str,
    key_id: &str,
) -> Option<crate::attestation::BnautAttestationSigner> {
    if signing_key.trim().is_empty() {
        None
    } else {
        let base = crate::attestation::BnautAttestationSigner::new(
            signing_key.as_bytes().to_vec(),
            key_id.to_string(),
        );
        Some(base.derive_domain(crate::attestation::RESULT_PROVENANCE_DOMAIN_INFO))
    }
}
