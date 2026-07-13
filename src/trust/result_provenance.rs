// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Runtime result-provenance receipts.
//!
//! The gateway is the one component that observes un-fakeable *runtime*
//! provenance of every proxied tool call: which backend answered, when, under
//! which auth context, whether the response came from cache, and whether the
//! backend reported an error. This module models that as a facts-only receipt.
//!
//! Design contract (MIK-6905, rung 1):
//! - **Facts, not judgments.** A receipt records what was observed. It never
//!   infers meaning. In particular an absent [`RuntimeProvenanceReceipt::row_count`]
//!   means "not observed", never "zero rows"; an empty successful result is
//!   never rendered as an authoritative negative. Consumers decide what the
//!   facts mean.
//! - **Observed evidence only.** Every receipt carries
//!   [`TrustEvidenceKind::Observed`] and [`CbomSubjectKind::Runtime`] — this is
//!   the data-plane sibling of the capability-definition provenance already
//!   modelled in [`super`].
//! - **No secrets.** Only a *reference* to the auth context (an opaque
//!   handle/hash chosen by the caller) is ever stored, never a raw credential,
//!   token, or backend-internal string (keeps the CWE-532 leak lint green).

use serde::{Deserialize, Serialize};

use super::{CbomSubjectKind, TrustEvidenceKind};
use crate::attestation::SIGNING_ALGORITHM;
use crate::attestation::signer::BnautAttestationSigner;
use crate::hashing::canonical_json;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Where a proxied result came from with respect to the response cache.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CacheOutcome {
    /// Served from a warm cache entry.
    Hit,
    /// Fetched live from the backend (no usable cache entry).
    Miss,
    /// Cache was intentionally bypassed for this call.
    Bypass,
}

/// A facts-only receipt of one observed runtime tool call.
///
/// Serialized form is additive metadata destined for the MCP `_meta.provenance`
/// channel. It carries no tool-result content and mutates no payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeProvenanceReceipt {
    /// CBOM subject kind. Always [`CbomSubjectKind::Runtime`] for a receipt.
    pub subject_kind: CbomSubjectKind,
    /// Identifier of the backend/server that answered the call.
    pub backend_id: String,
    /// Name of the tool that was invoked.
    pub tool: String,
    /// RFC-3339 wall-clock instant the result was observed at the gateway.
    pub observed_at: String,
    /// Opaque reference to the caller's auth context (hash/handle), never a raw
    /// credential. `None` when the call was unauthenticated or no reference was
    /// available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_context_ref: Option<String>,
    /// Whether the result was served from cache, fetched live, or bypassed cache.
    pub cache: CacheOutcome,
    /// Observed row/item count when the backend exposes one. `None` = not
    /// observed (NOT zero — see module contract).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row_count: Option<u64>,
    /// Whether the backend reported success (`isError == false`).
    pub backend_ok: bool,
    /// Evidence quality. Always [`TrustEvidenceKind::Observed`].
    pub evidence_kind: TrustEvidenceKind,
}

impl RuntimeProvenanceReceipt {
    /// Construct a receipt from observed facts.
    ///
    /// `evidence_kind` and `subject_kind` are fixed to `Observed`/`Runtime` —
    /// this constructor is the only sanctioned way to build a receipt, so those
    /// invariants cannot be violated at a call site.
    pub fn observed(
        backend_id: impl Into<String>,
        tool: impl Into<String>,
        observed_at: impl Into<String>,
        cache: CacheOutcome,
        backend_ok: bool,
    ) -> Self {
        Self {
            subject_kind: CbomSubjectKind::Runtime,
            backend_id: backend_id.into(),
            tool: tool.into(),
            observed_at: observed_at.into(),
            auth_context_ref: None,
            cache,
            row_count: None,
            backend_ok,
            evidence_kind: TrustEvidenceKind::Observed,
        }
    }

    /// Attach an opaque auth-context reference (hash/handle, never a raw secret).
    #[must_use]
    pub fn with_auth_context_ref(mut self, auth_context_ref: impl Into<String>) -> Self {
        self.auth_context_ref = Some(auth_context_ref.into());
        self
    }

    /// Attach an observed row/item count.
    #[must_use]
    pub fn with_row_count(mut self, row_count: u64) -> Self {
        self.row_count = Some(row_count);
        self
    }

    /// Canonical (deterministic key-order) JSON bytes of this receipt.
    ///
    /// This is the exact payload signed by the attestation signer in rung 1.3,
    /// so key ordering must be stable regardless of struct field order.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // A receipt is a fixed flat struct of primitives — serialization to a
        // `Value` cannot fail; fall back to an empty object if it ever did
        // rather than panic on the hot path.
        let value = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        canonical_json(&value).into_bytes()
    }

    /// Sign this receipt with the gateway's attestation signer.
    ///
    /// The HMAC covers [`Self::canonical_bytes`], so a receipt and its
    /// signature travel together in `_meta.provenance`. Verification is owned by
    /// [`crate::attestation::AttestationValidator::verify_result_provenance`].
    #[must_use]
    pub fn sign(&self, signer: &BnautAttestationSigner) -> SignedResultProvenance {
        let signature = signer.sign_bytes(&self.canonical_bytes());
        SignedResultProvenance {
            receipt: self.clone(),
            key_id: signer.key_id().to_string(),
            algorithm: SIGNING_ALGORITHM.to_string(),
            signature: URL_SAFE_NO_PAD.encode(signature),
        }
    }
}

/// A [`RuntimeProvenanceReceipt`] plus its detached HMAC signature.
///
/// This is the object that lands in the MCP `_meta.provenance` channel. It is
/// additive metadata — it carries no tool-result content and mutates no payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedResultProvenance {
    /// The observed facts.
    pub receipt: RuntimeProvenanceReceipt,
    /// Namespaced identifier of the signing key (`bnaut/...`).
    pub key_id: String,
    /// Signing algorithm, e.g. `HS256`.
    pub algorithm: String,
    /// base64url(no-pad) HMAC over `receipt.canonical_bytes()`.
    pub signature: String,
}

impl SignedResultProvenance {
    /// Decode the detached signature back to raw bytes, or `None` if the
    /// encoding is malformed.
    #[must_use]
    pub fn signature_bytes(&self) -> Option<Vec<u8>> {
        URL_SAFE_NO_PAD.decode(self.signature.as_bytes()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RuntimeProvenanceReceipt {
        RuntimeProvenanceReceipt::observed(
            "github",
            "search_issues",
            "2026-07-13T10:15:30Z",
            CacheOutcome::Miss,
            true,
        )
    }

    #[test]
    fn observed_receipt_is_always_observed_runtime_evidence() {
        let r = sample();
        assert_eq!(r.evidence_kind, TrustEvidenceKind::Observed);
        assert_eq!(r.subject_kind, CbomSubjectKind::Runtime);
    }

    #[test]
    fn defaults_carry_no_optional_facts() {
        let r = sample();
        // Absent count means "not observed", never zero.
        assert!(r.row_count.is_none());
        assert!(r.auth_context_ref.is_none());
    }

    #[test]
    fn builders_attach_optional_facts() {
        let r = sample()
            .with_auth_context_ref("sha256:deadbeef")
            .with_row_count(0);
        assert_eq!(r.auth_context_ref.as_deref(), Some("sha256:deadbeef"));
        // Explicit zero IS representable — it is only *absence* that must not
        // be read as zero.
        assert_eq!(r.row_count, Some(0));
    }

    #[test]
    fn canonical_bytes_are_key_order_stable() {
        // Two receipts with identical facts produce byte-identical canonical
        // JSON — the signing invariant for rung 1.3.
        assert_eq!(sample().canonical_bytes(), sample().canonical_bytes());
    }

    #[test]
    fn optional_fields_omitted_from_serialization_when_absent() {
        let json = serde_json::to_string(&sample()).unwrap();
        assert!(!json.contains("row_count"));
        assert!(!json.contains("auth_context_ref"));
    }

    #[test]
    fn serialization_round_trips() {
        let r = sample().with_auth_context_ref("ref-1").with_row_count(42);
        let json = serde_json::to_string(&r).unwrap();
        let back: RuntimeProvenanceReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}
