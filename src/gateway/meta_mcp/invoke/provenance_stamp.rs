// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Runtime-provenance stamping of a delivered result (MIK-6905, MIK-6908),
//! split out of `invoke.rs`: behaviour unchanged.

use std::borrow::Cow;

use serde_json::Value;

use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::support::{augment_with_provenance, strip_backend_provenance};

impl MetaMcp {
    /// Stamp a signed runtime-provenance receipt into `value._meta` when
    /// provenance stamping is enabled (MIK-6905). No-op when the signer is
    /// absent, so payloads stay byte-identical with the feature off.
    ///
    /// `backend_ok` is derived from the result's `isError` flag so cache hits
    /// carrying a stored error are reported honestly.
    ///
    /// When shadow claim capture is also enabled (MIK-6908, rung 3.1), this
    /// is the single chokepoint both the meta and direct-route call paths
    /// funnel through, so a call whose receipt carries a `call_id` is
    /// shadow-captured here alongside the derived claim. A `call_id`-less
    /// receipt (no trace scope active) is skipped rather than captured
    /// un-joinable — consistent with `score_corpus`'s mis-join contract,
    /// which treats a missing join key as unscoreable, not as evidence.
    ///
    /// `client_claim` is the MIK-6914 Option B claim-under-test — an untrusted
    /// typed claim the caller supplied for this call. When present it is
    /// captured verbatim as the claim under scrutiny; when absent, capture
    /// falls back to the honest `Claim::Succeeded` floor. It is never used as
    /// the ground-truth leg (that is the receipt's extractor-observed
    /// `row_count`).
    pub(super) fn maybe_stamp_provenance(
        &self,
        mut value: Value,
        server: &str,
        tool: &str,
        api_key_name: Option<&str>,
        cache: crate::trust::CacheOutcome,
        client_claim: Option<&crate::trust::ClientClaim>,
    ) -> Value {
        // Only this gateway may put a signature chain on a result (ASI07).
        crate::security::signature_chain::strip_chain(&mut value);
        let Some(ref signer) = self.provenance_signer else {
            // Stamping off: any `_meta.provenance` is backend-injected. Strip
            // it so it cannot pass as a gateway receipt (MIK-6909).
            return strip_backend_provenance(value);
        };
        // A receipt states when the gateway observed the call. On a clock
        // before 1970 there is no honest time: no receipt is written, and a
        // backend-supplied one is stripped, so provenance reads as absent.
        let Ok(observed_at) = crate::clock::utc_now().map(|now| now.to_rfc3339()) else {
            return strip_backend_provenance(value);
        };
        let backend_ok = !value
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let (stamped, signed_receipt) = augment_with_provenance(
            value,
            signer,
            server,
            tool,
            api_key_name,
            cache,
            backend_ok,
            observed_at,
        );
        if let Some(sink) = &self.claim_capture
            && let Some(call_id) = signed_receipt.receipt.call_id.clone()
        {
            let claim = crate::trust::derive_claim(client_claim);
            sink.capture(call_id, claim, signed_receipt);
        }
        stamped
    }

    /// Stamp provenance onto an upstream task result recovered after its call
    /// returned (MIK-8030), through the same chokepoint as a live call.
    ///
    /// Tagged [`CacheOutcome::Miss`], as the live path tags its own fetches:
    /// the result came from the backend, and no cache was skipped on purpose.
    /// With stamping disabled a backend-supplied receipt is removed.
    #[must_use]
    pub fn stamp_recovered_result(
        &self,
        result: Value,
        backend_id: &str,
        tool: &str,
        api_key_name: Option<&str>,
    ) -> Value {
        // A recovered result carries no gateway-parsed `_claim` directive.
        self.maybe_stamp_provenance(
            result,
            backend_id,
            tool,
            api_key_name,
            crate::trust::CacheOutcome::Miss,
            None,
        )
    }

    /// Stamp provenance onto a direct per-backend route result (the
    /// `/mcp/{name}` passthrough, which bypasses the meta chokepoint — rung 3).
    ///
    /// Tagged [`CacheOutcome::Bypass`] because the direct route never consults
    /// the meta response cache. With stamping disabled a backend-supplied
    /// receipt is removed and nothing else changes.
    #[must_use]
    pub fn stamp_direct_result(
        &self,
        result: Value,
        backend_id: &str,
        tool: &str,
        api_key_name: Option<&str>,
    ) -> Value {
        self.maybe_stamp_provenance(
            result,
            backend_id,
            tool,
            api_key_name,
            crate::trust::CacheOutcome::Bypass,
            // The direct passthrough carries no gateway-parsed `_claim`
            // directive, so there is no client claim-under-test here.
            None,
        )
    }

    pub(crate) fn seal_public_provenance(&self, result: &mut Value) {
        let Some(public) = self.public_provenance_signer.as_deref() else {
            return;
        };
        let Some(hmac) = self.provenance_signer.as_deref() else {
            return;
        };
        seal_receipt(public, hmac, result);
    }
}

/// Seal one receipt this gateway itself signed, and no other.
///
/// Signs only when `object._meta.provenance` deserializes as a signed receipt
/// whose HMAC verifies under this gateway's receipt-domain key; anything else
/// is left unsealed, so the gateway never puts its Ed25519 signature on a
/// receipt it did not issue.
pub(in crate::gateway::meta_mcp) fn seal_receipt(
    public: &crate::trust::provenance_public::ProvenancePublicSigner,
    hmac: &crate::attestation::BnautAttestationSigner,
    object: &mut Value,
) {
    let Some(prov) = object.pointer("/_meta/provenance").cloned() else {
        return;
    };
    let Ok(signed) = serde_json::from_value::<crate::trust::SignedResultProvenance>(prov) else {
        return;
    };
    let Some(signature) = signed.signature_bytes() else {
        return;
    };
    if !hmac.verify_bytes(&signed.receipt.canonical_bytes(), &signature) {
        return;
    }
    let sig = public.sign_receipt(&signed.receipt, Some(&*object));
    if let Some(obj) = object
        .pointer_mut("/_meta/provenance")
        .and_then(|v| v.as_object_mut())
    {
        if let Ok(sig_value) = serde_json::to_value(&sig) {
            obj.insert("public_signature".to_owned(), sig_value);
        }
    }
}

/// Seal the step receipts nested in a chain or playbook answer, and only those.
///
/// Every `results[i].result` that is an object and every `output.<step>` member
/// that is an object is sealed; nothing else is visited and there is no generic
/// recursion, so a mapped playbook output carries no step receipt.
pub(in crate::gateway::meta_mcp) fn seal_step_receipts(
    public: &crate::trust::provenance_public::ProvenancePublicSigner,
    hmac: &crate::attestation::BnautAttestationSigner,
    content: &mut Value,
) {
    if let Some(results) = content.get_mut("results").and_then(Value::as_array_mut) {
        for element in results.iter_mut() {
            if let Some(result) = element.get_mut("result").filter(|v| v.is_object()) {
                seal_receipt(public, hmac, result);
            }
        }
    }
    if let Some(output) = content.get_mut("output").and_then(Value::as_object_mut) {
        for value in output.values_mut().filter(|v| v.is_object()) {
            seal_receipt(public, hmac, value);
        }
    }
}

/// Lift `_meta.provenance` out of a dispatch result before it is wrapped.
///
/// Returns the content without the receipt alongside the removed receipt.
/// `_meta` itself is dropped when the removal leaves it empty, and every
/// other `_meta` member is kept. Without a receipt the content is borrowed
/// and nothing is cloned, so unstamped results keep their bytes.
pub(in crate::gateway::meta_mcp) fn lift_receipt(
    content: &Value,
) -> (Cow<'_, Value>, Option<Value>) {
    let has_receipt = content
        .get("_meta")
        .and_then(Value::as_object)
        .is_some_and(|meta| meta.contains_key("provenance"));
    if !has_receipt {
        return (Cow::Borrowed(content), None);
    }
    let mut lifted = content.clone();
    let receipt = lifted
        .get_mut("_meta")
        .and_then(Value::as_object_mut)
        .and_then(|meta| meta.remove("provenance"));
    let meta_empty = lifted
        .get("_meta")
        .and_then(Value::as_object)
        .is_some_and(|meta| meta.is_empty());
    if meta_empty && let Some(object) = lifted.as_object_mut() {
        object.remove("_meta");
    }
    (Cow::Owned(lifted), receipt)
}
