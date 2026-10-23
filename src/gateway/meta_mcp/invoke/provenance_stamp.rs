// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Runtime-provenance stamping of a delivered result (MIK-6905, MIK-6908),
//! split out of `invoke.rs`.
//!
//! The public seal (MIK-8398 C1c) signs only a receipt this request minted,
//! once: the mint records the receipt's HMAC signature in the request's minted
//! set, and the seal consumes it.

use serde_json::Value;

use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::support::{augment_with_provenance, strip_backend_provenance};

// MIK-8663 T3: the client claim the last provenance stamp on this thread was
// handed, so a row can check it is bound to its call. It records only; the
// stamp below behaves the same with and without it.
#[cfg(test)]
thread_local! {
    static LAST_CLIENT_CLAIM: std::cell::RefCell<Option<crate::trust::ClientClaim>> =
        const { std::cell::RefCell::new(None) };
}

/// Take the client claim the last provenance stamp on this thread was handed
/// (MIK-8663 T3).
#[cfg(test)]
pub(super) fn take_last_client_claim() -> Option<crate::trust::ClientClaim> {
    LAST_CLIENT_CLAIM.with(|last| last.borrow_mut().take())
}

tokio::task_local! {
    /// The HMAC signatures this request minted and has not sealed yet.
    static MINTED: parking_lot::Mutex<std::collections::HashSet<String>>;
}

/// Run `request` with one minted-receipt set for its whole lifetime, beside
/// the visibility memo. A request already inside one keeps it, so nested entry
/// points share the outer request's set.
///
/// The argument is boxed as `dyn Future` so the scope adds no future-type
/// depth (MIK-7678, `scripts/ci/check-recursion-margin.sh`).
pub(crate) async fn with_minted_receipts<'a, T>(
    request: std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>,
) -> T {
    if MINTED.try_with(|_| ()).is_ok() {
        return request.await;
    }
    MINTED
        .scope(
            parking_lot::Mutex::new(std::collections::HashSet::new()),
            request,
        )
        .await
}

/// Count a receipt left unsealed, by why the seal refused it.
fn note_unsealed(reason: &str) {
    telemetry_metrics::counter!(
        "mcp_public_provenance_unsealed_total",
        "reason" => reason.to_owned()
    )
    .increment(1);
}

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
        #[cfg(test)]
        LAST_CLIENT_CLAIM.with(|last| *last.borrow_mut() = client_claim.cloned());
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
        // The mint: this request may seal this receipt, once. Outside a minted
        // scope nothing is recorded and the receipt stays unsealed.
        let sig = signed_receipt.signature.clone();
        let _ = MINTED.try_with(|set| set.lock().insert(sig));
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

/// Seal one receipt this request minted, and no other.
///
/// Signs only when `object._meta.provenance` deserializes as a signed receipt
/// whose HMAC verifies under this gateway's receipt-domain key and whose
/// signature this request's minted set still holds. The seal consumes the
/// mint, so a receipt is sealed at most once; anything else is left unsealed
/// and counted, and the gateway never puts its Ed25519 signature on a receipt
/// it did not mint in this request.
///
/// Sealing principle (MIK-8398 C1g): the seal must cover the bytes as
/// delivered, so every deterministic wire transform happens before it.
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
        note_unsealed("hmac_mismatch");
        return;
    };
    if !hmac.verify_bytes(&signed.receipt.canonical_bytes(), &signature) {
        note_unsealed("hmac_mismatch");
        return;
    }
    match MINTED.try_with(|set| set.lock().remove(&signed.signature)) {
        Ok(true) => {}
        Ok(false) => return note_unsealed("not_minted"),
        Err(_) => return note_unsealed("no_scope"),
    }
    let sig = public.sign_receipt(&signed.receipt, Some(&*object));
    if let Some(obj) = object
        .pointer_mut("/_meta/provenance")
        .and_then(|v| v.as_object_mut())
        && let Ok(sig_value) = serde_json::to_value(&sig)
    {
        obj.insert("public_signature".to_owned(), sig_value);
    }
}

/// Lift `_meta.provenance` out of a dispatch result before it is wrapped.
///
/// Returns the removed receipt. `_meta` itself is dropped when the removal
/// leaves it empty, and every other `_meta` member is kept. Without a receipt
/// nothing is touched, so unstamped results keep their bytes.
pub(in crate::gateway::meta_mcp) fn lift_receipt(content: &mut Value) -> Option<Value> {
    let receipt = content
        .get_mut("_meta")
        .and_then(Value::as_object_mut)
        .and_then(|meta| meta.remove("provenance"))?;
    let meta_empty = content
        .get("_meta")
        .and_then(Value::as_object)
        .is_some_and(serde_json::Map::is_empty);
    if meta_empty && let Some(object) = content.as_object_mut() {
        object.remove("_meta");
    }
    Some(receipt)
}
