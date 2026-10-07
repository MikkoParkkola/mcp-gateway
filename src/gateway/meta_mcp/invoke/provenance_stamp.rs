// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Runtime-provenance stamping of a delivered result (MIK-6905, MIK-6908),
//! split out of `invoke.rs`: behaviour unchanged.

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
        let backend_ok = !value
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let (stamped, signed_receipt) =
            augment_with_provenance(value, signer, server, tool, api_key_name, cache, backend_ok);
        if let Some(sink) = &self.claim_capture
            && let Some(call_id) = signed_receipt.receipt.call_id.clone()
        {
            let claim = crate::trust::derive_claim(client_claim);
            sink.capture(call_id, claim, signed_receipt);
        }
        stamped
    }

    /// Stamp provenance onto a result that bypassed the meta chokepoint: the
    /// direct per-backend route (the `/mcp/{name}` passthrough, rung 3) and a
    /// recovered upstream task result (MIK-8030).
    ///
    /// Tagged [`CacheOutcome::Bypass`] because neither consults the meta
    /// response cache. With stamping disabled a backend-supplied receipt is
    /// removed and nothing else changes.
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
}
