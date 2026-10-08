// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Capability calls with caller identity, client claims and projection.

use serde_json::Value;

use super::output_shape::{apply_validated_output, extract_output_validation_target};
use crate::Result;

pub(super) async fn call_capability_tool_with_identity(
    cap: &crate::capability::CapabilityBackend,
    tool: &str,
    arguments: Value,
    context: crate::capability::CapabilityExecutionContext,
) -> Result<crate::protocol::ToolsCallResult> {
    cap.call_tool_with_context(tool, arguments, context).await
}

/// Strip and parse the MIK-6914 Option B claim-under-test (`_claim`) directive
/// from an invocation's arguments, binding it to this call's `call_id`.
///
/// The directive is a gateway directive, not an upstream parameter, so it is
/// removed from `arguments` (like `_full`) and never forwarded to a backend. A
/// malformed or absent directive yields `None`, and capture then falls back to
/// the honest `Claim::Succeeded` floor. The parsed claim is untrusted client
/// input: it is only ever the claim-under-test, never the ground-truth leg.
pub(super) fn extract_client_claim(
    arguments: &mut Value,
    call_id: &str,
) -> Option<crate::trust::ClientClaim> {
    let raw = arguments.as_object_mut()?.remove("_claim")?;
    let claim = serde_json::from_value::<crate::trust::provenance_eval::Claim>(raw).ok()?;
    Some(crate::trust::ClientClaim::untrusted(call_id, claim))
}

/// Apply a capability's canonical [`ProjectionSpec`](crate::projection::schema::ProjectionSpec)
/// to a dispatched response (MIK-3534).
///
/// Invoked *last* in `dispatch_to_backend` — after `response_transform` and
/// `enforce_output_schema` — for two load-bearing reasons:
///
/// 1. **No leak.** Because it runs after `response_transform`, the canonical
///    view and the preserved `_raw` are built from the already-redacted
///    payload; a field that `response_transform` redacted cannot reappear under
///    `_raw`. Projection is a presentation layer, never redaction.
/// 2. **Shape.** The projected `{actor, …, _raw}` value would not satisfy a
///    backend output schema, so projection must follow schema validation.
///
/// It operates on the inner capability payload (unwrapping the MCP envelope via
/// [`extract_output_validation_target`]) and re-wraps via
/// [`apply_validated_output`] — projecting the outer envelope is bug #167.
/// `want_full` (the `_full: true` directive) bypasses projection, mirroring
/// `response_transform`. Error envelopes are never projected. When the spec
/// resolves no fields, [`project`](crate::projection::project) returns the
/// payload unchanged (fail-fast) and the original response passes through
/// untouched — re-wrapping it would clobber a non-JSON `content` text.
pub(super) fn apply_capability_projection(
    response: Value,
    spec: &crate::projection::schema::ProjectionSpec,
    want_full: bool,
) -> Value {
    // `_full` opts out of projection (and, upstream, out of the response cache
    // and idempotency), mirroring `response_transform`.
    if want_full {
        return response;
    }
    // Never project an error envelope: its `content` text must stay legible for
    // the caller and for the recovery-hint classifier. Mirrors the `isError`
    // skip in `enforce_output_schema`.
    if response
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return response;
    }
    let inner = extract_output_validation_target(&response).unwrap_or_else(|| response.clone());
    let projected = crate::projection::project(&inner, spec);
    // Fail-fast: `project` resolved no fields and returned `inner` verbatim
    // (a successful projection always adds `_raw`, so it never equals `inner`).
    // Re-wrapping here would replace a non-JSON `content` text with a JSON dump
    // of the envelope, so pass the original response through untouched.
    if projected == inner {
        return response;
    }
    apply_validated_output(&response, projected)
}

/// Emit one A/B telemetry record for an eligible (experimental-mode,
/// projection-capable) invocation (MIK-5877, PROJ-ROLLOUT.3).
///
/// Emits both metrics (a labelled counter + a response-size histogram, for
/// dashboards) and a structured `target: "projection_ab"` tracing event keyed by
/// `session_id` (so an offline analysis can join arm → task outcome). Called
/// only when [`crate::projection::ab_classification`] returns `Some`, so it is
/// zero-cost outside the experiment.
pub(super) fn emit_projection_ab_event(
    session_id: Option<&str>,
    // The experiment key the arm was drawn from, logged as a fingerprint so a
    // modern call (no session) can still be joined to its caller.
    arm_key: &str,
    server: &str,
    tool: &str,
    rec: crate::projection::AbRecord,
    result: &Value,
) {
    let response_bytes = serde_json::to_string(result).map_or(0, |s| s.len());
    let is_error = result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let projected = if rec.projected { "true" } else { "false" };

    telemetry_metrics::counter!(
        "projection_ab_invocations_total",
        "arm" => rec.arm,
        "projected" => projected
    )
    .increment(1);
    telemetry_metrics::histogram!(
        "projection_ab_response_bytes",
        "arm" => rec.arm
    )
    // u32->f64 is lossless; clamp the (absurd) >4 GiB case rather than risk a
    // precision-losing usize->f64 cast.
    .record(f64::from(u32::try_from(response_bytes).unwrap_or(u32::MAX)));
    tracing::info!(
        target: "projection_ab",
        // A modern call has no session and logs "none"; its arm is its
        // caller's (G4). A keyless call emits no event at all.
        session_id = %session_id
            .filter(|sid| !sid.is_empty())
            .map_or_else(|| "none".to_string(), crate::gateway::session_id::session_fp),
        caller = %crate::gateway::session_id::session_fp(arm_key),
        server = server,
        tool = tool,
        arm = rec.arm,
        projected = rec.projected,
        response_bytes = response_bytes,
        is_error = is_error,
        "projection A/B invocation"
    );
}

/// Whether a JSON value is non-empty at the top level: `null`, `{}`, and `[]`
/// are considered empty; any scalar (including `0`, `false`, `""`) and any
/// non-empty object/array are non-empty. This is a deliberately shallow check
/// used by the projection fail-fast guard — when a projection reduces a
/// populated payload to one of the empty forms, the guard logs a warning. It
/// intentionally treats a present-but-empty scalar as non-empty so legitimate
/// values are preserved.
pub(super) fn json_is_populated(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Object(map) => !map.is_empty(),
        Value::Array(items) => !items.is_empty(),
        _ => true,
    }
}

impl crate::gateway::meta_mcp::MetaMcpCallerContext<'_> {
    /// Who a continuation minted or redeemed for this caller is bound to.
    ///
    /// The one derivation both the mint and the redeem read, so the two cannot
    /// name one caller two ways.
    pub(crate) fn principal_source(
        &self,
        dispatch_binding: Option<&str>,
    ) -> crate::protocol::mrtr::PrincipalSource<'_> {
        match self.stdio_nonce {
            Some(nonce) => crate::protocol::mrtr::PrincipalSource::Stdio {
                nonce: nonce.bytes(),
            },
            // The guard's order: a propagated binding ahead of the identity.
            None if self.verified_identity.is_some() && dispatch_binding.is_none() => {
                crate::protocol::mrtr::PrincipalSource::Credential(self.verified_identity)
            }
            // The guard's own inputs (`invoke.rs`, `caller_cache_principal`).
            None => crate::gateway::meta_mcp::support::key_binding(
                (dispatch_binding, self.grant_subject.as_ref()),
                self.owner_principal(),
                self.authentication,
            ),
        }
    }
}
