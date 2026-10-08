// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Refusal of methods a modern backend's protocol revision removed.

/// Whether the peer behind `backend` has had `method` removed from under it
/// (MIK-7217, OUTBOUND.1).
///
/// The gateway is the only place that knows both which revision the backend
/// speaks and which methods that revision deleted, so it is the only place the
/// refusal can be made without spending a round trip to hear it. Sending one
/// anyway is not harmless: a modern peer answers `method not found`, which is
/// indistinguishable from a peer that is merely missing a feature, so the
/// gateway would be manufacturing the ambiguity it exists to resolve.
///
/// Unresolved and legacy eras both forward. Silence is not evidence of
/// modernity, and refusing on a guess would take `logging/setLevel` away from
/// every 2025 backend whose era probe has not come back yet.
///
/// `pub(in crate::gateway)`, widened from private, so the direct backend
/// route (`gateway::router::backend_handlers`) can reuse this one mechanism
/// instead of a second copy of the revision's removed-method list (MIK-7217,
/// OUTBOUND.1).
pub(in crate::gateway) async fn era_removed_method(
    backend: &crate::backend::Backend,
    method: &str,
) -> bool {
    let era = backend.cached_era().await;
    if era != Some(crate::protocol::era::Era::Modern) {
        return false;
    }
    if !crate::protocol::meta::REMOVED_IN_2026_07_28.contains(&method) {
        return false;
    }
    // `debug!`, not `warn!`: the refusal is triggered by whatever method a
    // client asks for, so at `warn!` a client polling a removed method sets
    // the gateway's log volume. The counter below carries the same event at a
    // volume an operator controls.
    tracing::debug!(
        backend = %backend.name,
        method,
        "Refusing a method the backend's protocol revision removed"
    );
    telemetry_metrics::counter!(
        "mcp_gateway_removed_method_refused_total",
        "backend" => backend.name.clone(),
        "method" => method.to_string(),
        "era" => "modern"
    )
    .increment(1);
    true
}
