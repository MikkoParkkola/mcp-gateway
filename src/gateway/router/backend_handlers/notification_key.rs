// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The upstream session bucket a direct-route notification rides, or its
//! refusal (#2240). Its own file to keep `backend_handlers.rs` under the
//! file-size ratchet.

/// The upstream session bucket a notification rides (MIK-6735 fix 2), or a
/// refusal when this caller's request on the same backend would be refused
/// (#2240).
///
/// Notifications stay outside the request gate below (no id to answer, no
/// tool policy), but they reach the backend, so they pass the same identity
/// decisions: the passthrough arm, the resolver the request arm calls with the
/// same arguments, and, for the shared bucket, the per-user isolation check.
/// `Ok(None)` is the shared bucket, which a backend with no personal binding
/// keeps (IDP.5). The passthrough arm writes its own `idp_refuse` row; the
/// minting resolver writes one of its own.
pub(super) async fn resolve(
    state: &super::AppState,
    backend: &crate::backend::Backend,
    name: &str,
    inbound_headers: &axum::http::HeaderMap,
    verified_identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
) -> Result<Option<String>, ()> {
    let idp_cfg = backend.identity_propagation_config();
    let binding = match idp_cfg
        .filter(|c| c.strategy == crate::identity_propagation::PropagationStrategyKind::Passthrough)
    {
        Some(cfg) => match super::resolve_passthrough_headers(
            cfg,
            inbound_headers,
            backend.transport_carries_identity_headers(),
        ) {
            Ok((_headers, binding)) => binding,
            Err(reason) => {
                if let Err(e) = super::audit_identity_propagation(
                    state.transparency_log.as_ref(),
                    "idp_refuse",
                    &super::audit_subject(verified_identity),
                    name,
                    Some(cfg.audience.as_str()),
                    Some(reason.as_str()),
                )
                .await
                {
                    tracing::warn!(backend = %name, error = %e, "notification refuse audit write failed");
                }
                return Err(());
            }
        },
        None => {
            let (_headers, binding, _held) = state
                .meta_mcp
                .resolve_propagation_credential_held(name, verified_identity)
                .await
                .map_err(|_| ())?;
            binding
        }
    };
    if binding.is_none() {
        state
            .meta_mcp
            .enforce_oauth_isolation_for(backend, name, false)
            .map_err(|_| ())?;
    }
    Ok(binding)
}
