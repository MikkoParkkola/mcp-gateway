// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a direct-route notification carries upstream (the caller's credential
//! and session bucket), or its refusal (#2240, #2292). Its own file to keep
//! `backend_handlers.rs` under the file-size ratchet.

/// The credential and session bucket a notification carries (MIK-6735 fix 2,
/// #2292), or a refusal when this caller's request on the same backend would
/// be refused (#2240).
///
/// Notifications stay outside the request gate below (no id to answer, no
/// tool policy), but they reach the backend, so they pass the same identity
/// decisions: the passthrough arm, the resolver the request arm calls with the
/// same arguments, and, for the shared bucket, the per-user isolation check.
/// A resolved credential is forwarded under the request arm's rules: carried
/// or refused, never replaced by the static one, and audited. No headers and
/// no binding is the shared bucket, which a backend with no personal binding
/// keeps (IDP.5).
pub(super) async fn resolve(
    state: &super::AppState,
    backend: &crate::backend::Backend,
    name: &str,
    inbound_headers: &axum::http::HeaderMap,
    caller: crate::identity_propagation::CallerProof<'_>,
    proven: Option<&str>,
) -> Result<Resolved, ()> {
    let idp_cfg = backend.identity_propagation_config();
    let audience = idp_cfg.map(|c| c.audience.as_str());
    let (headers, binding) = if let Some(cfg) = idp_cfg
        .filter(|c| c.strategy == crate::identity_propagation::PropagationStrategyKind::Passthrough)
    {
        match super::resolve_passthrough_headers(
            cfg,
            inbound_headers,
            backend.transport_carries_identity_headers(),
        ) {
            Ok((headers, digest)) => (
                headers,
                super::charged_binding(state, backend, caller, proven, digest),
            ),
            Err(reason) => {
                refuse_audited(state, (name, backend), caller, audience, &reason).await;
                return Err(());
            }
        }
    } else {
        // A credential the transport cannot carry is refused before it is
        // minted, so the log never records a mint for a notification that is
        // not sent (#2310). With no principal nothing is minted: the resolver
        // decides, and a non-required backend keeps its static path.
        if idp_cfg.is_some()
            && !backend.transport_carries_identity_headers()
            && state.meta_mcp.has_principal_for(backend, caller)
        {
            refuse_audited(state, (name, backend), caller, audience, CANNOT_CARRY).await;
            return Err(());
        }
        match state
            .meta_mcp
            .resolve_propagation_credential_held_for(name, Some(backend), caller)
            .await
        {
            Ok((headers, binding, _held)) => (headers, binding),
            Err(e) => {
                // With no propagation config the only refusal is the unbound
                // account check, which writes no row; the minting resolver
                // writes its own, so writing here too would double it.
                if idp_cfg.is_none() {
                    refuse_audited(state, (name, backend), caller, audience, &e.to_string()).await;
                }
                return Err(());
            }
        }
    };
    if !headers.is_empty() {
        // Sent without its caller's credential, the notification would carry
        // the backend's static one: refuse it instead (#2292).
        if !backend.transport_carries_identity_headers() {
            refuse_audited(state, (name, backend), caller, audience, CANNOT_CARRY).await;
            return Err(());
        }
        // A forwarded credential is audited as a request's is, and not
        // forwarded without a durable record (the request arm's guards).
        let required = idp_cfg.is_some_and(|c| c.required);
        if required && state.transparency_log.is_none() {
            tracing::warn!(backend = %name, "required credential not forwarded: no transparency log");
            return Err(());
        }
        let subject = state.meta_mcp.audit_subject_for(backend, caller);
        super::audit_identity_propagation(
            state.transparency_log.as_ref(),
            "idp_mint",
            &subject,
            name,
            audience,
            None,
        )
        .await
        .map_err(|e| {
            tracing::warn!(backend = %name, error = %e, "notification mint audit write failed; failing closed");
        })?;
    }
    if binding.is_none() {
        state
            .meta_mcp
            .enforce_oauth_isolation_for(backend, name, false)
            .map_err(|_| ())?;
    }
    Ok(Resolved { headers, binding })
}

/// The `idp_refuse` reason for a credential the backend's transport cannot
/// carry (#2310).
const CANNOT_CARRY: &str = crate::identity_propagation::TRANSPORT_CANNOT_CARRY_HEADERS;

/// What a forwarded notification carries: the caller's credential headers
/// and the session bucket. No `Debug`: the headers are credentials.
pub(super) struct Resolved {
    pub(super) headers: Vec<(String, String)>,
    pub(super) binding: Option<String>,
}

/// Write the route's `idp_refuse` row; a failed write is logged, the refusal
/// stands either way (the request arm's policy).
async fn refuse_audited(
    state: &super::AppState,
    (name, backend): (&str, &crate::backend::Backend),
    caller: crate::identity_propagation::CallerProof<'_>,
    audience: Option<&str>,
    reason: &str,
) {
    if let Err(e) = super::audit_identity_propagation(
        state.transparency_log.as_ref(),
        "idp_refuse",
        &state.meta_mcp.audit_subject_for(backend, caller),
        name,
        audience,
        Some(reason),
    )
    .await
    {
        tracing::warn!(backend = %name, error = %e, "notification refuse audit write failed");
    }
}
