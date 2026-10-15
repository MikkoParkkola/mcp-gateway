// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The credential mint for an identity-propagating MCP backend (#1961).

use std::sync::Arc;

use crate::personal_accounts::identity::Principal;

/// Mint for `server`, keeping the managed lease when the backend's account
/// descriptor is installed with vault custody (A11-e′). The typed vault is
/// the SAME instance as `strategy` (`InstalledAccount`), and its `propagate`
/// is `prepare` minus the lease, so keeping the lease is the only difference.
pub(super) async fn mint_held(
    managed_vault: Option<&Arc<crate::personal_accounts::VaultStrategy>>,
    strategy: &Arc<dyn crate::identity_propagation::IdentityPropagation>,
    principal: Principal<'_>,
    descriptor: &crate::identity_propagation::BackendDescriptor,
) -> std::result::Result<
    (
        crate::identity_propagation::PropagatedCredential,
        Option<crate::personal_accounts::ManagedLease>,
    ),
    crate::personal_accounts::MintError,
> {
    match (managed_vault, principal.verified()) {
        (Some(vault), _) => vault
            .prepare_held_classified(principal, descriptor)
            .await
            .map(|(cred, managed)| (cred, Some(managed))),
        (None, Some(identity)) => strategy
            .propagate(identity, descriptor)
            .await
            .map(|cred| (cred, None))
            .map_err(crate::personal_accounts::MintError::Other),
        // Only a managed vault serves a non-verified principal.
        (None, None) => Err(crate::personal_accounts::MintError::Other(
            crate::identity_propagation::PropagationError::Refuse(
                "only a managed account mints for a caller without a verified identity".into(),
            ),
        )),
    }
}

/// What `server` mints against: the backend id, and the audience and token
/// exchange its identity-propagation config names.
pub(super) fn descriptor_for(
    server: &str,
    idp_cfg: &crate::identity_propagation::IdentityPropagationConfig,
) -> crate::identity_propagation::BackendDescriptor {
    crate::identity_propagation::BackendDescriptor {
        id: server.to_string(),
        audience: idp_cfg.audience.clone(),
        token_exchange_endpoint: idp_cfg.token_exchange_endpoint.clone(),
        token_exchange_scope: idp_cfg.token_exchange_scope.clone(),
    }
}

/// The first minted header whose name or value cannot go on the wire, so an
/// invalid minted credential fails closed rather than letting the static
/// Authorization through (MIK-6734 review carry-forward).
pub(super) fn invalid_header(headers: &[(String, String)]) -> Option<&str> {
    headers
        .iter()
        .find(|(name, value)| {
            name.parse::<reqwest::header::HeaderName>().is_err()
                || value.parse::<reqwest::header::HeaderValue>().is_err()
        })
        .map(|(name, _)| name.as_str())
}
