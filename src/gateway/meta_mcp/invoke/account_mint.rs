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
    crate::identity_propagation::PropagationError,
> {
    match (managed_vault, principal.verified()) {
        (Some(vault), _) => vault
            .prepare_held(principal, descriptor)
            .await
            .map(|(cred, managed)| (cred, Some(managed))),
        (None, Some(identity)) => strategy
            .propagate(identity, descriptor)
            .await
            .map(|cred| (cred, None)),
        // Only a managed vault serves a non-verified principal.
        (None, None) => Err(crate::identity_propagation::PropagationError::Refuse(
            "only a managed account mints for a caller without a verified identity".into(),
        )),
    }
}
