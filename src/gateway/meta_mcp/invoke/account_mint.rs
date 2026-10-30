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

/// When a minted credential stops working. A non-positive `expires_at` is a
/// strategy that published none; a synthetic one is the issuer's silence.
pub(super) fn expiry_of(
    cred: &crate::identity_propagation::PropagatedCredential,
) -> crate::identity_propagation::send_check::Expiry {
    use crate::identity_propagation::send_check::Expiry;
    match (cred.expires_at, cred.expiry_synthetic) {
        (at, _) if at <= 0 => Expiry::Unpublished,
        (at, true) => Expiry::AtSynthetic(at),
        (at, false) => Expiry::At(at),
    }
}

/// The check every send of a minted credential runs first. A managed one is
/// the custody recheck of its lease against the vault installed NOW (read at
/// each send, so a replaced or removed install refuses); any other is its
/// expiry. The registry is held, never the gateway, so the check outlives
/// nothing it should not.
pub(super) fn send_check_for(
    accounts: &Arc<crate::identity_propagation::AccountStrategyRegistry>,
    (descriptor_id, managed): (
        Option<&str>,
        Option<&crate::personal_accounts::ManagedLease>,
    ),
    (expiry, headers): (
        crate::identity_propagation::send_check::Expiry,
        &[(String, String)],
    ),
) -> crate::transport::SendCheck {
    use crate::transport::Refusal;
    let Some(lease) = managed else {
        return crate::identity_propagation::send_check::expiry_check(
            expiry,
            headers,
            crate::identity_propagation::send_check::unix_now,
        );
    };
    let (lease, accounts, id) = (
        lease.clone(),
        Arc::clone(accounts),
        descriptor_id.map(str::to_owned),
    );
    Arc::new(move || {
        let (lease, accounts, id) = (lease.clone(), Arc::clone(&accounts), id.clone());
        Box::pin(async move {
            let Some(vault) = accounts.managed_vault(id.as_deref()) else {
                return Err(Refusal::Definitive);
            };
            lease.recheck_send(&vault).await
        })
    })
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
