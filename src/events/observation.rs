// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which identity a backend's events are observed under. A per-user backend's listener observes as
//! one subscriber; the key it observes under, `obs`, is derived wherever it is needed from the
//! row's stored identity and the live config, never stored. The row keeps `ObsBasis`, the
//! non-secret config the key was derived from, so a reload or restart that would change it is seen
//! and the row revoked.

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, observation_key,
};
use crate::key_server::oidc::VerifiedIdentity;
use crate::personal_accounts::identity::{AccountKeyDescriptor, Principal, account_key};

/// How a record stamps the lease generation it was observed under. Here,
/// not beside the lease, whose code may format nothing (LEASE-T6).
pub(crate) fn lease_stamp(generation: u128) -> String {
    format!("{generation:032x}")
}

/// What a leased listener run puts in an occurrence's `fence`: its own
/// generation, marked so a vault binding can never read as one.
pub(crate) fn run_fence(generation: u128) -> String {
    format!("{RUN_FENCE_PREFIX}{}", lease_stamp(generation))
}

/// Whether `stamp` has the form [`lease_stamp`] writes: 32 lowercase hex
/// digits. Anything else in a marked fence names no lease.
fn is_lease_stamp(stamp: &str) -> bool {
    stamp.len() == 32
        && stamp
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The marker on a leased run's fence (see [`run_fence`]).
pub(crate) const RUN_FENCE_PREFIX: &str = "lease:";

/// The operator config besides the identity that defines `obs` (B3). Plain
/// config, so it is stored as written and compared exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ObsBasis {
    pub strategy: PropagationStrategyKind,
    pub audience: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_exchange_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_exchange_scope: Option<String>,
    /// The `accounts.descriptors` key a managed-account backend names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descriptor_id: Option<String>,
    /// That descriptor's resource and issuer: both are in the account key,
    /// so a change to either is a change of what the row observes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_issuer: Option<String>,
}

/// A backend's identity binding in the live config. Absent for a backend
/// whose credential is shared.
#[derive(Debug, Clone)]
pub(crate) struct Binding {
    pub config: IdentityPropagationConfig,
    pub basis: ObsBasis,
    account: Option<AccountKeyDescriptor>,
}

/// Why no observation key can be had for a subscriber.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObsRefusal {
    /// A managed-account backend whose account cannot be bound to the
    /// subscriber.
    NoAccount,
    /// The backend's identity config is not the one the row was observed
    /// under (or the backend moved between shared and per-user): the row is
    /// revoked, never re-keyed silently (B3).
    BasisChanged,
    /// A per-user row with no stored identity to observe as.
    NoIdentity,
}

/// The identity binding `backend` runs with in `config`, after account
/// references compile (the same view `judged_backends` takes).
pub(crate) fn binding(config: &Config, backend: &str) -> Option<Binding> {
    let raw = config.backends.get(backend)?;
    let bound = crate::config::account_bindings::compile(config)
        .ok()
        .and_then(|mut all| all.remove(backend));
    let effective = bound
        .as_ref()
        .map_or_else(|| raw.clone(), |b| b.effective(raw));
    let propagation = effective.identity_propagation?;
    let descriptor_id = bound.as_ref().map(|b| b.descriptor_id.clone());
    let account = bound.as_ref().and_then(|b| b.account.as_ref());
    Some(Binding {
        basis: ObsBasis {
            strategy: propagation.strategy,
            audience: propagation.audience.clone(),
            token_exchange_endpoint: propagation.token_exchange_endpoint.clone(),
            token_exchange_scope: propagation.token_exchange_scope.clone(),
            descriptor_id,
            account_resource: account.map(|a| a.resource.clone()),
            account_issuer: account.map(|a| a.issuer.clone()),
        },
        config: propagation,
        account: bound.and_then(|b| b.account),
    })
}

impl Binding {
    /// The key `identity` is observed under on this backend.
    ///
    /// # Errors
    /// A managed-account backend whose account cannot be bound.
    pub(crate) fn observe(&self, identity: &VerifiedIdentity) -> Result<String, ObsRefusal> {
        if let Some(key) = observation_key(&self.config, identity) {
            return Ok(key);
        }
        let descriptor = self.account.as_ref().ok_or(ObsRefusal::NoAccount)?;
        let account = account_key(Some(Principal::Verified(identity)), descriptor)
            .map_err(|_| ObsRefusal::NoAccount)?;
        crate::personal_accounts::vault_observation_key(&account, &self.config.audience)
            .map_err(|_| ObsRefusal::NoAccount)
    }
}

/// A stored row's observation key on `backend`, re-derived from the live
/// config: `None` for a row of a shared backend.
///
/// # Errors
/// The live basis differs from the row's, or its identity is gone.
pub(crate) fn observe_row(
    config: &Config,
    backend: &str,
    sub: &super::records::Subscription,
) -> Result<Option<String>, ObsRefusal> {
    match (&sub.obs_basis, binding(config, backend)) {
        (None, None) => Ok(None),
        (Some(basis), Some(live)) if *basis == live.basis => {
            let identity = sub.observed_as().ok_or(ObsRefusal::NoIdentity)?;
            live.observe(&identity).map(Some)
        }
        _ => Err(ObsRefusal::BasisChanged),
    }
}

impl super::EventsHub {
    /// `sub`'s observation now, under `config`: what a record stamps at
    /// fan-out and must still equal when it is sent (A2). `Ok(None)` for a
    /// shared row. `fence` is the producing listener run's at fan-out (a
    /// vault grant's binding, or a leased run's marked generation) and a
    /// fresh read at delivery (a vault row's grant; none for a leased row,
    /// which then reads the lease held now), so a record observed under a
    /// grant or lease that moved never matches.
    ///
    /// # Errors
    /// A per-user row whose observation cannot be had now: fan-out sends it
    /// nothing, and a record already queued for it is buried.
    pub(super) fn observed_now(
        &self,
        sub: &super::records::Subscription,
        config: &Config,
        fence: Option<&str>,
    ) -> Result<Option<super::outbox::ObservedUnder>, ObsRefusal> {
        let Some(basis) = sub.obs_basis.clone() else {
            return Ok(None);
        };
        let (backend, _) =
            super::upstream::parse_name(&sub.name).ok_or(ObsRefusal::BasisChanged)?;
        let obs = observe_row(config, backend, sub)?.ok_or(ObsRefusal::BasisChanged)?;
        let lease = match basis.strategy {
            // At fan-out, the generation the producing run was opened under,
            // so an occurrence read under a replaced lease can never carry
            // the new one; at delivery and replay (no fence), the lease held
            // now, which a record from a replaced lease no longer matches.
            PropagationStrategyKind::Passthrough => match fence {
                // A fence not marked as a leased run's names no lease: no
                // stamp, so it never matches a lease held now.
                Some(fence) => fence
                    .strip_prefix(RUN_FENCE_PREFIX)
                    .filter(|stamp| is_lease_stamp(stamp))
                    .map(str::to_owned),
                None => self
                    .leases
                    .held_generation(&super::lease::LeaseKey {
                        backend: backend.to_owned(),
                        obs,
                    })
                    .map(lease_stamp),
            },
            // Prefixed so it never equals a passthrough generation; a leased
            // run's marked fence is never read as a vault binding.
            PropagationStrategyKind::Vault => fence
                .filter(|f| !f.starts_with(RUN_FENCE_PREFIX))
                .map(|binding| format!("vault:{binding}")),
            _ => None,
        };
        Ok(Some(super::outbox::ObservedUnder {
            incarnation: sub.incarnation,
            obs_basis: basis,
            lease,
        }))
    }
}

/// What a subscribe on `backend` records for `identity`:
/// the basis its observation comes from, `None` for a shared backend. The
/// key itself is derived again wherever it is needed, never stored.
///
/// # Errors
/// `-32012` when a per-user backend has no verified identity to observe as,
/// or its account cannot be bound.
pub(crate) fn observe_subscriber(
    config: &Config,
    backend: &str,
    identity: Option<&VerifiedIdentity>,
) -> Result<Option<ObsBasis>, super::RpcError> {
    let Some(binding) = binding(config, backend) else {
        return Ok(None);
    };
    let identity = identity.ok_or_else(super::RpcError::forbidden)?;
    binding
        .observe(identity)
        .map_err(|_| super::RpcError::forbidden())?;
    Ok(Some(binding.basis))
}

impl super::Caller {
    /// The identity a per-user row stores: none for a shared
    /// backend, and none when its OIDC bearer binding already carries it.
    pub(super) fn stored_identity(
        &self,
        basis: Option<&ObsBasis>,
    ) -> Option<crate::key_server::oidc::VerifiedIdentity> {
        let bearer = matches!(
            self.credential.binding,
            Some(super::records::LiveBinding::OidcBearer { .. })
        );
        basis.filter(|_| !bearer).and(self.identity.clone())
    }
}

impl super::EventsHub {
    /// How `caller` observes the backend behind event `name`: `None` for a
    /// shared backend or another source's event.
    pub(super) fn observe(
        &self,
        caller: &super::Caller,
        name: &str,
    ) -> Result<Option<ObsBasis>, super::RpcError> {
        let (Some((backend, _)), Some(services)) = (
            super::upstream::parse_name(name),
            self.runtime.services.get(),
        ) else {
            return Ok(None);
        };
        observe_subscriber(&services.live.get(), backend, caller.identity.as_ref())
    }
}

#[cfg(test)]
#[path = "observation_tests.rs"]
mod tests;
