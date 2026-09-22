// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The managed-account propagation strategy: custody behind the EXISTING
//! [`IdentityPropagation`] trait.
//!
//! ONE RESOLVER, ONE STORE. A `personal_managed` descriptor compiles to
//! [`PropagationStrategyKind::Vault`], and this is the strategy installed for
//! that kind. Every consumer — `gateway_invoke` and the direct backend route —
//! reaches it through the same `resolve_caller_credential`, so there is no
//! second managed branch, no second store, no second encoder. The account key
//! is built by the existing `identity::account_key`, hashed by the existing
//! `AccountKey::digest`, and served by the existing `CustodyHandle`.
//!
//! A LEASE IS NEVER AUTHORITY. `refresh_if_expired` yields a lease — a
//! non-secret binding — and the credential itself only exists past
//! `release`, which rechecks the WHOLE lease against current durable state
//! first. A revoked, superseded or reconnect-required account therefore fails
//! at the boundary rather than after the token is already on the wire.
//!
//! NOTHING FALLS BACK. Every refusal below is `PropagationError::Refuse`, which
//! the resolver turns into a closed request for a required backend. There is no
//! path here that answers "no account" with the gateway's own credential.
//!
//! ONE PRINCIPAL PER DEPLOYMENT, NOT PER REQUEST. A gateway whose configuration
//! asserts a single user ([`Principal::SoleOperator`]) serves its stored grants
//! under one fixed principal; every other gateway needs a verified identity and
//! refuses without one. Which of the two applies is decided once at install
//! (`sole_operator`) and is never influenced by a request. The assertion is the
//! operator's, not a proof: two humans sharing that machine share the grants.

use std::sync::Arc;

use crate::identity_propagation::{
    BackendDescriptor, CallerProof, IdentityPropagation, PropagatedCredential, PropagationError,
};
use crate::key_server::oidc::VerifiedIdentity;

use super::AccountKey;
use super::identity::{AccountDescriptor, Principal, account_key};
use super::service::{
    CredentialLease, CredentialReleaseObserver, RefreshProvider, ReleasedCredentials,
};
use super::worker::{CustodyError, CustodyHandle};

/// The two custody operations a dispatch needs, object-safe.
///
/// Type erasure only. The blanket implementation below delegates to the real
/// [`CustodyHandle`] without adding behaviour, so the production gateway
/// installs its own `GatewayCustody` and a test installs a handle whose
/// refresh PROVIDER is scripted — the same worker, the same service, the same
/// store in both. Nothing here is a seam for a second resolution path.
#[async_trait::async_trait]
pub(crate) trait AccountCustody: Send + Sync {
    /// Refresh when the durable grant has expired, then hand back the lease.
    async fn refresh_if_expired(
        &self,
        account: &AccountKey,
    ) -> Result<CredentialLease, CustodyError>;

    /// Recheck the lease against current state and release the credential.
    async fn release(&self, lease: &CredentialLease) -> Result<ReleasedCredentials, CustodyError>;
}

#[async_trait::async_trait]
impl<P, O> AccountCustody for CustodyHandle<P, O>
where
    P: RefreshProvider + 'static,
    O: CredentialReleaseObserver + 'static,
{
    async fn refresh_if_expired(
        &self,
        account: &AccountKey,
    ) -> Result<CredentialLease, CustodyError> {
        CustodyHandle::refresh_if_expired(self, account).await
    }

    async fn release(&self, lease: &CredentialLease) -> Result<ReleasedCredentials, CustodyError> {
        CustodyHandle::release(self, lease).await
    }
}

/// Managed personal-account custody as an identity-propagation strategy.
///
/// Installed PER BACKEND, because the descriptor is what the account key is
/// built from and a process-wide instance could not tell two descriptors of one
/// provider apart. The descriptor is immutable for the life of the install: it
/// is the configuration the gateway validated before it started serving.
pub(crate) struct VaultStrategy {
    custody: Arc<dyn AccountCustody>,
    descriptor: AccountDescriptor,
    /// Whether this deployment may fall back to the sole-operator principal
    /// when a request carries no verified identity.
    ///
    /// A CONFIGURATION FACT, resolved ONCE at install from
    /// [`AuthConfig::grants_single_user_principal`](crate::config::features::auth::AuthConfig::grants_single_user_principal)
    /// and never re-decided per request. A per-request decision would be a
    /// second place the mode could be computed, and the mode is a property of
    /// the deployment, not of the caller — a caller must never be able to
    /// influence which principal their credential is served under.
    sole_operator: bool,
}

impl VaultStrategy {
    /// Bind one configured descriptor to the gateway's one custody.
    ///
    /// `sole_operator` is the operator's assertion, not a proof: see
    /// [`Principal::SoleOperator`].
    pub(crate) fn new(
        custody: Arc<dyn AccountCustody>,
        descriptor: AccountDescriptor,
        sole_operator: bool,
    ) -> Self {
        Self {
            custody,
            descriptor,
            sole_operator,
        }
    }

    /// Who this call is made as, or `None` when nothing proves or asserts a
    /// principal.
    ///
    /// A verified identity always wins. The assertion is consulted ONLY in its
    /// absence, so a deployment that later gains an identity provider changes
    /// nothing about how a verified caller's accounts are addressed — and a
    /// deployment that has one never reaches the second arm anyway, because the
    /// predicate behind `sole_operator` is false whenever an `IdP` is configured.
    ///
    /// TWO CONDITIONS, BOTH REQUIRED, and they answer different questions. The
    /// deployment must have asserted a single user (`sole_operator`, a
    /// configuration fact), AND this request must have presented a credential
    /// established it as the operator ([`CallerProof::Operator`], a request fact).
    /// Dropping the second would hand the operator's stored OAuth grants to any
    /// anonymous caller reaching a public path — which the shipped starter
    /// configuration lists `/mcp` as.
    ///
    /// Public to the crate because the REST account registry needs the SAME
    /// answer this strategy will mint under, for its audit subject and for the
    /// actor the prepared credential is rechecked against. Asking here rather
    /// than re-deriving it there keeps one answer.
    pub(crate) fn principal<'a>(&self, caller: CallerProof<'a>) -> Option<Principal<'a>> {
        match caller {
            CallerProof::Verified(identity) => Some(Principal::Verified(identity)),
            // BOTH conditions are checked HERE, not just in `CallerProof::new`.
            // The variants are `pub(crate)`, so crate code can build
            // `Operator(CallerProvenance::Anonymous)` without going through the
            // constructor; matching `Operator(_)` would then mint the
            // deployment principal for a caller nothing established. Carrying
            // the provenance in the type only helps if the enforcement point
            // reads it.
            CallerProof::Operator(provenance) => (self.sole_operator
                && provenance.establishes_the_operator())
            .then_some(Principal::SoleOperator),
            // Nothing validated. No assertion covers a caller the gateway never
            // recognised, whatever the configuration says about how many humans
            // are supposed to be behind it.
            CallerProof::Anonymous => None,
        }
    }

    /// The WHOLE of `propagate`, plus the lease the credential was released
    /// under.
    ///
    /// Factored out rather than duplicated: [`IdentityPropagation::propagate`]
    /// below is this function with the lease dropped, so the MCP route's trait
    /// behaviour is byte for byte what it was. A consumer that must RECHECK the
    /// credential later — the REST account registry, which resolves before its
    /// cache lookup and rechecks before egress — keeps the lease instead, so the
    /// recheck can be the real custody boundary rather than an expiry
    /// comparison. The lease is a non-secret binding: it authorizes nothing on
    /// its own, and holding it is not holding a token.
    ///
    /// # Errors
    ///
    /// [`PropagationError::Misconfigured`] when the backend audience and the
    /// descriptor resource have drifted; [`PropagationError::Refuse`] for an
    /// unusable account key, an unusable account (revoked, reconnect-required,
    /// superseded) or a refused release. Nothing here falls back.
    pub(crate) async fn prepare(
        &self,
        principal: Principal<'_>,
        backend: &BackendDescriptor,
    ) -> Result<(PropagatedCredential, CredentialLease), PropagationError> {
        // The installed descriptor and the backend's compiled propagation
        // config are produced together by `config::account_bindings`. A
        // mismatch means an install and a configuration have drifted, and
        // minting under the wrong audience is exactly the substitution the
        // per-backend install exists to prevent.
        if backend.audience != self.descriptor.resource {
            return Err(PropagationError::Misconfigured(format!(
                "backend '{}' expects audience '{}' but account descriptor '{}' is scoped to \
                 a different resource",
                backend.id, backend.audience, self.descriptor.descriptor_id
            )));
        }

        // The principal's authority + subject + the CONFIGURED resource and
        // issuer. No display name, no email, nothing from the request body.
        let account = account_key(Some(principal), &self.descriptor).map_err(|error| {
            PropagationError::Refuse(format!("account identity binding refused: {error}"))
        })?;

        let lease = self
            .custody
            .refresh_if_expired(&account)
            .await
            .map_err(|error| {
                PropagationError::Refuse(format!("managed account is not usable: {error}"))
            })?;
        let binding = cache_binding(&account, &lease)?;
        // The lease alone authorizes nothing. This is the recheck against
        // current durable state, and the only point a credential exists.
        let credentials = self.custody.release(&lease).await.map_err(|error| {
            PropagationError::Refuse(format!(
                "managed account credential was not released: {error}"
            ))
        })?;

        let credential = PropagatedCredential {
            headers: vec![(
                "Authorization".to_string(),
                authorization_value(&credentials),
            )],
            // Resolved per dispatch and deliberately not reusable: custody
            // rechecks the whole lease on every release, so a credential
            // carried past this dispatch would be one nothing rechecked. The
            // durable grant's own expiry stays inside custody, where the
            // refresh decision is made.
            expires_at: now_secs(),
            subject_key: binding.clone(),
            audience: backend.audience.clone(),
            // Scope authority lives on the lease, which is built from the
            // durable record — never from a claim the caller made.
            scopes: lease.scopes.clone(),
            cache_binding: binding,
        };
        Ok((credential, lease))
    }

    /// Re-run the REAL release recheck for a lease released earlier in this
    /// dispatch, and discard what it releases.
    ///
    /// This is the durable-custody half of a credential recheck: it asks the
    /// store, under its authority lock, whether THIS lease — this generation,
    /// this authorization epoch, this token revision, this descriptor revision
    /// — is still the current grant. A revocation, a reconnect requirement, a
    /// re-authorization or a rotation committed after the credential was
    /// prepared therefore refuses HERE, before a cache entry may be selected
    /// and before anything reaches the wire.
    ///
    /// It never refreshes and never re-mints: a recheck that could mint would
    /// answer "still valid" for a lease that is not, by quietly acquiring a
    /// different one. The released credential is dropped immediately; the
    /// credential this dispatch presents is the one prepared with it.
    ///
    /// # Errors
    ///
    /// [`PropagationError::Refuse`] naming the custody refusal.
    pub(crate) async fn recheck(&self, lease: &CredentialLease) -> Result<(), PropagationError> {
        // Bound to this statement: the released token is never bound to a name
        // that outlives the check it exists for (CWE-226).
        self.custody.release(lease).await.map_err(|error| {
            PropagationError::Refuse(format!(
                "managed account credential is no longer releasable: {error}"
            ))
        })?;
        Ok(())
    }
}

/// What a cache or an upstream session may be keyed on.
///
/// The five account-key fields, separated by the existing versioned
/// length-prefixed digest, plus the grant authority the credential was released
/// under: a re-authorized or rotated account produces a different binding, so a
/// result cached for the previous grant is never served for the new one. No
/// token material, and no raw subject: the digest already distinguishes
/// principals without publishing them into cache keys and log lines.
fn cache_binding(
    account: &AccountKey,
    lease: &CredentialLease,
) -> Result<String, PropagationError> {
    let digest = account
        .digest()
        .map_err(|error| PropagationError::Refuse(format!("account key is unusable: {error}")))?;
    Ok(format!(
        "acct:v1:{digest}:{}:{}:{}:{}:{}:{}",
        lease.generation.len(),
        lease.generation,
        lease.authorization_epoch,
        lease.token_revision,
        lease.descriptor_revision.len(),
        lease.descriptor_revision,
    ))
}

#[async_trait::async_trait]
impl IdentityPropagation for VaultStrategy {
    /// Unchanged behaviour for every existing consumer: [`Self::prepare`] with
    /// the lease dropped. The MCP route's credential, headers, binding, expiry
    /// and refusals are exactly what they were.
    ///
    /// The trait takes a verified identity, so this entry can only ever mint
    /// under [`Principal::Verified`]. A sole-operator deployment reaches
    /// [`Self::prepare`] through the REST account registry, which holds the
    /// caller's identity as an `Option` and asks [`Self::principal`] for the
    /// answer. Widening the trait is the 4.1 direction (design doc §4.3), not
    /// this increment.
    async fn propagate(
        &self,
        identity: &VerifiedIdentity,
        backend: &BackendDescriptor,
    ) -> Result<PropagatedCredential, PropagationError> {
        let (credential, _lease) = self.prepare(Principal::Verified(identity), backend).await?;
        Ok(credential)
    }
}

/// `token_type` as the provider returned it, with the RFC 6749 default for a
/// provider that returned nothing usable. The token itself is never inspected,
/// reformatted or logged.
fn authorization_value(credentials: &ReleasedCredentials) -> String {
    let scheme = credentials.token_type.trim();
    let scheme = if scheme.is_empty() { "Bearer" } else { scheme };
    format!("{scheme} {}", credentials.access_token)
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

#[cfg(test)]
#[path = "vault_tests.rs"]
mod vault_tests;
