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
//! NOTHING FALLS BACK. Every refusal below is a `PropagationError` the resolver
//! turns into a closed request for a required backend — `Refuse`, or the typed
//! `AccountNotConnected` / `AccountReconnectRequired` states a connect journey
//! remedies. There is no path here that answers "no account" with the
//! gateway's own credential. The typed states carry no URL: only a dispatch
//! site may attach a connect offer (MIK-6745 design §9.2, BC-1).
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
use super::identity::{AccountKeyDescriptor, Principal, account_key};
use super::service::{
    AccountServiceError, CredentialLease, CredentialReleaseObserver, RefreshProvider,
    RejectionOutcome, ReleasedCredentials,
};
use super::worker::{CustodyError, CustodyHandle};

/// The ONE mapping from a custody refusal to a propagation refusal.
///
/// Every custody boundary in this file routes through here, on purpose. Three
/// call sites each writing their own `map_err` is how the absence discriminant
/// came to be preserved through `CustodyError::Account` and then destroyed one
/// hop later: a per-site mapping only has to be forgotten once.
///
/// `context` keeps each boundary's existing wording for every refusal that
/// stays a `Refuse`, so those messages are unchanged.
///
/// Absence drops the context deliberately. "Which custody call observed it" is
/// not informative for a state the store simply does not hold — absence at
/// refresh and absence at release are the same fact — and prepending
/// "managed account is not usable" to "account is not connected" produced a
/// message that said the same thing three times by the time it reached a
/// caller. The variant names the state; the inner text is the remediation.
///
/// Exactly the three states a connect journey remedies are lifted out of
/// [`PropagationError::Refuse`]: absence, revocation and reconnect-required.
/// The latter two keep their `context`, so their text is the `Refuse` text it
/// always was. A busy custody, a shutdown and a store failure stay `Refuse`:
/// connecting cannot fix them, and a store failure must never read as absence
/// — `AccountService::connected` keeps that invariant upstream, and flattening
/// it back here would undo it.
fn refusal(context: &str, error: &CustodyError) -> PropagationError {
    match error {
        CustodyError::Account(AccountServiceError::ConnectOffer) => {
            PropagationError::AccountNotConnected(error.to_string())
        }
        CustodyError::Account(
            AccountServiceError::Revoked | AccountServiceError::ReconnectRequired,
        ) => PropagationError::AccountReconnectRequired(format!("{context}: {error}")),
        _ => PropagationError::Refuse(format!("{context}: {error}")),
    }
}

/// The two custody operations a dispatch needs, object-safe.
///
/// Type erasure only. The blanket implementation below delegates to the real
/// [`CustodyHandle`] without adding behaviour, so the production gateway
/// installs its own `GatewayCustody` and a test installs a handle whose
/// refresh PROVIDER is scripted — the same worker, the same service, the same
/// store in both. Nothing here is a seam for a second resolution path.
#[async_trait::async_trait]
pub(crate) trait AccountCustody: Send + Sync {
    /// The current lease, read without refreshing: no provider call and no
    /// durable write.
    async fn resolve(&self, account: &AccountKey) -> Result<CredentialLease, CustodyError>;

    /// Refresh when the durable grant has expired, then hand back the lease.
    async fn refresh_if_expired(
        &self,
        account: &AccountKey,
    ) -> Result<CredentialLease, CustodyError>;

    /// Recheck the lease against current state and release the credential.
    async fn release(&self, lease: &CredentialLease) -> Result<ReleasedCredentials, CustodyError>;

    /// A11-c: at most one forced refresh after the backend refused `lease`.
    async fn refresh_after_rejection(
        &self,
        lease: &CredentialLease,
    ) -> Result<RejectionOutcome, CustodyError>;
}

#[async_trait::async_trait]
impl<P, O> AccountCustody for CustodyHandle<P, O>
where
    P: RefreshProvider + 'static,
    O: CredentialReleaseObserver + 'static,
{
    async fn resolve(&self, account: &AccountKey) -> Result<CredentialLease, CustodyError> {
        CustodyHandle::resolve(self, account).await
    }

    async fn refresh_if_expired(
        &self,
        account: &AccountKey,
    ) -> Result<CredentialLease, CustodyError> {
        CustodyHandle::refresh_if_expired(self, account).await
    }

    async fn release(&self, lease: &CredentialLease) -> Result<ReleasedCredentials, CustodyError> {
        CustodyHandle::release(self, lease).await
    }

    async fn refresh_after_rejection(
        &self,
        lease: &CredentialLease,
    ) -> Result<RejectionOutcome, CustodyError> {
        CustodyHandle::refresh_after_rejection(self, lease).await
    }
}

/// The typed outcome of a mint-free view read (MIK-8392 Busy parity).
#[derive(Debug)]
pub(crate) enum ViewBinding {
    Bound(String),
    NoView(PropagationError),
    Transient(PropagationError),
    Unavailable(PropagationError),
}

impl ViewBinding {
    /// Why the read did not bind, for a diagnostic; `None` for `Bound`.
    pub(crate) fn failure(&self) -> Option<&PropagationError> {
        match self {
            Self::Bound(_) => None,
            Self::NoView(error) | Self::Transient(error) | Self::Unavailable(error) => Some(error),
        }
    }
}

/// A mint refusal with a busy custody kept typed (MIK-8428): decided from
/// [`CustodyError::Busy`] itself at the custody boundary, never from text.
/// Every other refusal keeps its [`PropagationError`] unchanged.
#[derive(Debug)]
pub(crate) enum MintError {
    Busy(PropagationError),
    Other(PropagationError),
}

impl MintError {
    /// The refusal as callers that do not distinguish a busy custody see it.
    pub(crate) fn into_error(self) -> PropagationError {
        match self {
            Self::Busy(error) | Self::Other(error) => error,
        }
    }
}

impl From<PropagationError> for MintError {
    fn from(error: PropagationError) -> Self {
        Self::Other(error)
    }
}

/// Map one custody boundary's failure, keeping `Busy` typed: the busy arm
/// carries the same refusal text the view read carries for its resolve
/// (this file's `view_binding_classified`), so the one transient audit
/// record's reason bytes match on the live mint and the stored read.
fn mint_refusal(context: &str, error: &CustodyError) -> MintError {
    match error {
        CustodyError::Busy => MintError::Busy(refusal("managed account view", error)),
        _ => MintError::Other(refusal(context, error)),
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
    descriptor: AccountKeyDescriptor,
    /// The live descriptor's `descriptor_revision`, computed at install from
    /// the configuration this gateway validated. A grant stored under any other
    /// revision was connected under a descriptor the operator has since changed
    /// (#2249), and is refused as reconnect-required.
    descriptor_revision: String,
    /// Whether this deployment may fall back to the sole-operator principal
    /// when a request carries no verified identity.
    ///
    /// A CONFIGURATION FACT, resolved ONCE at install from
    /// [`sole_operator_asserted`](crate::gateway::server::account_bindings::sole_operator_asserted)
    /// (always true over stdio; the HTTP single-user settings otherwise)
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
        descriptor: AccountKeyDescriptor,
        descriptor_revision: String,
        sole_operator: bool,
    ) -> Self {
        Self {
            custody,
            descriptor,
            descriptor_revision,
            sole_operator,
        }
    }

    /// Whether an account key can be built for `principal` under this
    /// descriptor. A principal that cannot bind never will: no grant can be
    /// stored or read for it (MIK-8392). No custody read.
    pub(crate) fn binds(&self, principal: Principal<'_>) -> bool {
        account_key(Some(principal), &self.descriptor).is_ok()
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
    /// superseded), a refused release or a clock that reads before 1970.
    /// Nothing here falls back.
    pub(crate) async fn prepare(
        &self,
        principal: Principal<'_>,
        backend: &BackendDescriptor,
    ) -> Result<(PropagatedCredential, CredentialLease), PropagationError> {
        self.prepare_classified(principal, backend)
            .await
            .map_err(MintError::into_error)
    }

    /// [`Self::prepare`] with a busy custody kept typed to the caller
    /// (MIK-8428): the same body, decided from [`CustodyError::Busy`] at
    /// each custody boundary.
    async fn prepare_classified(
        &self,
        principal: Principal<'_>,
        backend: &BackendDescriptor,
    ) -> Result<(PropagatedCredential, CredentialLease), MintError> {
        // Read the clock first, before custody resolves, refreshes or releases
        // anything (MIK-8202 P4a): chrono's own clock read panics before 1970,
        // and a dispatch on such a clock is refused with nothing moved. The
        // same reading dates the credential. The `i64` conversion cannot fail
        // before the year 292 billion; it refuses rather than wraps.
        let now = crate::clock::unix_secs()
            .ok()
            .and_then(|secs| i64::try_from(secs).ok())
            .ok_or_else(|| {
                PropagationError::Refuse(
                    "managed account credential not issued: the gateway clock reads before 1970"
                        .to_string(),
                )
            })?;
        // The installed descriptor and the backend's compiled propagation
        // config are produced together by `config::account_bindings`. A
        // mismatch means an install and a configuration have drifted, and
        // minting under the wrong audience is exactly the substitution the
        // per-backend install exists to prevent.
        if backend.audience != self.descriptor.resource {
            return Err(MintError::Other(PropagationError::Misconfigured(format!(
                "backend '{}' expects audience '{}' but account descriptor '{}' is scoped to \
                     a different resource",
                backend.id, backend.audience, self.descriptor.descriptor_id
            ))));
        }

        // The principal's authority + subject + the CONFIGURED resource and
        // issuer. No display name, no email, nothing from the request body.
        let account = account_key(Some(principal), &self.descriptor).map_err(|error| {
            PropagationError::Refuse(format!("account identity binding refused: {error}"))
        })?;

        // The descriptor fence runs BEFORE the refresh (#2249). A refresh would
        // talk to the provider with the new descriptor's client and could
        // rotate or durably fence the grant, so reverting the config edit would
        // no longer restore it. The read below moves nothing.
        let current = self
            .custody
            .resolve(&account)
            .await
            .map_err(|error| mint_refusal("managed account is not usable", &error))?;
        self.fence_changed_descriptor(&current)?;
        let lease = self
            .custody
            .refresh_if_expired(&account)
            .await
            .map_err(|error| mint_refusal("managed account is not usable", &error))?;
        // Again on the lease actually released: the grant may have been
        // replaced between the read and the refresh.
        self.fence_changed_descriptor(&lease)?;
        let binding = cache_binding(&account, &lease)?;
        // The lease alone authorizes nothing. This is the recheck against
        // current durable state, and the only point a credential exists.
        // A busy custody HERE is not a transient (MIK-8428): the refresh above
        // may already have refreshed or rotated the grant with the provider,
        // an effect that spends the call's nonce witness, so this site keeps
        // the plain refusal (no retryable answer, no refund). Only the resolve
        // and refresh admissions, refused before anything ran, are `Busy`.
        let credentials = self.custody.release(&lease).await.map_err(|error| {
            MintError::Other(refusal(
                "managed account credential was not released",
                &error,
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
            expires_at: now,
            subject_key: binding.clone(),
            audience: backend.audience.clone(),
            // Scope authority lives on the lease, which is built from the
            // durable record — never from a claim the caller made.
            scopes: lease.scopes.clone(),
            cache_binding: binding,
        };
        Ok((credential, lease))
    }

    /// A current-grant check for listings: the cache binding `principal`'s
    /// credential would carry, read from the current lease without refreshing,
    /// releasing or minting (MIK-7690). `None` where [`Self::prepare_held_classified`]
    /// refuses before minting: no account key, no usable grant, or a grant
    /// fenced by a changed descriptor. A credential that fails header
    /// validation at mint is not predicted here.
    #[cfg(test)]
    pub(crate) async fn view_binding(&self, principal: Principal<'_>) -> Option<String> {
        self.view_binding_checked(principal).await.ok()
    }

    /// [`Self::view_binding`] with the reason it failed (MIK-8392): the
    /// custody error goes through [`refusal`]'s partition, so absence,
    /// revocation and reconnect-required (what a connect journey fixes) stay
    /// apart from a busy custody, a shutdown or a store failure. A caller
    /// that judges liveness must not read the second kind as "no view".
    /// Mint-free, like `view_binding`: no refresh, no provider call.
    #[cfg(test)]
    pub(crate) async fn view_binding_checked(
        &self,
        principal: Principal<'_>,
    ) -> Result<String, PropagationError> {
        match self.view_binding_classified(principal).await {
            ViewBinding::Bound(binding) => Ok(binding),
            ViewBinding::NoView(error)
            | ViewBinding::Transient(error)
            | ViewBinding::Unavailable(error) => Err(error),
        }
    }

    /// The mint-free view read with a busy custody kept distinct (MIK-8392
    /// Busy parity): decided from [`CustodyError::Busy`] itself, never text.
    pub(crate) async fn view_binding_classified(&self, principal: Principal<'_>) -> ViewBinding {
        self.read_binding(principal, cache_binding).await
    }

    /// The events fence: the mint-free read of the grant a delivery and a
    /// listener run are fenced on. The same read as the view, keyed on the
    /// stable grant only, so an ordinary token refresh does not move it.
    pub(crate) async fn fence_binding(&self, principal: Principal<'_>) -> ViewBinding {
        self.read_binding(principal, fence_key).await
    }

    /// The one mint-free read behind both bindings; `encode` names what the
    /// binding is keyed on.
    async fn read_binding(
        &self,
        principal: Principal<'_>,
        encode: fn(&AccountKey, &CredentialLease) -> Result<String, PropagationError>,
    ) -> ViewBinding {
        let account = match account_key(Some(principal), &self.descriptor) {
            Ok(account) => account,
            Err(error) => {
                return ViewBinding::Unavailable(PropagationError::Refuse(format!(
                    "account identity binding refused: {error}"
                )));
            }
        };
        let current = match self.custody.resolve(&account).await {
            Ok(current) => current,
            Err(error) => {
                return match error {
                    CustodyError::Busy => {
                        ViewBinding::Transient(refusal("managed account view", &error))
                    }
                    _ => match refusal("managed account view", &error) {
                        error @ (PropagationError::AccountNotConnected(_)
                        | PropagationError::AccountReconnectRequired(_)) => {
                            ViewBinding::NoView(error)
                        }
                        error => ViewBinding::Unavailable(error),
                    },
                };
            }
        };
        if let Err(error) = self.fence_changed_descriptor(&current) {
            return ViewBinding::NoView(error);
        }
        match encode(&account, &current) {
            Ok(binding) => ViewBinding::Bound(binding),
            Err(error) => ViewBinding::Unavailable(error),
        }
    }

    /// Refuse a grant stored under a descriptor revision other than the live
    /// one. Nothing is written: the fence is a function of the stored revision
    /// and the installed configuration, so reverting the edit restores service
    /// and reconnecting (which stores the live revision) clears it.
    fn fence_changed_descriptor(&self, lease: &CredentialLease) -> Result<(), PropagationError> {
        if lease.descriptor_revision == self.descriptor_revision {
            return Ok(());
        }
        Err(PropagationError::AccountReconnectRequired(format!(
            "managed account '{}' was connected under a different account configuration; \
             reconnect the account to grant the current one",
            self.descriptor.descriptor_id
        )))
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
    /// [`PropagationError::Refuse`] naming the custody refusal, a busy custody
    /// kept typed: nothing is sent before this recheck (MIK-8428 Case A).
    pub(crate) async fn recheck(&self, lease: &CredentialLease) -> Result<(), MintError> {
        // Bound to this statement: the released token is never bound to a name
        // that outlives the check it exists for (CWE-226).
        self.custody
            .release(lease)
            .await
            .map_err(|error| match &error {
                // Audited as the recheck it is, not as the view read.
                CustodyError::Busy => MintError::Busy(refusal("managed account recheck", &error)),
                _ => MintError::Other(refusal(
                    "managed account credential is no longer releasable",
                    &error,
                )),
            })?;
        Ok(())
    }
}

/// One managed credential's custody handle: the vault that released it and
/// the lease it was released under (A11-e′).
///
/// Only [`VaultStrategy::prepare_held_classified`] builds one, so no other strategy can
/// hand a dispatch site a forced refresh. The lease is a non-secret binding:
/// holding it is not holding a token.
pub(crate) struct ManagedLease {
    strategy: Arc<VaultStrategy>,
    lease: CredentialLease,
}

impl ManagedLease {
    /// Whether `vault` is the very instance that released this lease.
    pub(crate) fn minted_by(&self, vault: &Arc<VaultStrategy>) -> bool {
        Arc::ptr_eq(vault, &self.strategy)
    }

    /// The real custody release for this lease, refused unless `installed` is
    /// still the very vault that released it: a descriptor re-installed
    /// against different custody cannot be rechecked with the previous one.
    pub(crate) async fn recheck(&self, installed: &Arc<VaultStrategy>) -> Result<(), MintError> {
        if !self.minted_by(installed) {
            return Err(MintError::Other(PropagationError::Refuse(
                "the managed custody backing it was replaced after the credential was minted"
                    .to_string(),
            )));
        }
        self.strategy.recheck(&self.lease).await
    }

    /// The events fence binding of the grant these headers were released
    /// under: the same encoding [`VaultStrategy::fence_binding`] reads from
    /// custody, so a listener run and a delivery compare like with like.
    ///
    /// # Errors
    /// The account key cannot be digested.
    pub(crate) fn fence_binding(&self) -> Result<String, PropagationError> {
        fence_key(&self.lease.account, &self.lease)
    }

    /// A11-c: the backend answered this dispatch with HTTP 401. At most one
    /// forced refresh, then the caller's answer: a reconnect refusal when the
    /// provider killed the grant, otherwise the rejection mark. A custody
    /// refusal that connecting cannot fix (busy, shut down, a store fault)
    /// leaves `refused` as it was.
    pub(crate) async fn after_upstream_401(&self, refused: crate::Error) -> crate::Error {
        match self
            .strategy
            .custody
            .refresh_after_rejection(&self.lease)
            .await
        {
            Ok(outcome) => super::refusal::mark_rejection(outcome, &refused),
            Err(error) => {
                let cause = refusal("the backend refused the account's token", &error);
                if matches!(cause, PropagationError::AccountReconnectRequired(_)) {
                    super::refusal::mark(
                        crate::Error::Config(cause.to_string()),
                        &cause,
                        Some(&self.strategy.descriptor.descriptor_id),
                    )
                } else {
                    refused
                }
            }
        }
    }
}

impl VaultStrategy {
    /// [`Self::prepare`], keeping the custody handle with the lease so a 401
    /// seen after dispatch can force a refresh of exactly this grant; a busy
    /// custody is kept typed (MIK-8428).
    pub(crate) async fn prepare_held_classified(
        self: &Arc<Self>,
        principal: Principal<'_>,
        backend: &BackendDescriptor,
    ) -> Result<(PropagatedCredential, ManagedLease), MintError> {
        let (credential, lease) = self.prepare_classified(principal, backend).await?;
        Ok((
            credential,
            ManagedLease {
                strategy: Arc::clone(self),
                lease,
            },
        ))
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

/// What the events fence is keyed on: [`cache_binding`] without
/// `token_revision`. A refresh moves only the token, so it never ends a
/// listener run; a re-grant, a narrowing (it bumps the epoch) and a
/// descriptor move each change it. Same length prefixes, so no two field
/// tuples encode alike.
fn fence_key(account: &AccountKey, lease: &CredentialLease) -> Result<String, PropagationError> {
    let digest = account
        .digest()
        .map_err(|error| PropagationError::Refuse(format!("account key is unusable: {error}")))?;
    Ok(format!(
        "acct:fence:v1:{digest}:{}:{}:{}:{}:{}",
        lease.generation.len(),
        lease.generation,
        lease.authorization_epoch,
        lease.descriptor_revision.len(),
        lease.descriptor_revision,
    ))
}

/// The events observation key for `account` on `audience`: the account digest and audience only. No
/// lease field is in it, so a rotation keeps the listener's route; the lease is fenced separately.
///
/// # Errors
/// The account key cannot be digested.
pub(crate) fn observation_key(
    account: &AccountKey,
    audience: &str,
) -> Result<String, PropagationError> {
    let digest = account
        .digest()
        .map_err(|error| PropagationError::Refuse(format!("account key is unusable: {error}")))?;
    Ok(format!("acct:v1:{digest}:{}:{audience}", audience.len()))
}

/// [`cache_binding`] for a lease of `generation`, so a test plants the key
/// dispatch mints rather than a hand-written copy of its format.
#[cfg(test)]
pub(super) fn cache_binding_for_test(account: &AccountKey, generation: &str) -> String {
    let lease = CredentialLease {
        account: account.clone(),
        generation: generation.to_owned(),
        authorization_epoch: 1,
        scopes: Vec::new(),
        descriptor_revision: "0".repeat(64),
        token_revision: 1,
    };
    cache_binding(account, &lease).expect("a valid account key binds")
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

#[cfg(test)]
#[path = "vault_tests.rs"]
mod vault_tests;
