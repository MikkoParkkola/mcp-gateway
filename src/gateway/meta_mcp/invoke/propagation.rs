// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Identity-propagation and account credential resolution.

use std::sync::Arc;

use super::account_mint;
use super::{CallerCredential, DispatchCredential};
use crate::events::FenceRead;
use crate::gateway::meta_mcp::MetaMcp;
use crate::identity_propagation::{CallerProof, CallerProvenance, audit_subject};
use crate::personal_accounts::identity::Principal;
use crate::{Error, Result};

impl MetaMcp {
    /// Resolve the per-user propagation headers for a backend by name, for the
    /// direct backend route (`/mcp/{name}`) which does not go through
    /// `dispatch_to_backend` (MIK-6704). Returns the empty vec when the backend
    /// is not propagation-configured (unchanged static path); fail-closed `Err`
    /// for a `required` backend with no identity/strategy.
    pub async fn resolve_propagation_headers(
        &self,
        server: &str,
        verified_identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
    ) -> Result<Vec<(String, String)>> {
        #[allow(
            clippy::disallowed_methods,
            reason = "Discovery: the headers API forwards to the credential API (design §2.6)"
        )]
        Ok(self
            .resolve_propagation_credential(server, verified_identity)
            .await?
            .0)
    }

    /// The headers an events listener of `server` sends as `identity`:
    /// the audited mint a call uses, with the same transport
    /// check, header validation, audit record and refusals. Fail-closed even
    /// on a non-required backend: a listener with nothing minted sends
    /// nothing, never the gateway's own credential. A vault mint names the
    /// fence binding of the grant it released, from the lease itself.
    ///
    /// # Errors
    /// No such backend, no identity propagation on it, a refused or failed
    /// mint, an unavailable audit log, an empty minted set, or a vault lease
    /// whose binding cannot be encoded.
    pub(crate) async fn mint_listener_credential(
        &self,
        server: &str,
        identity: &crate::key_server::oidc::VerifiedIdentity,
    ) -> Result<crate::events::ListenerGrant> {
        let backend = self.backends.get_for(
            crate::gateway::meta_mcp::scoped_backends::Unscoped::Background,
            server,
        );
        let Some(idp_cfg) = backend
            .as_deref()
            .and_then(|b| b.identity_propagation_config().cloned())
        else {
            return Err(Error::Config(format!(
                "events listener for backend '{server}': no identity propagation"
            )));
        };
        let caller = CallerProof::new(Some(identity), CallerProvenance::Anonymous);
        let mut minted = self
            .resolve_caller_credential_as(server, backend.as_deref(), &idp_cfg, caller)
            .await?;
        if minted.headers.is_empty() {
            return Err(Error::Config(format!(
                "events listener for backend '{server}': nothing was minted"
            )));
        }
        let fence = minted
            .managed
            .as_ref()
            .map(crate::personal_accounts::ManagedLease::fence_binding)
            .transpose()
            .map_err(|error| {
                Error::Config(format!("events listener for backend '{server}': {error}"))
            })?;
        Ok(crate::events::ListenerGrant {
            headers: std::mem::take(&mut minted.headers),
            fence,
        })
    }

    /// The grant an events listener of `server` observing as `identity` is
    /// fenced on: the vault's stable binding, read without minting or
    /// refreshing. `None` when no managed account backs the backend, so
    /// nothing rotates under it.
    ///
    /// # Errors
    /// [`FenceRead::Closed`] when the backend is gone or the caller has no
    /// view of the grant (revoked, reconnect required, descriptor moved);
    /// [`FenceRead::Busy`] when custody cannot answer now.
    pub(crate) async fn listener_fence_binding(
        &self,
        server: &str,
        identity: &crate::key_server::oidc::VerifiedIdentity,
    ) -> std::result::Result<Option<String>, FenceRead> {
        use crate::personal_accounts::ViewBinding;
        let backend = self.backends.get_for(
            crate::gateway::meta_mcp::scoped_backends::Unscoped::Background,
            server,
        );
        let backend = backend.as_deref().ok_or(FenceRead::Closed)?;
        let Some(vault) = self
            .account_strategies
            .managed_vault(backend.account_descriptor_id())
        else {
            return Ok(None);
        };
        let caller = CallerProof::new(Some(identity), CallerProvenance::Anonymous);
        let principal = self
            .principal_for(backend, caller)
            .ok_or(FenceRead::Closed)?;
        match vault.fence_binding(principal).await {
            ViewBinding::Bound(binding) => Ok(Some(binding)),
            ViewBinding::NoView(_) => Err(FenceRead::Closed),
            ViewBinding::Transient(_) | ViewBinding::Unavailable(_) => Err(FenceRead::Busy),
        }
    }

    /// Like [`Self::resolve_propagation_headers`] but also returns the caller's
    /// stable identity binding (MIK-6784), so the direct backend route can
    /// partition upstream `MCP-Session-Id` state per identity. The binding is
    /// `None` for a non-propagation backend (unchanged static path).
    ///
    /// # Errors
    ///
    /// Fail-closed `Err` for a `required` backend with no identity/strategy —
    /// same contract as [`Self::resolve_propagation_headers`].
    pub async fn resolve_propagation_credential(
        &self,
        server: &str,
        verified_identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
    ) -> Result<(Vec<(String, String)>, Option<String>)> {
        // Identity-only by construction; production reads pass a proof (#2231).
        let caller = CallerProof::new(verified_identity, CallerProvenance::Anonymous);
        let backend = self.backends.get_for(
            crate::gateway::meta_mcp::scoped_backends::Unscoped::Discovery,
            server,
        );
        self.resolve_propagation_credential_held_for(server, backend.as_deref(), caller)
            .await
            // A public API that has returned a plain `Vec` since before the
            // send recheck: the secret is moved out, never copied, and from
            // here its owner is the caller. Changing the type is an API change.
            .map(|(mut lent, cache_binding, _)| (std::mem::take(&mut *lent.headers), cache_binding))
    }

    /// [`Self::resolve_propagation_credential`] for the caller `caller` proves,
    /// keeping the managed lease for the direct route's post-dispatch 401 site
    /// (A11-e′). The direct route passes its classified proof, so the sole
    /// operator is served there as on `gateway_invoke` (#2190).
    /// [`Self::resolve_propagation_credential`] for the caller `caller` proves,
    /// keeping the managed lease for the direct route's post-dispatch 401 site
    /// (A11-e'), against the backend the caller already holds. A route that
    /// captured the instance it will dispatch through must resolve against THAT
    /// instance: a name lookup can return a replacement registered by a reload
    /// in between, and the credential rules of one backend would then apply to
    /// a request sent through another (MIK-7804). `None` is a backend the
    /// registry does not hold, as a name miss always was. The direct route
    /// passes its classified proof, so the sole operator is served there as on
    /// `gateway_invoke` (#2190).
    pub(crate) async fn resolve_propagation_credential_held_for(
        &self,
        server: &str,
        backend: Option<&crate::backend::Backend>,
        caller: CallerProof<'_>,
    ) -> Result<DispatchCredential> {
        self.resolve_propagation_credential_attempted_for(server, backend, caller)
            .await
            .map(|(held, _attempted, _unproven)| held)
    }

    /// [`Self::resolve_propagation_credential_held_for`] for the direct route,
    /// as three values:
    /// - the held credential;
    /// - whether a mint was attempted whatever came of it, which the direct
    ///   route's refund rule counts as an effect (MIK-8379 H1);
    /// - the refusal a stored per-user result answers with when this
    ///   propagation-configured backend minted nothing (an optional backend's
    ///   static fallback, IDP.5), else `None`: the same proof `/mcp` judges
    ///   a stored replay by (MIK-8434). A backend with no propagation config
    ///   proves nothing and needs nothing, so it is `None` too.
    pub(crate) async fn resolve_propagation_credential_attempted_for(
        &self,
        server: &str,
        backend: Option<&crate::backend::Backend>,
        caller: CallerProof<'_>,
    ) -> Result<(DispatchCredential, bool, Option<Error>)> {
        let Some(idp_cfg) = backend.and_then(|b| b.identity_propagation_config().cloned()) else {
            Self::refuse_unbound_account_backend(server, backend)?;
            return Ok((
                (crate::transport::LentCredential::default(), None, None),
                false,
                None,
            ));
        };
        let mut cred = self
            .resolve_caller_credential_as(server, backend, &idp_cfg, caller)
            .await?;
        let unproven = cred
            .cache_binding
            .is_none()
            .then(|| super::stored_proof::unminted_refusal(server));
        // Moved, not cloned: no second copy of the caller's secret is left
        // behind outside the zeroizing holder.
        let lent = crate::transport::LentCredential {
            headers: std::mem::take(&mut cred.headers),
            check: cred.check.take(),
        };
        Ok((
            (lent, cred.cache_binding, cred.managed),
            cred.attempted,
            unproven,
        ))
    }

    /// Fail closed for a backend that names an `accounts.descriptors` entry but
    /// reached dispatch with no compiled propagation configuration.
    ///
    /// Startup compiles a bound backend's descriptor into its effective
    /// `identity_propagation` before the backend is constructed, so the only
    /// way to observe this state is a registration rebuilt from the raw config
    /// (a hot reload) that lost the binding. Dispatching then would send the
    /// call with no per-user credential at all — the exact silent downgrade the
    /// account reference exists to prevent — so it is refused instead.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] naming the backend and its descriptor reference.
    pub(super) fn refuse_unbound_account_backend(
        server: &str,
        backend: Option<&crate::backend::Backend>,
    ) -> Result<()> {
        let account = backend.and_then(|b| b.account_descriptor_id().map(str::to_string));
        match account {
            Some(account) => Err(Error::Config(format!(
                "backend '{server}' is bound to account '{account}' but no account strategy is \
                 installed for it; refusing to dispatch without the account holder's credential"
            ))),
            None => Ok(()),
        }
    }

    /// Resolve the per-user identity-propagation credential for a backend
    /// configured with `identity_propagation` (MIK-6704 / ADR-007). This is the
    /// single identity gate: minting, fail-closed enforcement, and the cache
    /// binding are decided once here, then reused for the cache key AND dispatch.
    ///
    /// Fail-closed for a `required` backend: returns `Err` — never a
    /// static-credential fallback — when there is no verified identity, no
    /// propagation strategy wired, the strategy refuses, or a minted header does
    /// not parse. For a non-required backend, a mint failure degrades to the
    /// empty credential (no headers, no binding → shared cache key, best-effort).
    /// Identity-only; production callers pass their proof to the `_as` form.
    #[cfg(test)]
    pub(super) async fn resolve_caller_credential(
        &self,
        server: &str,
        idp_cfg: &crate::identity_propagation::IdentityPropagationConfig,
        verified_identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
    ) -> Result<CallerCredential> {
        let caller = CallerProof::new(verified_identity, CallerProvenance::Anonymous);
        let backend = self.backends.for_test().get(server);
        self.resolve_caller_credential_as(server, backend.as_deref(), idp_cfg, caller)
            .await
    }

    /// Who a credential for `descriptor_id`'s backend is resolved for: the
    /// managed vault's own sole-operator predicate when the backend is bound to
    /// a managed account (as REST, #1961), otherwise the verified identity only.
    pub(in crate::gateway::meta_mcp) fn caller_principal<'a>(
        &self,
        descriptor_id: Option<&str>,
        caller: CallerProof<'a>,
    ) -> Option<Principal<'a>> {
        match self.account_strategies.managed_vault(descriptor_id) {
            Some(vault) => vault.principal(caller),
            None => caller.verified().map(Principal::Verified),
        }
    }

    /// A minted credential as a dispatch carries it, with the per-send check
    /// every lent-only send of it runs first: the managed lease's recheck,
    /// else its expiry.
    fn minted_credential(
        &self,
        cred: crate::identity_propagation::PropagatedCredential,
        managed: Option<crate::personal_accounts::ManagedLease>,
        descriptor_id: Option<&str>,
    ) -> CallerCredential {
        let expiry = account_mint::expiry_of(&cred);
        let check = account_mint::send_check_for(
            &self.account_strategies,
            (descriptor_id, managed.as_ref()),
            (expiry, &cred.headers),
        );
        CallerCredential {
            headers: cred.headers.into(),
            cache_binding: Some(cred.cache_binding),
            managed,
            attempted: false,
            expiry: Some(expiry),
            check: Some(check),
        }
    }

    /// With the caller's provenance, so the sole operator can be served (#1961).
    pub(super) async fn resolve_caller_credential_as(
        &self,
        server: &str,
        backend: Option<&crate::backend::Backend>,
        idp_cfg: &crate::identity_propagation::IdentityPropagationConfig,
        caller: CallerProof<'_>,
    ) -> Result<CallerCredential> {
        // Audit context (MIK-6740, IDP4): every mint and every fail-closed
        // refusal on THIS route is recorded, identically to the direct backend
        // route. Only subject/backend/audience/reason reach the log — never the
        // minted credential bytes.
        let audit_logger = self.transparency_logger.as_ref();
        // #1961: the vault's own sole-operator predicate (as REST); else verified only.
        let descriptor_id = backend.and_then(|b| b.account_descriptor_id().map(str::to_owned));
        let managed_vault = self
            .account_strategies
            .managed_vault(descriptor_id.as_deref());
        let principal = self.caller_principal(descriptor_id.as_deref(), caller);
        let subject_id = principal.map_or_else(|| audit_subject(None), Principal::stable_actor_id);
        let audience = idp_cfg.audience.as_str();

        let vault = idp_cfg.strategy == crate::identity_propagation::PropagationStrategyKind::Vault;
        let refuse = async |msg: String| -> Result<CallerCredential> {
            if idp_cfg.required || vault {
                // Refused either way; the helper logs a failed audit write.
                Self::audit_refused_credential(audit_logger, &subject_id, server, audience, &msg)
                    .await;
                Err(Error::Config(format!(
                    "identity propagation required for backend '{server}' but {msg}"
                )))
            } else {
                // Best-effort: non-required backend proceeds with static creds.
                // This is the static-credential fallback (IDP.5), not a mint or
                // a fail-closed refusal, so — like the direct route's
                // `Ok(empty)` branch — it is intentionally not audited.
                Ok(CallerCredential::default())
            }
        };

        // Vault is installed only for a compiled account-bound backend. A raw
        // declaration cannot borrow a global strategy, even when optional.
        let account_bound = descriptor_id.is_some();
        if vault && !account_bound {
            let msg = "raw Vault identity propagation requires an account descriptor";
            return refuse(msg.to_string()).await;
        }

        // MIK-6710: refuse BEFORE minting when this backend's transport cannot
        // carry `extra_headers` on the wire (stdio, websocket) — otherwise a
        // `required` backend would mint successfully here and then silently
        // run unauthenticated once `request_with_headers` drops the credential.
        //
        // A missing registry entry defaults to "capable": every real caller
        // resolves `idp_cfg` FROM the registered backend, so a `Some(idp_cfg)`
        // guarantees the backend exists in production; "not found" only happens
        // in unit tests against a fabricated config, and a genuinely absent
        // backend fails downstream at dispatch regardless.
        let transport_capable =
            backend.is_none_or(crate::backend::Backend::transport_carries_identity_headers);
        if let Err(msg) = crate::identity_propagation::ensure_transport_carries_identity_headers(
            idp_cfg.required,
            transport_capable,
        ) {
            return refuse(msg).await;
        }

        let Some(principal) = principal else {
            // The one refusal here that is a decision about the caller; the
            // others are configuration the operator has not finished.
            return refuse(NO_IDENTITY.into()).await.inspect_err(raise);
        };
        // An explicit account reference requires its own installed strategy.
        // A missing or stale install must never borrow an unrelated global
        // strategy. Descriptorless callers retain their existing behavior.
        let strategy = if account_bound {
            self.backend_identity_strategy(server)
        } else {
            self.backend_identity_strategy(server)
                .or_else(|| self.identity_propagation.read().clone())
        };
        let Some(strategy) = strategy else {
            return refuse("no identity-propagation strategy is configured".to_string()).await;
        };

        let descriptor = account_mint::descriptor_for(server, idp_cfg);
        // A11-e′: a managed descriptor mints through its typed vault, the SAME
        // instance as `strategy` (`account_strategies.rs` `InstalledAccount`),
        // whose `propagate` is `prepare` minus the lease. Keeping the lease is
        // the only difference: headers, binding, refusals and audit are unchanged.
        let minted =
            account_mint::mint_held(managed_vault.as_ref(), &strategy, principal, &descriptor)
                .await;
        // Every outcome from here on followed a strategy call, so each counts as
        // an attempt in one place (MIK-8379 H1): a mint, a failed mint that
        // falls back to static credentials, or an invalid minted header that
        // does. An attempt may have reached the issuer.
        let outcome = async {
            match minted {
                Ok((cred, managed)) => {
                    // Every header must parse BEFORE dispatch.
                    if let Some(k) = account_mint::invalid_header(&cred.headers) {
                        return refuse(format!("minted credential header '{k}' is invalid")).await;
                    }
                    // cache_binding distinguishes user AND audience (collision-safe),
                    // so per-user results cache in isolation instead of being dropped
                    // (IDP.8 — replaces the earlier blanket cache bypass).
                    if !cred.headers.is_empty() {
                        Self::audit_minted_credential(
                            server,
                            idp_cfg,
                            audit_logger,
                            &subject_id,
                            audience,
                        )
                        .await?;
                    }
                    Ok(self.minted_credential(cred, managed, descriptor_id.as_deref()))
                }
                // A busy custody at the mint released nothing (MIK-8428):
                // the one transient record and sealed retryable answer
                // replace this site's refusal record and `Config` fold.
                Err(error) => {
                    if let crate::personal_accounts::MintError::Busy(busy) = &error
                        && let Some(descriptor_id) = descriptor_id.as_deref()
                    {
                        Err(self
                            .account_strategies
                            .transient_mint_refusal(audit_logger, descriptor_id, caller, busy)
                            .await)
                    } else {
                        let error = error.into_error();
                        refuse(format!("credential minting failed: {error}"))
                            .await
                            .map_err(|refused| {
                                let account_id = backend.and_then(|b| b.account_descriptor_id());
                                crate::personal_accounts::refusal::mark(refused, &error, account_id)
                            })
                    }
                }
            }
        }
        .await;
        outcome.map(|cred| CallerCredential {
            attempted: true,
            ..cred
        })
    }

    /// Fail-closed hardening: a minted credential must never reach the caller
    /// without a durable audit record, so an audit-write failure here aborts
    /// the mint instead of letting it proceed. Split out of
    /// [`Self::resolve_caller_credential`] purely to keep that function under
    /// the line budget — logic and ordering are unchanged.
    ///
    /// Operator-misconfig fail-OPEN guard: the audit helper treats `logger =
    /// None` (transparency log disabled) as a no-op `Ok(())`. On a `required`
    /// backend that would let a minted per-user credential go on the wire
    /// with NO audit record — the "no mint without a durable audit record"
    /// guarantee silently evaporating via misconfiguration. When propagation
    /// is REQUIRED but no transparency log is configured, fail closed on the
    /// SAME path as an audit-write failure rather than mint blind.
    /// (Non-required backends keep the `None -> Ok(())` best-effort
    /// behavior — a mint there is not covered by the durable-record
    /// guarantee.)
    pub(super) async fn audit_minted_credential(
        server: &str,
        idp_cfg: &crate::identity_propagation::IdentityPropagationConfig,
        audit_logger: Option<&Arc<crate::security::TransparencyLogger>>,
        subject_id: &str,
        audience: &str,
    ) -> Result<()> {
        if idp_cfg.required && audit_logger.is_none() {
            return Err(Error::Internal(format!(
                "identity-propagation is required for backend '{server}' but no \
                 transparency log is configured; refusing to mint a per-user \
                 credential without a durable audit record"
            )));
        }
        if let Err(audit_err) = crate::identity_propagation::audit_identity_propagation(
            audit_logger,
            "idp_mint",
            subject_id,
            server,
            Some(audience),
            None,
        )
        .await
        {
            // CWE-209: `audit_err` can carry the transparency-log filesystem
            // path / IO detail. Keep it in the server log only; return a
            // generic client-facing message so the sensitive detail never
            // reaches the JSON-RPC caller (mirrors the direct route in
            // backend_handlers.rs).
            tracing::warn!(
                server,
                error = %audit_err,
                "identity-propagation mint audit write failed"
            );
            return Err(Error::Internal(format!(
                "identity-propagation audit unavailable for backend '{server}'"
            )));
        }
        Ok(())
    }

    /// Resolve the account credential a CAPABILITY tool needs, before any
    /// cache is consulted, with the `auth.account` it was read from (`None`
    /// when the capability names none): the one read of that reference, so
    /// what the dispatch records as its account (MIK-8407) is what it
    /// resolved, never a second read a reload could change.
    ///
    /// No credential means there is nothing to resolve on this route: the target
    /// is not the capability backend, the tool is not one of its capabilities,
    /// the capability names no account, or the account is an explicit `shared`
    /// descriptor whose static credential path is preserved unchanged. Every
    /// other outcome is either a credential minted for the verified caller by
    /// the ONE shared registry — the same instance the executor rechecks
    /// against — or a refusal that returns before the response cache is read.
    ///
    /// The reference read here is the capability's PRIMARY `auth`, which is the
    /// same `auth` the executor injects at egress; nothing here re-derives it
    /// from a provider name or a backend name.
    ///
    /// # Errors
    ///
    /// Every refusal from
    /// [`crate::identity_propagation::AccountStrategyRegistry::resolve`].
    pub(super) async fn resolve_capability_account_credential(
        &self,
        server: &str,
        tool: &str,
        caller: CallerProof<'_>,
    ) -> Result<CapabilityAccount> {
        use crate::identity_propagation::AccountCredential;

        let Some(capabilities) = self.caller_capabilities() else {
            return Ok((None, None));
        };
        if server != capabilities.name {
            return Ok((None, None));
        }
        let Some(definition) = capabilities.get(tool) else {
            return Ok((None, None));
        };
        let Some(account) = definition.auth.account.as_deref() else {
            return Ok((None, None));
        };
        let credential = match self
            .account_strategies
            .resolve(account, &definition.auth.key, caller)
            .await?
        {
            AccountCredential::Legacy => None,
            AccountCredential::Prepared(prepared) => Some(prepared),
        };
        Ok((Some(account.to_owned()), credential))
    }

    /// The credentials a call to `server:tool` dispatches under, and the one
    /// dispatch binding derived from them.
    ///
    /// One function, called by the dispatch itself and by a chain resume that
    /// must open its handle under the binding the stopped step minted with
    /// (MIK-8137): two derivations of "which binding is this call under" is
    /// how a mint and its redemption stop agreeing.
    ///
    /// Resolved before any cache is consulted (MIK-6734 / ADR-007): the MCP
    /// route's per-user propagation credential, fail-closed for a required
    /// backend, then the capability route's account credential, which comes
    /// from its own `auth.account` rather than the backend-keyed map. A refusal
    /// returns here, before anything is dispatched or spent.
    pub(super) async fn resolve_dispatch(
        &self,
        (server, tool): (&str, &str),
        backend: Option<&crate::backend::Backend>,
        caller_proof: CallerProof<'_>,
        verified_identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
    ) -> Result<ResolvedDispatch> {
        let caller_credential =
            if let Some(idp_cfg) = backend.and_then(|b| b.identity_propagation_config().cloned()) {
                let resolved =
                    self.resolve_caller_credential_as(server, backend, &idp_cfg, caller_proof);
                self.with_connect_offer(resolved.await, verified_identity)
                    .await?
            } else {
                Self::refuse_unbound_account_backend(server, backend)?;
                CallerCredential::default()
            };
        // The OAuth-isolation denial is delivered as this call's answer;
        // inside a composite step it is raised only while vouched.
        self.refuse_shared_oauth_login(server, tool, &caller_credential, backend)
            .inspect_err(|_| crate::gateway::delivery_facts::refused_while_vouched())?;
        let resolving = self.resolve_capability_account_credential(server, tool, caller_proof);
        let (capability_account, account_credential) = self
            .with_connect_offer(resolving.await, verified_identity)
            .await?;
        // The account this dispatch runs under, from the instance and the
        // reference resolved above (MIK-8407): a stored result records it,
        // and a replay is served only while it is still the target's.
        let account = backend
            .and_then(|backend| {
                backend
                    .identity_propagation_config()
                    .and(backend.account_descriptor_id())
            })
            .or(capability_account.as_deref())
            .map(|id| {
                crate::gateway::meta_mcp::stored_binding::binding_token(
                    &self.account_strategies,
                    id,
                )
            });
        // ONE binding for both cache layers and for the transport's session
        // partitioning. The MCP route's propagation binding when there is one,
        // otherwise the account credential's — they are never both present,
        // because one describes a backend's propagation config and the other a
        // capability's account reference.
        let binding = caller_credential.cache_binding.clone().or_else(|| {
            account_credential
                .as_ref()
                .map(|prepared| prepared.cache_binding().to_owned())
        });
        Ok(ResolvedDispatch {
            caller_credential,
            account_credential,
            binding,
            account,
            account_reference: capability_account,
        })
    }
}

/// What [`MetaMcp::resolve_dispatch`] resolved for one call.
pub(crate) struct ResolvedDispatch {
    /// The MCP route's per-user propagation credential, or none.
    pub(super) caller_credential: CallerCredential,
    /// The capability route's account credential, or none.
    pub(super) account_credential:
        Option<Arc<crate::identity_propagation::PreparedAccountCredential>>,
    /// The dispatch binding: whichever of the two names a per-caller binding.
    pub(super) binding: Option<String>,
    /// The account token this dispatch runs under
    /// (`AccountStrategyRegistry::binding_token`), shared accounts included;
    /// `None` when the target names no account (MIK-8407).
    pub(super) account: Option<String>,
    /// The capability's `auth.account` this resolution read (`None` when it
    /// names none), which its execution must still name (MIK-8407).
    pub(super) account_reference: Option<String>,
}

/// The account a dispatch resolved (MIK-8407): the prepared credential, and
/// the capability's `auth.account` reference it was resolved for, which the
/// executor refuses to run under any other.
#[derive(Clone, Default)]
pub(super) struct DispatchAccount {
    pub(super) credential: Option<Arc<crate::identity_propagation::PreparedAccountCredential>>,
    pub(super) reference: Option<String>,
}

impl DispatchAccount {
    /// The credential, handed over once (a bridged round reuses it, never a
    /// second resolution), with the reference kept for every round.
    pub(super) fn take(&mut self) -> Self {
        Self {
            credential: self.credential.take(),
            reference: self.reference.clone(),
        }
    }
}

/// [`ResolvedDispatch::into_parts`]: what a dispatch sends with.
pub(super) type DispatchParts = (CallerCredential, DispatchAccount, Option<String>);

/// A capability tool's `auth.account` and the credential resolved for it.
type CapabilityAccount = (
    Option<String>,
    Option<Arc<crate::identity_propagation::PreparedAccountCredential>>,
);

impl ResolvedDispatch {
    /// The caller credential, the account credential and the dispatch
    /// binding the dispatch consumes; the account token stays with the
    /// lift's judgement (MIK-8407).
    pub(super) fn into_parts(self) -> DispatchParts {
        let account = DispatchAccount {
            credential: self.account_credential,
            reference: self.account_reference,
        };
        (self.caller_credential, account, self.binding)
    }

    /// Whether the credential step may have reached an issuer: a failed
    /// optional mint counts too.
    pub(super) fn minted(&self) -> bool {
        self.caller_credential.cache_binding.is_some() || self.caller_credential.attempted
    }
}

/// The required-identity denial's reason.
const NO_IDENTITY: &str = "the request carries no verified end-user identity";

/// The delivered answer is the gateway refusing the caller: raised while the
/// cell still vouches for it, so a composite that goes on is not marked.
fn raise(_: &Error) {
    crate::gateway::delivery_facts::refused_while_vouched();
}
