// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Identity-propagation and account credential resolution.

use std::sync::Arc;

use super::account_mint;
use super::{CallerCredential, HeldCredential};
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
        Ok(self
            .resolve_propagation_credential(server, verified_identity)
            .await?
            .0)
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
        let backend = self.backends.get(server);
        self.resolve_propagation_credential_held_for(server, backend.as_deref(), caller)
            .await
            .map(|(headers, cache_binding, _)| (headers, cache_binding))
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
    ) -> Result<HeldCredential> {
        let Some(idp_cfg) = backend.and_then(|b| b.identity_propagation_config().cloned()) else {
            Self::refuse_unbound_account_backend(server, backend)?;
            return Ok((Vec::new(), None, None));
        };
        let cred = self
            .resolve_caller_credential_as(server, backend, &idp_cfg, caller)
            .await?;
        Ok((cred.headers, cred.cache_binding, cred.managed))
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
        let backend = self.backends.get(server);
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

    /// With the caller's provenance, so the sole operator can be served (#1961).
    pub(super) async fn resolve_caller_credential_as(
        &self,
        server: &str,
        backend: Option<&crate::backend::Backend>,
        idp_cfg: &crate::identity_propagation::IdentityPropagationConfig,
        caller: CallerProof<'_>,
    ) -> Result<CallerCredential> {
        use crate::identity_propagation::BackendDescriptor;

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
            return refuse("the request carries no verified end-user identity".to_string()).await;
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

        let descriptor = BackendDescriptor {
            id: server.to_string(),
            audience: idp_cfg.audience.clone(),
            token_exchange_endpoint: idp_cfg.token_exchange_endpoint.clone(),
            token_exchange_scope: idp_cfg.token_exchange_scope.clone(),
        };
        // A11-e′: a managed descriptor mints through its typed vault, the SAME
        // instance as `strategy` (`account_strategies.rs` `InstalledAccount`),
        // whose `propagate` is `prepare` minus the lease. Keeping the lease is
        // the only difference: headers, binding, refusals and audit are unchanged.
        match account_mint::mint_held(managed_vault.as_ref(), &strategy, principal, &descriptor)
            .await
        {
            Ok((cred, managed)) => {
                // Validate every header parses BEFORE dispatch, so an invalid
                // minted credential fails closed rather than silently letting the
                // static Authorization through (MIK-6734 review carry-forward).
                for (k, v) in &cred.headers {
                    if k.parse::<reqwest::header::HeaderName>().is_err()
                        || v.parse::<reqwest::header::HeaderValue>().is_err()
                    {
                        return refuse(format!("minted credential header '{k}' is invalid")).await;
                    }
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
                Ok(CallerCredential {
                    headers: cred.headers,
                    cache_binding: Some(cred.cache_binding),
                    managed,
                })
            }
            Err(e) => refuse(format!("credential minting failed: {e}"))
                .await
                .map_err(|refused| {
                    let account_id = backend.and_then(|b| b.account_descriptor_id());
                    crate::personal_accounts::refusal::mark(refused, &e, account_id)
                }),
        }
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
    /// cache is consulted.
    ///
    /// `Ok(None)` means there is nothing to resolve on this route: the target
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
    ) -> Result<Option<Arc<crate::identity_propagation::PreparedAccountCredential>>> {
        use crate::identity_propagation::AccountCredential;

        let Some(capabilities) = self.get_capabilities() else {
            return Ok(None);
        };
        if server != capabilities.name {
            return Ok(None);
        }
        let Some(definition) = capabilities.get(tool) else {
            return Ok(None);
        };
        let Some(account) = definition.auth.account.as_deref() else {
            return Ok(None);
        };
        match self
            .account_strategies
            .resolve(account, &definition.auth.key, caller)
            .await?
        {
            AccountCredential::Legacy => Ok(None),
            AccountCredential::Prepared(prepared) => Ok(Some(prepared)),
        }
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
        self.refuse_shared_oauth_login(server, tool, &caller_credential, backend)?;
        let resolving = self.resolve_capability_account_credential(server, tool, caller_proof);
        let account_credential = self
            .with_connect_offer(resolving.await, verified_identity)
            .await?;
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
        })
    }
}

/// What [`MetaMcp::resolve_dispatch`] resolved for one call.
pub(super) struct ResolvedDispatch {
    /// The MCP route's per-user propagation credential, or none.
    pub(super) caller_credential: CallerCredential,
    /// The capability route's account credential, or none.
    pub(super) account_credential:
        Option<Arc<crate::identity_propagation::PreparedAccountCredential>>,
    /// The dispatch binding: whichever of the two names a per-caller binding.
    pub(super) binding: Option<String>,
}
