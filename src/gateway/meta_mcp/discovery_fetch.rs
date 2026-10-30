// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How discovery gets a backend's tool list, and from whose pool slot.
//!
//! Split out of `search.rs` because these four are one concern — which slot a
//! discovery read comes from, and who is allowed to refresh it — and because
//! `search.rs` is over the file-size ceiling and may not grow.

use super::MetaMcp;
use super::visible::memo::{DescriptorId, HeldView, judge_held};
use crate::backend::Backend;
use crate::identity_propagation::{CallerProof, PropagationError};
use crate::personal_accounts::ViewBinding;
use crate::protocol::Tool;
use std::sync::Arc;
use tracing::debug;

impl MetaMcp {
    /// The caller's per-user credential for `server`: headers and cache binding.
    ///
    /// THE CONTRACT LIVES HERE, not on the context-taking
    /// [`MetaMcp::tool_credential_for`], because the protocol-level catalogue
    /// handlers — `prompts/list`, `resources/list` and
    /// `resources/templates/list` — are dispatched from the method table with
    /// no `MetaMcpCallerContext` to borrow. They build the same proof from the
    /// client and identity they receive.
    ///
    /// Returns empty WITHOUT calling the resolver when the resolver would find
    /// no principal for this caller on this backend (#2231). That short-circuit
    /// is load-bearing, not an optimisation: resolving mints over the network
    /// and writes a durable transparency-log record, and this runs in a loop
    /// over every registered backend on ordinary discovery. A caller with no
    /// verified identity therefore mints nothing and audits nothing (IDP.5) —
    /// except the sole operator on a managed-account backend, whom the vault's
    /// own predicate serves, exactly as `gateway_invoke` and the direct route do.
    ///
    /// A resolution failure is empty too, never an error: a caller who cannot
    /// mint for this backend simply gets no per-user view of it and falls back
    /// to the identity-free one. That fallback is NOT omission for most
    /// backends — the identity-free guard omits only a `required` backend, so a
    /// failed mint against a non-`required` one degrades to the shared
    /// catalogue rather than hiding it. Discovery must not fail wholesale
    /// because one backend out of many refused.
    pub(crate) async fn caller_credential_for_identity(
        &self,
        backend: &Backend,
        caller: CallerProof<'_>,
    ) -> (Vec<(String, String)>, Option<String>) {
        if self.principal_for(backend, caller).is_none() {
            return (Vec::new(), None);
        }
        self.resolve_propagation_credential_held_for(&backend.name, Some(backend), caller)
            .await
            .map(|(headers, binding, _lease)| (headers, binding))
            .unwrap_or_default()
    }

    /// [`Self::catalogue_credential_for`] for a request's caller context: the
    /// tool-discovery reads (listing and search) omit a backend on the same
    /// rule the prompt and resource catalogues do (#2326).
    ///
    /// ONE resolution per request per backend, returning BOTH halves, because
    /// the isolation verdict and the slot selection must not disagree about who
    /// the caller is (design §4.3's residual) — and because resolving twice
    /// would mint twice. `None` means omit.
    pub(crate) async fn tool_credential_for(
        &self,
        backend: &Backend,
        caller: &super::MetaMcpCallerContext<'_>,
    ) -> Option<(Vec<(String, String)>, Option<String>)> {
        self.catalogue_credential_for(backend, Self::proof_of(caller))
            .await
    }

    /// What `caller` proved: its verified identity, else its credential's
    /// provenance.
    pub(super) fn proof_of<'a>(caller: &super::MetaMcpCallerContext<'a>) -> CallerProof<'a> {
        CallerProof::new(caller.verified_identity, caller.provenance())
    }

    /// Whether `backend` has no view at all for `caller`: it is `required`
    /// and the resolver would find no principal, so
    /// [`Self::catalogue_credential_for`] omits it. Known here without a mint,
    /// for a reader that only counts (#2346).
    ///
    /// For a managed-account backend the caller's grant is read without
    /// refreshing or minting, so a principal with no usable grant has no view
    /// either, and neither does one whose binding the isolation guard or the
    /// per-user slot rule would refuse (MIK-7690).
    pub(super) async fn has_no_view_for(&self, backend: &Backend, caller: CallerProof<'_>) -> bool {
        // The listing behaviour is unchanged: a busy custody reads as no
        // view here, exactly as `view_binding` read it (MIK-8392).
        self.has_no_view_for_classified(backend, caller)
            .await
            .unwrap_or(true)
    }

    /// [`Self::has_no_view_for`] for the direct route's withheld gate
    /// (MIK-8361 ruling B): whether `caller` has no view of `backend`.
    /// Side-effect-free: it records no no-view marker, no account outcome and
    /// no audit row, and reads the grant without refreshing or minting.
    /// The one crate-visible entry to the predicate (approved visibility
    /// change, 2026-10-15).
    pub(crate) async fn caller_lacks_view(
        &self,
        backend: &Backend,
        caller: CallerProof<'_>,
    ) -> bool {
        self.has_no_view_for(backend, caller).await
    }

    /// [`Self::has_no_view_for`] with a busy custody kept distinct for the
    /// caller verdict (MIK-8392 Busy parity): `Err` is the transient, never
    /// a finding of no view.
    pub(super) async fn has_no_view_for_classified(
        &self,
        backend: &Backend,
        caller: CallerProof<'_>,
    ) -> std::result::Result<bool, PropagationError> {
        let required = backend
            .identity_propagation_config()
            .is_some_and(|cfg| cfg.required);
        let read = if required {
            self.classified_read(backend, caller).await
        } else {
            None
        };
        self.no_view_decision(backend, caller, read)
    }

    /// The caller's one mint-free view read on `backend`: `None` when the
    /// caller has no principal there or the backend has no managed vault.
    async fn classified_read(
        &self,
        backend: &Backend,
        caller: CallerProof<'_>,
    ) -> Option<ViewBinding> {
        let principal = self.principal_for(backend, caller)?;
        let vault = self
            .account_strategies
            .managed_vault(backend.account_descriptor_id())?;
        Some(vault.view_binding_classified(principal).await)
    }

    /// Whether `backend` has no view for `caller`, decided over the one read
    /// ([`Self::classified_read`]); `None` is no read, as with no vault.
    fn no_view_decision(
        &self,
        backend: &Backend,
        caller: CallerProof<'_>,
        read: Option<ViewBinding>,
    ) -> std::result::Result<bool, PropagationError> {
        if self.lacks_principal_on_required(backend, caller) {
            return Ok(true);
        }
        let required = backend
            .identity_propagation_config()
            .is_some_and(|cfg| cfg.required);
        if !required {
            return Ok(false);
        }
        if self.principal_for(backend, caller).is_none() {
            return Ok(true);
        }
        let Some(read) = read else {
            return Ok(false);
        };
        match read {
            ViewBinding::Bound(binding) => Ok(self
                .meta_route_isolation_refused_for_caller(backend, Some(&binding))
                || !backend.fetch_carries_caller_identity(Some(&binding))),
            ViewBinding::Transient(error) => Err(error),
            ViewBinding::NoView(_) | ViewBinding::Unavailable(_) => Ok(true),
        }
    }

    /// Re-check this caller's indexed slot on every managed-account backend
    /// against its current grant, read without refreshing or minting, and
    /// forget an entry the current grant no longer yields (MIK-8356 design
    /// R4.2, gpt r3 F2). Run at a listing's async entry, so the synchronous
    /// readers after it read a rotated or revoked grant's slot as cold, never
    /// as the caller's. One classified read per managed-account backend, with
    /// or without a slot indexed; it also becomes this request's account
    /// read (`memo::held_view_current`), so a publish that lands after it is
    /// judged against the grant it saw. A revoked caller's entry becomes
    /// `NoView` even over a stored read's running cold lease (MIK-8392 d1
    /// F9): intended, the revocation is the newer fact. A busy custody is not
    /// a revocation: it leaves a running cold lease standing, so that lease's
    /// winner still publishes, and keeps a held slot for the next request.
    pub(crate) async fn revalidate_caller_slots(&self, caller: CallerProof<'_>) {
        for backend in self
            .backends
            .all_for(crate::gateway::meta_mcp::scoped_backends::Unscoped::Discovery)
        {
            if backend.keeps_per_user_catalogues() {
                self.revalidate_backend_slot(&backend, caller).await;
            }
        }
        #[cfg(test)]
        super::visible::seams::revalidated().await;
    }

    /// [`Self::revalidate_caller_slots`] for one backend.
    async fn revalidate_backend_slot(&self, backend: &Backend, caller: CallerProof<'_>) {
        let Some(principal) = self.principal_for(backend, caller) else {
            return;
        };
        let id = principal.stable_actor_id();
        // Captured before the awaited read: an entry published during it is
        // not the one judged, and survives the conditional forget below.
        let seen = backend.caller_slot_held(&id);
        let read = self.classified_read(backend, caller).await;
        #[cfg(test)]
        super::visible::seams::custody_read().await;
        let bound = match &read {
            Some(ViewBinding::Bound(binding)) => Some(binding.clone()),
            _ => None,
        };
        if let Some(read) = &read {
            record_read(backend, read);
        }
        match self.no_view_decision(backend, caller, read) {
            Ok(false) => {}
            Err(_) if backend.cold_lease_remaining(&id).is_some() => return,
            Ok(true) | Err(_) => {
                backend.record_no_view(&id);
                return;
            }
        }
        if backend.caller_has_no_view(&id) {
            backend.forget_caller_principal(&id);
        }
        if let (Some(seen), Some(current)) = (seen, bound)
            && judge_held(Some(&current), seen.binding()) == HeldView::Stale
        {
            backend.forget_caller_held(&id, &seen);
        }
    }

    /// Whether `backend` must be omitted from a per-caller catalogue
    /// aggregation, and the credential to fetch it with if not.
    ///
    /// ONE HELPER FOR ALL THREE LIST HANDLERS (MIK-7334.CATALOGUE.1). Resolving
    /// the credential and evaluating the isolation verdict are a pair: the
    /// verdict is computed from the headers that were just minted, and the fetch
    /// that follows runs on the slot those headers opened. Splitting them across
    /// three handlers is how `resources/list` and `prompts/list` came to pass a
    /// constant `PoolKey::Shared` while `tools/list` passed a caller-derived key.
    ///
    /// `None` means omit. `Some((headers, binding))` is safe to fetch with, and
    /// `binding` is `None` for an identity-free caller, which selects the shared
    /// slot exactly as before.
    pub(super) async fn catalogue_credential_for(
        &self,
        backend: &Backend,
        caller: CallerProof<'_>,
    ) -> Option<(Vec<(String, String)>, Option<String>)> {
        let (headers, binding) = self.caller_credential_for_identity(backend, caller).await;
        if self.meta_route_isolation_refused_for_caller(backend, binding.as_deref()) {
            return None;
        }
        // A `required` backend has no identity-free view: on a single-user
        // gateway the guard above admits it, and the fill would then go out
        // over the shared session without the caller. One rule for every
        // catalogue read, the resource-owner lookup included.
        let required = backend
            .identity_propagation_config()
            .is_some_and(|cfg| cfg.required);
        if required && !backend.fetch_carries_caller_identity(binding.as_deref()) {
            return None;
        }
        Some((headers, binding))
    }

    /// The tools discovery should show for `backend`, from THIS CALLER's slot.
    ///
    /// `binding` and `headers` come from one `tool_credential_for` resolution
    /// (MIK-7334.CATALOGUE.1). `None`/empty is the identity-free caller and
    /// selects the shared slot, so single-tenant discovery is unchanged.
    ///
    /// The background refresh stays SHARED-only on purpose: it is spawned with
    /// only an `Arc<Backend>` and holds no credential, so letting it fill a
    /// per-user slot would write the static-credential catalogue under a user's
    /// identity — the original bug.
    ///
    /// THE TWO PATHS THEREFORE AGE DIFFERENTLY, and the difference is why the
    /// freshness check below is not symmetric:
    ///
    /// - **Shared**: serve the snapshot and refresh behind it. Something else
    ///   always will, so a stale read costs one interval of staleness and no
    ///   caller waits. Unchanged.
    /// - **Per-user**: NOTHING will ever refresh this slot on its own, because
    ///   the only refresher holds no credential. Serving a stale snapshot here
    ///   serves it forever — and the invoke path refreshes on TTL through
    ///   `get_or_fetch_shared`, so the same caller would see two different views
    ///   of one backend. A per-user slot that has aged out falls through to the
    ///   credentialed refetch below instead.
    ///
    /// An earlier revision claimed the inline refresh while returning above it,
    /// so the read it named was never reached (MIK-7334.CATALOGUE.1 C4).
    pub(super) async fn backend_tools_for_discovery(
        backend: &Arc<Backend>,
        allow_empty_cache_fetch: bool,
        binding: Option<&str>,
        headers: &[(String, String)],
    ) -> Option<Arc<Vec<Tool>>> {
        let tools = backend.get_cached_tools_snapshot_for(binding);
        // An empty shared slot is filled behind this read, never by it: one
        // never populated (outside `meta_mcp.warm_start`, or warm-start gave
        // up) is otherwise skipped by every search forever (#3036), and one
        // whose every tool is withheld must still refresh on TTL (#1441).
        // Single-flight and the fill cooldown keep a dead backend to one
        // `tools/list` per cooldown, however many searches arrive. An `Io`,
        // `Http` or `Tls` failure stamps no cooldown (`fill_check::Replay`);
        // the circuit breaker bounds those instead.
        if tools.is_empty() && binding.is_none() {
            Self::refresh_stale_backend_tools_in_background(backend);
        }
        if !tools.is_empty() {
            if binding.is_none() {
                // Shared: serve now, refresh behind. Byte-for-byte as before.
                Self::refresh_stale_backend_tools_in_background(backend);
                return Some(tools);
            }
            // Per-user: only a FRESH slot may be served from cache.
            if backend.has_cached_tools_for(binding) {
                return Some(tools);
            }
        }

        // A per-user slot fills on its owner's own credentialed read, never on a
        // background task's, so an empty one is always worth filling here.
        if allow_empty_cache_fetch || binding.is_some() {
            return match backend.get_tools_for_binding(binding, headers).await {
                Ok(tools) if !tools.is_empty() => Some(tools),
                Ok(_) => None,
                Err(e) => {
                    debug!(
                        backend = %backend.name,
                        error = %e,
                        "On-demand backend tool-cache fill failed"
                    );
                    None
                }
            };
        }

        None
    }

    pub(super) fn code_mode_backend_candidates(&self, query: &str) -> (Vec<Arc<Backend>>, bool) {
        if let Some((server, _)) = query.split_once(':')
            && !server.is_empty()
            && !server.contains('*')
            && !server.contains('?')
        {
            return self
                .backends
                .get_for(
                    crate::gateway::meta_mcp::scoped_backends::Unscoped::Discovery,
                    server,
                )
                .map_or_else(|| (Vec::new(), false), |backend| (vec![backend], true));
        }

        (
            self.backends
                .all_for(crate::gateway::meta_mcp::scoped_backends::Unscoped::Discovery),
            false,
        )
    }

    pub(super) async fn refresh_stale_backend_tools(backend: Arc<Backend>) {
        if let Err(e) = backend.get_tools_shared().await {
            debug!(
                backend = %backend.name,
                error = %e,
                "Background backend tool-cache refresh failed"
            );
        }
    }

    pub(super) fn refresh_stale_backend_tools_in_background(backend: &Arc<Backend>) {
        if !backend.has_cached_tools() {
            let backend = Arc::clone(backend);
            tokio::spawn(Self::refresh_stale_backend_tools(backend));
        }
    }

    /// Fill `backend`'s shared slot behind a read that carries no caller
    /// credential (MIK-7962). The fill runs over the identity-free shared
    /// transport, so a backend that propagates caller identity, or one the
    /// multi-user guard isolates (INV-2), is never asked here: credentialed
    /// discovery fills those, on the caller's own slot.
    pub(super) fn refresh_shared_behind_read(&self, backend: &Arc<Backend>) {
        if backend.identity_propagation_config().is_none()
            && !self.meta_route_isolation_refused(backend)
        {
            Self::refresh_stale_backend_tools_in_background(backend);
        }
    }
}

/// Make `read` this request's account read for `backend`'s account: the
/// binding a `Bound` read gave, else the unchecked marker (overwriting).
pub(super) fn record_read(backend: &Backend, read: &ViewBinding) {
    let Some(account) = backend.account_descriptor_id() else {
        return;
    };
    let account = DescriptorId(account.to_owned());
    match read {
        ViewBinding::Bound(binding) => {
            super::visible::memo::record_account_binding(&backend.name, &account, binding);
        }
        failed => {
            debug!(
                backend = %backend.name,
                error = ?failed.failure(),
                "account read did not bind; held views read cold for this request"
            );
            super::visible::memo::record_account_unchecked(&backend.name, &account);
        }
    }
}

#[cfg(test)]
impl MetaMcp {
    /// Test-only: open the slot production resolves for `caller` on `server`
    /// with the transport already seeded on the shared one.
    ///
    /// A propagating backend gives an identified caller its own slot whatever
    /// its `session_mode` (`Backend::pool_key_for`), so a fixture that seeds
    /// only the shared slot would send that caller to a slot with no wire. The
    /// binding is `resolve_caller_credential`'s `cache_binding` — the function
    /// dispatch calls — never a restated format, so a fixture cannot seed a slot
    /// production would not select. A caller the resolver refuses gets no slot
    /// here, which leaves a refusal test observing the very resolution it
    /// asserts on.
    ///
    /// THE RESOLVE IS REAL: it mints, audits and — for an account-bound backend
    /// — releases custody. Seed only backends whose test does not count those.
    pub(crate) async fn seed_caller_slot_for_test(
        &self,
        server: &str,
        caller: &crate::key_server::oidc::VerifiedIdentity,
    ) {
        let Ok((_, Some(binding))) = self
            .resolve_propagation_credential(server, Some(caller))
            .await
        else {
            return;
        };
        let backend = self
            .backends
            .for_test()
            .get(server)
            .expect("seeded backend is registered");
        let shared = backend
            .pooled_transport_for_test(&crate::backend::PoolKey::Shared)
            .expect("the shared slot is seeded first");
        backend
            .set_pooled_transport_for_test(&crate::backend::PoolKey::PerUser { binding }, shared);
    }
}

#[cfg(test)]
#[path = "captured_backend_tests.rs"]
mod captured_backend_tests;
