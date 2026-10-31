// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct `POST /mcp/{name}` bypass's own idempotency guard
//! (MIK-7272.SUB.4).
//!
//! Its own file because `meta_mcp/mod.rs` is a shared surface: this is the one
//! lane that owns it.

use serde_json::Value;

use super::MetaMcp;
use super::support;
use crate::Result;

impl MetaMcp {
    /// Admit, replay, or refuse a direct-route call against the client's
    /// idempotency key.
    ///
    /// A broken stream forces the client to re-issue with a NEW request id, so
    /// a side-effecting call on this route is protected by the client's key or
    /// not at all. `invoke_tool_traced` is not reachable from
    /// `backend_handlers`, and `idempotency_cache` stays `pub(super)` so no
    /// future caller can reach past the namespacing `idempotency_key_for`
    /// performs — the bypass re-enforces the guard locally instead, exactly the
    /// shape `enforce_oauth_isolation` already uses there (ADR-008 INV-2/INV-3).
    ///
    /// Identity binds through the same principal function route 1 uses, and
    /// binds it HERE rather than at the caller so that ordering keeps one
    /// owner. It never binds on the API key name, which is operator-chosen and
    /// may be shared by two keys; an API-key caller binds on the digest of its
    /// validated secret (`credential_principal`) instead.
    ///
    /// `None` when no cache is configured, the client sent no key, or an
    /// authenticated caller resolves to no principal: the call then proceeds
    /// unguarded rather than touching the shared key space.
    ///
    /// # Errors
    ///
    /// Propagates the guard's refusals: a duplicate still in flight, a key
    /// already in use for a different request, or a cache at capacity.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn direct_route_idempotency(
        &self,
        client_key: Option<&str>,
        server: &str,
        cache_binding: Option<&str>,
        verified_identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
        grant_subject: Option<&crate::identity_grants::GrantSubject>,
        credential_principal: Option<&str>,
        authentication: super::Authentication,
        params: Option<&Value>,
    ) -> Result<Option<crate::idempotency::GuardOutcome>> {
        #[cfg(test)]
        RESERVATION_ATTEMPTS.with(|count| count.set(count.get() + 1));
        let Some(cache) = self.idempotency_cache.as_ref() else {
            return Ok(None);
        };
        let principal = support::caller_cache_principal(
            cache_binding,
            verified_identity,
            grant_subject,
            credential_principal,
            authentication,
        );
        // No projection and no chain step on this route: it forwards one call.
        let Some(key) =
            support::idempotency_key_for(client_key, "", &principal, Some(cache), "direct")
        else {
            return Ok(None);
        };
        // What the key is a key *for*, the same fingerprint shape route 1
        // derives at `meta_mcp/invoke.rs:1362`. A client key is an opaque string
        // it chose, so nothing about it says which request it was minted for:
        // without this, a key reused for a different tool replays the first
        // call's result as though it were this one's. The retry pair is part of
        // that binding (MRTR.10) for the same reason it is there.
        let tool = params
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let arguments = params
            .and_then(|p| p.get("arguments"))
            .cloned()
            .unwrap_or(Value::Null);
        let base = crate::idempotency::derive_key(&format!("{server}:{tool}"), &arguments);
        let retry = crate::protocol::mrtr::RetryFields::from_params(params);
        let claim = retry
            .is_retry()
            .then(|| crate::idempotency::claim_of(retry.request_state.as_deref()))
            .flatten();
        let fingerprint = format!("{base}{}", retry.key_discriminator());
        crate::idempotency::enforce_claimed(cache, &key, &fingerprint, claim.as_deref()).map(Some)
    }

    /// Stage 7b on the direct route (MIK-8154.LEASE.1, gap 11): the shared
    /// execution lease `/mcp`, stdio and tasks take, so one key covers one
    /// backend operation whichever route sends it.
    ///
    /// The owner is spelled as `admit_meta_sync` spells it (MIK-8193): the
    /// routed task owner, else the caller's credential or proven subject. The
    /// operation is the one `gateway_invoke` of the same target admits under,
    /// built from the same parse of `arguments`, so the two routes collide in
    /// the store instead of each admitting the operation once. The
    /// representation names the direct route: a stored result replays only to
    /// a request that would have produced it, and a cross-route reuse of the
    /// key is the store's mismatch refusal.
    ///
    /// # Errors
    ///
    /// The store's refusals (in flight, mismatch, sealed, unavailable) and a
    /// malformed retry, each before anything dispatched.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn direct_route_admission(
        &self,
        owner: super::AdmissionOwner<'_>,
        (credential_principal, grant_subject, caller_key): (
            Option<&str>,
            Option<&crate::identity_grants::GrantSubject>,
            Option<&str>,
        ),
        is_modern: bool,
        verified_identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
        retry: &crate::protocol::mrtr::RetryFields,
        (server, tool, params): (&str, &str, Option<&Value>),
        id: &crate::protocol::RequestId,
    ) -> Result<super::admission::SyncAdmission> {
        let owner_principal =
            support::execution_principal(owner, credential_principal, grant_subject, caller_key);
        let empty = Value::Object(serde_json::Map::new());
        let params = params.unwrap_or(&empty);
        // The direct route forwards `arguments` as sent and never refused a
        // malformed one; it keeps that, keyed by the value as sent.
        let mut arguments = crate::gateway::meta_mcp_helpers::parse_tool_arguments_cow(params)
            .unwrap_or_else(|_| {
                std::borrow::Cow::Borrowed(params.get("arguments").unwrap_or(&empty))
            });
        // The operation is spelled as `gateway_invoke` spells it, so the two
        // routes collide. That spelling drops `_claim` and `_full` (gateway
        // controls there) and parses string arguments; here those are the
        // backend's own bytes. So the representation binds the arguments as
        // sent: two direct requests that differ only there never replay each
        // other.
        super::admission::execution_arguments_cow(&mut arguments);
        let sent = params.get("arguments").unwrap_or(&Value::Null);
        self.admit_sync(
            is_modern,
            verified_identity,
            owner_principal,
            retry,
            server,
            tool,
            &arguments,
            || {
                serde_json::json!({"route": "direct", "server": server, "tool": tool,
                    "arguments": crate::hashing::canonical_json_sha256(sent)})
            },
            id,
        )
    }

    /// #1962: arm a direct-route reservation for its backend dispatch, so a
    /// caller that disconnects mid-call does not free the key.
    pub(crate) fn arm_direct_dispatch(
        reservation: Option<&mut crate::idempotency::IdempotencyReservation>,
    ) {
        super::invoke::arm_for_dispatch(reservation);
    }

    /// The audit subject a credential for `backend` is resolved under: the
    /// same string the credential resolver records, for a route that writes its
    /// own record (the direct route, #2190). Taken from the instance the route
    /// captured, so a reload that registers a replacement under the same name
    /// cannot change whose subject a credential is audited under (MIK-7804).
    pub(crate) fn audit_subject_for(
        &self,
        backend: &crate::backend::Backend,
        caller: crate::identity_propagation::CallerProof<'_>,
    ) -> String {
        self.principal_for(backend, caller).map_or_else(
            || crate::identity_propagation::audit_subject(None),
            crate::personal_accounts::identity::Principal::stable_actor_id,
        )
    }

    /// Whether the credential resolver has a principal to mint for `backend`
    /// under (#2310). Without one it mints nothing: a non-required backend
    /// keeps its static credential (IDP.5).
    pub(crate) fn has_principal_for(
        &self,
        backend: &crate::backend::Backend,
        caller: crate::identity_propagation::CallerProof<'_>,
    ) -> bool {
        self.principal_for(backend, caller).is_some()
    }

    /// Who the resolver would resolve `backend`'s credential for, if anyone.
    ///
    /// THE ONE LOOKUP both the resolver and every short-circuit ahead of it
    /// use, so a gate can never pick a different descriptor than the mint. It
    /// reads the instance in hand, never the registry by name: a reload can
    /// register a replacement under the same name, and the descriptor of one
    /// backend must not decide for a request sent through another (MIK-7804).
    pub(super) fn principal_for<'a>(
        &self,
        backend: &crate::backend::Backend,
        caller: crate::identity_propagation::CallerProof<'a>,
    ) -> Option<crate::personal_accounts::identity::Principal<'a>> {
        self.caller_principal(backend.account_descriptor_id(), caller)
    }

    /// Record that `caller`'s own catalogue is the one in per-user slot
    /// `binding` on `backend`, after a fill that read it (design R3.5). A
    /// Passthrough backend is never indexed: its caller's credential reaches
    /// the gateway only on the direct route, so no name-only reader could
    /// select its slot (design R4.2).
    ///
    /// A publish that would change the index is first judged by the publish
    /// gate against a fresh custody read, so a binding the grant has moved
    /// past is never indexed; one the index already holds reads nothing.
    pub(crate) async fn remember_caller_slot(
        &self,
        backend: &crate::backend::Backend,
        caller: crate::identity_propagation::CallerProof<'_>,
        binding: Option<&str>,
    ) {
        let Some(binding) = binding else {
            return;
        };
        if is_passthrough(backend) {
            return;
        }
        let Some(principal) = self.principal_for(backend, caller) else {
            return;
        };
        let unchanged = backend
            .caller_slot_binding(&principal.stable_actor_id())
            .as_deref()
            == Some(binding);
        if !unchanged
            && let Some(gate) = self.gate_inputs(backend, caller)
            && gate.judge(backend, binding).await != super::publish_gate::Publish::Allow
        {
            return;
        }
        self.index_caller_slot(backend, caller, binding);
    }

    /// Index `binding` as `caller`'s slot with no currency check: the part of
    /// [`Self::remember_caller_slot`] after its gate, and what a test's seed
    /// uses.
    fn index_caller_slot(
        &self,
        backend: &crate::backend::Backend,
        caller: crate::identity_propagation::CallerProof<'_>,
        binding: &str,
    ) {
        if is_passthrough(backend) {
            return;
        }
        if let Some(principal) = self.principal_for(backend, caller) {
            backend.record_caller_slot(&principal.stable_actor_id(), binding);
        }
    }

    /// Seed `caller`'s own slot on `server` as a real fill leaves it: the
    /// catalogue stored in per-user slot `binding`, and the caller-slot index
    /// pointing at it (MIK-8356). A row whose premise is "this caller's
    /// catalogue holds X" uses this, never a bare store the index cannot see.
    #[cfg(test)]
    pub(crate) fn seed_caller_catalogue_for_test(
        &self,
        server: &str,
        caller: crate::identity_propagation::CallerProof<'_>,
        binding: &str,
        tools: Vec<crate::protocol::Tool>,
    ) {
        let backend = self.backends.for_test().get(server).expect("the backend");
        backend.store_per_user_tools_for_test(binding, tools);
        self.index_caller_slot(&backend, caller, binding);
        assert!(
            backend
                .indexed_bindings_for_test()
                .iter()
                .any(|b| b == binding),
            "seed: the index does not point {server}'s caller at {binding}"
        );
    }

    /// The binding of the slot holding `caller`'s own catalogue on `backend`,
    /// if warm (MIK-8356 design R3.5; the read API agreed with MIK-8350).
    /// Synchronous and side-effect free: no mint, no fill, no slot creation.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "MIK-8356: read by its rows until readers adopt it"
        )
    )]
    pub(crate) fn caller_slot_binding_for(
        &self,
        backend: &crate::backend::Backend,
        caller: crate::identity_propagation::CallerProof<'_>,
    ) -> Option<String> {
        let principal = self.principal_for(backend, caller)?;
        backend.caller_slot_binding(&principal.stable_actor_id())
    }
}

// T9 (test plan "Shared fixture"): counts every reservation attempt into
// `direct_route_idempotency`, whatever the outcome, so a fixture can assert
// on it without `backend_handlers.rs` growing past its size baseline.
#[cfg(test)]
thread_local! {
    static RESERVATION_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
impl MetaMcp {
    /// Reservation attempts on this thread since the last reset (T9).
    pub(crate) fn reservation_attempts() -> usize {
        RESERVATION_ATTEMPTS.with(std::cell::Cell::get)
    }

    /// Reset the T9 counter for this thread.
    pub(crate) fn reset_reservation_attempts() {
        RESERVATION_ATTEMPTS.with(|count| count.set(0));
    }

    /// Test-only: every completed value the idempotency cache retains
    /// (MIK-8176 cache guards). Read-only; compiled only under
    /// `cfg(test)`, so no production caller reaches the cache through it.
    pub(crate) fn idempotency_completed_for_test(&self) -> Vec<Value> {
        self.idempotency_cache
            .as_ref()
            .map(|cache| cache.completed_values_for_test())
            .unwrap_or_default()
    }

    /// Test-only entry to `invoke_tool` for router cells that must drive a
    /// meta-layer exchange (a bridged input round) on the same `MetaMcp` an
    /// HTTP fixture serves (MIK-7597 T3c). Compiled only under `cfg(test)`.
    pub(crate) async fn invoke_tool_for_test(
        &self,
        args: &Value,
        session_id: Option<&str>,
        caller: &super::MetaMcpCallerContext<'_>,
    ) -> Result<Value> {
        self.invoke_tool(args, session_id, caller).await
    }
}

/// Whether `backend` is a Passthrough one, which is never indexed.
fn is_passthrough(backend: &crate::backend::Backend) -> bool {
    backend.identity_propagation_config().is_some_and(|idp| {
        matches!(
            idp.strategy,
            crate::identity_propagation::PropagationStrategyKind::Passthrough
        )
    })
}
