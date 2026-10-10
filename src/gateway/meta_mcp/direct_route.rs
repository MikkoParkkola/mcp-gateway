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
        let discriminator =
            crate::protocol::mrtr::RetryFields::from_params(params).key_discriminator();
        crate::idempotency::enforce(cache, &key, &format!("{base}{discriminator}")).map(Some)
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
