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
    /// Identity binds the same two inputs in the same order route 1 uses, and
    /// binds them HERE rather than at the caller so that ordering keeps one
    /// owner. It never binds on the API key name: that names the KEY, not the
    /// end user, so two people sharing one gateway key would share one entry —
    /// the exact disclosure `SUB.4.DIRECT.2` exists to deny.
    ///
    /// `None` when no cache is configured or the client sent no key: the call
    /// then proceeds unguarded, exactly as before.
    ///
    /// # Errors
    ///
    /// Propagates the guard's refusals: a duplicate still in flight, a key
    /// already in use for a different request, or a cache at capacity.
    pub(crate) fn direct_route_idempotency(
        &self,
        client_key: Option<&str>,
        server: &str,
        cache_binding: Option<&str>,
        verified_identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
        params: Option<&Value>,
    ) -> Result<Option<crate::idempotency::GuardOutcome>> {
        let Some(cache) = self.idempotency_cache.as_ref() else {
            return Ok(None);
        };
        let verified_actor =
            verified_identity.map(crate::key_server::oidc::VerifiedIdentity::stable_actor_id);
        let identity_suffix =
            support::retry_identity_suffix(cache_binding, verified_actor.as_deref());
        // No projection and no chain step on this route: it forwards one call.
        let Some(key) =
            support::idempotency_key_for(client_key, "", &identity_suffix, Some(cache), None)
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
}
