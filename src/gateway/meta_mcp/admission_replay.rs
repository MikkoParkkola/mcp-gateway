// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! STORED.2 site 1 (MIK-8392): a retained single-call result is served only
//! when nothing per-caller needs proving; otherwise it is deferred to the
//! live dispatch, whose resolution proves the account before the lift.

use serde_json::Value;

use crate::protocol::JsonRpcResponse;

use super::super::MetaMcp;
use crate::protocol::mrtr::RetryFields;

use super::ReplayAudit;

/// The single-call target a site-1 replay was admitted for (MIK-8392
/// STORED.2): what the route stage judges for liveness and keys the deferral
/// by. Owned: the admission outlives the arguments it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReplayTarget {
    /// The backend server: the target branch's, or a continuation origin's.
    pub(crate) server: String,
    /// The presented tool: the target branch's, or the retry's own name.
    pub(crate) tool: String,
}

impl MetaMcp {
    /// MIK-8392 STORED.2 E8: a non-meta name with no target for this
    /// caller (withheld, policy-refused or missing) is admitted
    /// unprotected, before any idempotency lookup, so no key state is
    /// consulted or revealed (else a revoked caller's keyed repeat leaks
    /// its key and tool through a 409 fingerprint mismatch). The live path
    /// then answers it exactly as it answers the same unkeyed call: a
    /// missing name -32601, a policy refusal the authorizer's own error,
    /// status and record. A name with no target is never dispatched, so
    /// nothing runs unprotected. A continuation retry with an origin keeps
    /// its path: a readable one proves via the origin target, and an
    /// unreadable one is E1's continuation error. Unkeyed calls never
    /// consult key state, a malformed retry is refused as malformed, and a
    /// call with no principal keeps admission's own -32003.
    pub(super) fn hidden_name_unprotected(
        &self,
        tool_name: &str,
        retry: &RetryFields,
        (verified_identity, owner_principal): (
            Option<&crate::key_server::oidc::VerifiedIdentity>,
            Option<&str>,
        ),
    ) -> bool {
        retry.idempotency_key.is_some()
            && !retry.is_malformed()
            && !crate::gateway::meta_mcp_tool_defs::is_governed_meta_tool(tool_name)
            && super::super::invoke::retry_origin_backend(&self.continuation, retry).is_none()
            && (verified_identity.is_some()
                || owner_principal.is_some_and(|principal| !principal.is_empty()))
    }

    /// The origin fallback (MIK-8392 STORED.2 D2): a continuation
    /// retry names the backend tool it continues, which no
    /// operator surfaced, so the plan branch takes the
    /// authenticated origin the envelope names, read without
    /// redeeming it. Only the two tools that redeem in place
    /// never take it, as the retry router skips them too.
    pub(super) fn replay_origin_target(
        &self,
        tool_name: &str,
        retry: &RetryFields,
    ) -> crate::Result<Option<ReplayTarget>> {
        if matches!(tool_name, "gateway_invoke" | "gateway_execute") {
            return Ok(None);
        }
        match super::super::invoke::retry_origin_backend(&self.continuation, retry) {
            None => Ok(None),
            Some(Ok(server)) => Ok(Some(ReplayTarget {
                server,
                tool: tool_name.to_owned(),
            })),
            // E1: an unreadable origin is never served stored; the
            // continuation error is the live path's answer for it.
            Some(Err(error)) => Err(error),
        }
    }

    /// Whether a site-1 retained result for `(server, tool)` defers to the
    /// live dispatch (MIK-8392 STORED.2): every target whose dispatch binds a
    /// per-caller credential (a managed account, or a per-caller mint with no
    /// account, E7) defers, and the lift serves it once resolution proves the
    /// account live. Only a backend that mints nothing per caller is exempt
    /// (U1/U2). There is no admission shortcut for an account already known
    /// live: the lift reuses the route-stage resolution, so serving here would
    /// save nothing measurable (lead ruling on M14).
    pub(crate) fn stored_replay_defers(&self, server: &str, tool: &str) -> bool {
        self.mints_per_caller(server, tool)
    }

    /// Whether dispatching `(server, tool)` mints a per-caller credential
    /// (MIK-8392 STORED.2 E7): the dispatch's own mint conditions, an
    /// identity-propagation backend (with or without an `account:`) or a
    /// capability account. A target this refuses needs no liveness proof.
    pub(crate) fn mints_per_caller(&self, server: &str, tool: &str) -> bool {
        self.target_account(server, tool).is_some()
            || self
                .backends
                .get(server)
                .is_some_and(|backend| backend.identity_propagation_config().is_some())
    }

    /// STORED.2 site 1: serve `response` when its account is proven live,
    /// else record it as deferred and answer `None`, in which case the
    /// caller proceeds as Unprotected, with no lease. A replay with no
    /// target (a plan) is served as today, as is an unkeyed one, which the
    /// lift could never meet.
    pub(crate) fn defer_or_serve_replay(
        &self,
        tool_name: &str,
        arguments: &Value,
        caller: &super::super::MetaMcpCallerContext<'_>,
        target: Option<ReplayTarget>,
        response: JsonRpcResponse,
        audit: Option<ReplayAudit>,
    ) -> Option<(JsonRpcResponse, Option<ReplayAudit>)> {
        // A replay with no target (a plan) is served as today (D1): there
        // is no account to prove live, and the lift could never meet it.
        // `?` would answer `None` here, which the caller reads as
        // "deferred", re-running the plan live instead of serving it (S6).
        let Some(target) = target else {
            return Some((response, audit));
        };
        // Unkeyed likewise: admission never replays one, so the lift could
        // never meet it either.
        let Some(key) =
            super::super::visible::deferred_replay_key(&target.server, &target.tool, caller.retry)
        else {
            return Some((response, audit));
        };
        if !self.stored_replay_defers(&target.server, &target.tool) {
            return Some((response, audit));
        }
        let id = response.id.clone();
        let recorded = super::super::visible::record_deferred_replay(
            key,
            super::super::visible::DeferredReplay {
                response,
                audit,
                tool_name: tool_name.to_owned(),
                arguments: arguments.clone(),
            },
        );
        // Fail closed: with no request memo nothing was deferred, and
        // proceeding Unprotected would run a completed call again. Every
        // caller runs inside a memo, so this is a guard, not a path.
        if !recorded {
            return Some((
                JsonRpcResponse::error(id, -32603, "stored replay could not be deferred"),
                None,
            ));
        }
        None
    }
}

#[cfg(test)]
#[path = "admission_replay_tests.rs"]
mod tests;
