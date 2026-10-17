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
    /// caller proceeds as Unprotected, with no lease. A plan replay
    /// (`gateway_execute`, `gateway_run_playbook`) has no single target: it
    /// is served only once every account its dispatched steps used is proven
    /// live (MIK-8406), and otherwise answers the first unproven step's live
    /// refusal, with nothing run. An unkeyed replay is served as today, since
    /// the lift could never meet it.
    ///
    /// `dispatched` is the stored record's executed steps; `None` (a record
    /// from before they were kept) judges the call's declared targets, fail
    /// closed.
    pub(crate) async fn defer_or_serve_replay(
        &self,
        tool_name: &str,
        arguments: &Value,
        caller: &super::super::MetaMcpCallerContext<'_>,
        target: Option<ReplayTarget>,
        dispatched: Option<Vec<(String, String)>>,
        (response, audit): (JsonRpcResponse, Option<ReplayAudit>),
    ) -> Option<(JsonRpcResponse, Option<ReplayAudit>)> {
        // A replay with no target is a plan or a read-only meta tool. A plan
        // proves every account its steps used before it is served; the rest
        // are served as today. `?` would answer `None` here, which the caller
        // reads as "deferred", re-running the call live (S6).
        let Some(target) = target else {
            if !matches!(tool_name, "gateway_execute" | "gateway_run_playbook") {
                return Some((response, audit));
            }
            return Some(
                match self
                    .first_unproven_plan_step(tool_name, arguments, caller, dispatched, &response)
                    .await
                {
                    None => (response, audit),
                    Some(answer) => (answer, None),
                },
            );
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

    /// MIK-8406 PLANREPLAY.1/.2: the first step of a stored plan whose
    /// account is not live in this request, answered as its live refusal;
    /// `None` when every account is proven. The steps are the record's
    /// executed ones, or with none recorded the call's declared targets
    /// (fail closed). The plan executor is never entered. A refusal settles
    /// the signed nonce here, since this exit never reaches the per-call
    /// settle: a busy refusal before any effect gives it back, and a walk
    /// that minted keeps it (G1, G2).
    async fn first_unproven_plan_step(
        &self,
        tool_name: &str,
        arguments: &Value,
        caller: &super::super::MetaMcpCallerContext<'_>,
        dispatched: Option<Vec<(String, String)>>,
        response: &JsonRpcResponse,
    ) -> Option<JsonRpcResponse> {
        // Admission builds every replay with the request's id; without one
        // the stored plan is not served (fail closed).
        let Some(id) = response.id.clone() else {
            return Some(JsonRpcResponse::error(
                None,
                -32603,
                "stored plan replay has no request id",
            ));
        };
        let steps: Vec<(String, String)> = dispatched.unwrap_or_else(|| {
            // A plan tool is never a surfaced name, so no session is read.
            let view = super::super::visible::TargetView::Caller(caller.scope(), None);
            crate::gateway::router::backend_tool_targets_for_call(self, tool_name, arguments, view)
                .into_iter()
                .chain(self.playbook_step_targets(tool_name, arguments))
                .map(|target| (target.server, target.tool))
                .collect()
        });
        let walk: Vec<(&str, &str)> = steps
            .iter()
            .map(|(server, tool)| (server.as_str(), tool.as_str()))
            .collect();
        let answer = self.first_unproven(&id, tool_name, &walk, caller).await?;
        if let Some(context) = caller.signing {
            self.settle_nonce_refund(context, super::super::signing::nonce_principal(caller));
        }
        Some(answer)
    }
}

#[cfg(test)]
#[path = "admission_replay_tests.rs"]
mod tests;
