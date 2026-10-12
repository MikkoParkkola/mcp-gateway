// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! STORED.2 site 1 (MIK-8392): a retained single-call result is served only
//! when nothing per-caller needs proving; otherwise it is deferred to the
//! live dispatch, whose resolution proves the account before the lift.

use serde_json::Value;

use crate::protocol::JsonRpcResponse;

use super::super::MetaMcp;
use super::{ReplayAudit, ReplayTarget};

impl MetaMcp {
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
        super::super::visible::record_deferred_replay(
            key,
            super::super::visible::DeferredReplay {
                response,
                audit,
                tool_name: tool_name.to_owned(),
                arguments: arguments.clone(),
            },
        );
        None
    }
}
