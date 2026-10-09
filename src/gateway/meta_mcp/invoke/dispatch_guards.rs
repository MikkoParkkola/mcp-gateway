// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! S1-S4 stage methods (design doc `2026-09-27-direct-route-guards.md` §2.1):
//! one control implementation per stage, in `MetaMcp`, at the lifecycle stage
//! each already runs today. Meta dispatch and the per-backend route both call
//! these; nothing else implements the controls (MIK-7597).

use serde_json::Value;

use super::BudgetOutcome;
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::JsonRpcResponse;
use crate::{Error, Result};

/// The direct-route shape of a dispatch, carrying what each stage needs to
/// identify the call without reaching back into the HTTP request (design doc
/// §2.1: `server` is the `{name}` path segment, `tool` is `params.name`).
pub(crate) struct BackendCall<'a> {
    pub server: &'a str,
    pub tool: &'a str,
    pub session_id: Option<&'a str>,
    pub api_key_name: Option<&'a str>,
    pub trace_id: &'a str,
    /// The router's caller key, for a session-less call's own spend record
    /// (MIK-7653). `None` where no spend is recorded, or the caller is keyless.
    pub caller_key: Option<&'a str>,
}

/// What admitting one backend call leaves behind: the warnings for its result
/// and, with cost governance on, the reservation on its cost (MIK-7763).
///
/// Pass it to `account_dispatch`, which settles the reservation with the
/// spend, then drop it. Dropping an unsettled one, on any path, gives the
/// reservation back, so a refused, failed or cancelled call holds nothing.
#[derive(Default)]
#[must_use = "dropping the admission gives the call's reserved budget back"]
pub(crate) struct Admission {
    /// Budget warnings to attach to the result.
    pub(crate) warnings: Vec<String>,
    /// The reservation: settled with the spend, or released on drop.
    #[cfg(feature = "cost-governance")]
    hold: Option<std::sync::Arc<crate::cost_accounting::enforcer::SpendHold>>,
}

#[cfg(feature = "cost-governance")]
impl Admission {
    /// An admitted call: its warnings and the reservation its check made.
    pub(crate) fn new(
        warnings: Vec<String>,
        hold: Option<std::sync::Arc<crate::cost_accounting::enforcer::SpendHold>>,
    ) -> Self {
        Self { warnings, hold }
    }

    /// The reservation a settle consumes, if the check made one.
    fn hold(&self) -> Option<&crate::cost_accounting::enforcer::SpendHold> {
        self.hold.as_deref()
    }
}

/// The direct-route classification of a completed dispatch, feeding S3
/// accounting and S4 payload gating (design doc §2.1a). `spend` marks
/// whether the call is eligible for spend recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectOutcome {
    Success { spend: bool },
    Failure { spend: bool },
    IgnoredRateLimit { spend: bool },
}

impl DirectOutcome {
    /// Classify a meta dispatch result: spend on any answered call, error
    /// budget class by [`BudgetOutcome`].
    pub(crate) fn of(result: &Result<Value>) -> Self {
        Self::from_class(BudgetOutcome::of(result), result.is_ok())
    }

    /// The per-backend adapter (design doc §2.1a): a JSON-RPC `error` is a
    /// failed dispatch, a `result` an answered one, classified as meta does.
    pub(crate) fn from_response(response: &Result<JsonRpcResponse>) -> Self {
        match response {
            Ok(r) => match &r.error {
                Some(e) => Self::from_class(
                    BudgetOutcome::of_error(&Error::json_rpc(e.code, e.message.clone())),
                    false,
                ),
                None => Self::from_class(
                    BudgetOutcome::of_value(r.result.as_ref().unwrap_or(&Value::Null)),
                    true,
                ),
            },
            Err(e) => Self::from_class(BudgetOutcome::of_error(e), false),
        }
    }

    fn from_class(class: BudgetOutcome, spend: bool) -> Self {
        match class {
            BudgetOutcome::Success => Self::Success { spend },
            BudgetOutcome::Failure => Self::Failure { spend },
            BudgetOutcome::IgnoredRateLimit => Self::IgnoredRateLimit { spend },
        }
    }

    fn class_and_spend(self) -> (BudgetOutcome, bool) {
        match self {
            Self::Success { spend } => (BudgetOutcome::Success, spend),
            Self::Failure { spend } => (BudgetOutcome::Failure, spend),
            Self::IgnoredRateLimit { spend } => (BudgetOutcome::IgnoredRateLimit, spend),
        }
    }
}

/// The stored body of a firewall refusal, marked with
/// [`crate::idempotency::FIREWALL_REFUSAL_MARKER`]. Built from the variant so
/// the replay cannot drift from the live refusal; both routes settle with it.
pub(crate) fn firewall_refusal_body() -> Value {
    let refused = Error::ResponseFirewallRefused;
    serde_json::json!({
        "code": refused.to_rpc_code(),
        "message": refused.to_string(),
        crate::idempotency::FIREWALL_REFUSAL_MARKER: true,
    })
}

/// True when a stored error is a marked firewall refusal.
pub(crate) fn is_firewall_refusal(error: &Value) -> bool {
    error
        .get(crate::idempotency::FIREWALL_REFUSAL_MARKER)
        .and_then(Value::as_bool)
        == Some(true)
}

/// The six controls one implementation each replaces (design doc §2.1 table).
#[cfg(test)]
pub(crate) const DISPATCH_CONTROLS: &[&str] = &[
    "kill_switch",
    "capability_disable",
    "session_profile",
    "cost_budget",
    "error_budget",
    "response_gates",
];

impl MetaMcp {
    /// S1 policy: session profile, kill switch, capability disable. Runs
    /// before idempotency, cache and nonce on both routes.
    pub(crate) fn admit_target(&self, call: &BackendCall<'_>) -> Result<()> {
        let (server, tool) = (call.server, call.tool);
        self.active_profile(call.session_id)
            .check(server, tool)
            .map_err(Error::Protocol)?;
        if self.kill_switch.is_killed(server) {
            return Err(Error::json_rpc(
                -32000,
                format!("Server '{server}' is currently disabled by operator kill switch"),
            ));
        }
        let cooldown = self.capability_budget_config.read().cooldown;
        if self
            .kill_switch
            .is_capability_disabled_with_cooldown(server, tool, cooldown)
        {
            return Err(Error::json_rpc(
                -32000,
                format!(
                    "Capability '{tool}' on server '{server}' is temporarily disabled due to \
                     a high error rate. It will auto-recover after the cooldown period. \
                     Use gateway_list_disabled_capabilities to see all disabled capabilities."
                ),
            ));
        }
        Ok(())
    }

    /// S2 spend: budget admission immediately before an actual dispatch.
    /// Returns the warnings to attach to the result.
    #[cfg_attr(
        not(feature = "cost-governance"),
        allow(clippy::unused_self, clippy::unnecessary_wraps)
    )]
    pub(crate) fn admit_spend_for(&self, call: &BackendCall<'_>) -> Result<Admission> {
        #[cfg(feature = "cost-governance")]
        return self.admit_spend(call.tool, call.api_key_name);
        #[cfg(not(feature = "cost-governance"))]
        {
            let _ = call;
            Ok(Admission::default())
        }
    }

    /// S3 accounting at dispatch completion: error budget, then spend on an
    /// answered call.
    ///
    /// The spend is settled against `admission`'s reservation in one step, so
    /// the caller's later drop of it gives nothing back (MIK-7903).
    pub(crate) fn account_dispatch(
        &self,
        call: &BackendCall<'_>,
        outcome: DirectOutcome,
        admission: &Admission,
    ) {
        #[cfg(not(feature = "cost-governance"))]
        let _ = admission;
        let (class, spend) = outcome.class_and_spend();
        self.record_error_budget(call.server, call.tool, class);
        if !spend {
            return;
        }
        // token_count 0: a backend tool call runs no model inference. A call
        // with no session still counts: `record` keeps "" out of any session.
        let session = call.session_id.unwrap_or_default();
        self.cost_tracker.record(
            session,
            call.api_key_name,
            call.server,
            call.tool,
            0,
            crate::cost_accounting::DEFAULT_PRICE_PER_MILLION,
        );
        // Only session-less spend needs this: a session's report covers its own.
        if session.is_empty()
            && let Some(key) = call.caller_key.filter(|key| !key.is_empty())
        {
            self.cost_tracker.record_caller(
                key,
                call.server,
                call.tool,
                0,
                crate::cost_accounting::DEFAULT_PRICE_PER_MILLION,
            );
        }
        #[cfg(feature = "cost-governance")]
        if let Some(ref enforcer) = self.budget_enforcer {
            let cost = enforcer.registry.cost_for(call.tool);
            enforcer.settle(admission.hold(), call.tool, call.api_key_name, cost);
        }
    }

    /// S4 payload: response gates (contract, inspection, context integrity)
    /// on a successful result, and whether a gate replaced it (A3 R2').
    pub(crate) fn gate_payload(
        &self,
        call: &BackendCall<'_>,
        value: Value,
    ) -> Result<(Value, super::super::response_security::GateEffect)> {
        self.apply_response_gates_effect(
            call.server,
            call.tool,
            call.api_key_name,
            call.trace_id,
            value,
        )
    }
}

#[cfg(test)]
#[path = "dispatch_guards_tests.rs"]
mod dispatch_guards_tests;

impl MetaMcp {
    /// A call refused before its backend was reached gives back what it took:
    /// its idempotency key (released, not settled: nothing acted) and the
    /// signing nonce it admitted, so the honest call re-sent under that nonce
    /// is judged on its merits, not refused as a replay (MIK-8150, as the
    /// direct route does since #3451).
    pub(crate) fn give_back_unsent(
        &self,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
        reservation: &mut Option<crate::idempotency::IdempotencyReservation>,
    ) {
        if let Some(reservation) = reservation.as_mut() {
            reservation.release();
        }
        self.release_unasked_nonce(caller);
    }
}
