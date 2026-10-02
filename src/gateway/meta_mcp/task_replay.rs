// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stored task result is re-authorized before it is delivered (#2450).
//!
//! `tasks/get` and a repeated task-augmented call both hand back a result the
//! caller already owns. Neither may do so once current policy blocks the calls
//! that produced it, the way a synchronous replay is refused (#2445).

use serde_json::json;

use super::{MetaMcp, MetaMcpCallerContext, error_response_preserving_status};
use crate::gateway::task_service::CommittedTask;
use crate::protocol::tasks::TaskStatus;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::{Error, Result};

impl MetaMcp {
    /// The refusal for delivering `stored`, or `None` when it may go out.
    ///
    /// A terminal task's output and a parked task's pending input requests
    /// (#2466) are both backend output, so both are checked. A working or
    /// cancelled task delivers none. `attestation` is the token this request
    /// presents.
    pub(crate) fn refuse_stored_delivery(
        &self,
        id: &RequestId,
        stored: &CommittedTask,
        attestation: Option<&str>,
        session: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> Option<JsonRpcResponse> {
        if !matches!(
            stored.task.status(),
            TaskStatus::Completed | TaskStatus::Failed | TaskStatus::InputRequired
        ) {
            return None;
        }
        self.authorize_stored(stored, attestation, session, caller)
            .err()
            .map(|error| error_response_preserving_status(id.clone(), &error))
    }

    fn authorize_stored(
        &self,
        stored: &CommittedTask,
        attestation: Option<&str>,
        session: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> Result<()> {
        if stored.output_free {
            // Only the gateway's own bounded error: no backend output to judge.
            return Ok(());
        }
        if stored.targets.is_empty() {
            // A recording gateway's empty list means nothing was dispatched.
            return if stored.targets_recorded {
                Ok(())
            } else {
                self.authorize_legacy_row(stored, attestation, session, caller)
            };
        }
        // MIK-7692: a poll that meets the same decision again is not written
        // again inside the window (`grant_audit` module docs).
        let task_and_caller = format!(
            "{}|{:?}|{:?}|{:?}",
            stored.task.id(),
            caller.api_key_name,
            caller.grant_subject,
            caller.agent_id
        );
        super::grant_audit::in_repeat_scope(&self.grant_repeats, task_and_caller, || {
            // Names only: no current policy reads a target's arguments.
            for target in &stored.targets {
                let args = super::upstream::recovery_policy_args(
                    &target.server,
                    &target.tool,
                    &json!({}),
                    attestation,
                );
                self.check_invocation_policy(&args, session, caller)?;
            }
            Ok(())
        })
    }

    /// A row written before targets were recorded. A plan (by the task's own
    /// tool name, never the backend label) has no provenance and is refused;
    /// anything else faces the backend-level checks, and then, because the row
    /// cannot name the tool it ran (`task.tool()` is the meta tool), is refused
    /// while any tool its backend lists is withheld from this caller, while
    /// that list is absent, empty or not known in full, or while the backend
    /// lists per caller (MIK-7686).
    fn authorize_legacy_row(
        &self,
        stored: &CommittedTask,
        attestation: Option<&str>,
        session: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> Result<()> {
        let refuse = |message: &str| Error::Forbidden {
            code: -32003,
            status: 403,
            message: message.to_owned(),
        };
        if matches!(
            stored.task.tool(),
            "gateway_execute" | "gateway_run_playbook"
        ) {
            return Err(refuse("stored plan result has no recorded provenance"));
        }
        let server = stored.backend.as_str();
        if !caller.authorizer.admits_backend(server) {
            return Err(refuse("stored task result is outside this caller's scope"));
        }
        if !self.active_profile(session).backend_allowed(server) {
            return Err(refuse("stored task result is outside the active profile"));
        }
        let saturated = self
            .backends
            .get(server)
            .is_some_and(|backend| backend.gate_saturated());
        if self.kill_switch.is_killed(server) || saturated {
            return Err(refuse("the backend that produced this result is disabled"));
        }
        let withheld = || {
            refuse(
                "stored task result has no recorded tool, and its backend has a withheld \
                 or unlisted tool",
            )
        };
        let Some(backend) = self.backends.get(server) else {
            return Err(withheld());
        };
        // A backend that forwards caller identity lists per caller, so the
        // shared catalogue cannot speak for this one.
        if backend.identity_propagation_config().is_some() {
            return Err(withheld());
        }
        // The list first, then the blocked set: a block landing between the
        // two is still seen by the second read.
        let Some(tools) = backend.cached_tools_complete().filter(|t| !t.is_empty()) else {
            return Err(withheld());
        };
        if backend.withholds_any_tool() {
            return Err(withheld());
        }
        for tool in tools.iter() {
            let args =
                super::upstream::recovery_policy_args(server, &tool.name, &json!({}), attestation);
            if self
                .check_invocation_policy(&args, session, caller)
                .is_err()
            {
                return Err(withheld());
            }
        }
        Ok(())
    }
}
