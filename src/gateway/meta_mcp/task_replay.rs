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
        let refused = self
            .authorize_stored(stored, attestation, session, caller)
            .err();
        // COLLUDE.1 §13.3: a stored result or pending prompt delivered again
        // renews the reader's receipt; the delivery owner commits it.
        if refused.is_none()
            && self.relay_active()
            && let [target] = stored.targets.as_slice()
        {
            let who = caller.relay_caller(session);
            let to = (target.server.as_str(), target.tool.as_str());
            match stored.task.status() {
                TaskStatus::Completed => {
                    if let Some(result) = stored.backend_result() {
                        self.stage_relay_receipt(who, to, result);
                    }
                }
                TaskStatus::InputRequired => {
                    if let Some(requests) = stored.task.input_requests() {
                        let prompt = serde_json::Value::Object(requests.clone());
                        let key = caller.api_key_name;
                        let recorded = self.recorded_prompt(to, key, "tasks/get", &prompt);
                        self.stage_relay_receipt(who, to, &recorded);
                    }
                }
                _ => {}
            }
        }
        refused.map(|error| error_response_preserving_status(id.clone(), &error))
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
            // An older row's empty list means it has no upstream descriptor to
            // name its call (`CommittedTask::of`): `task.tool()` is the meta
            // tool, and the backend's current list is no record of what ran, so
            // nothing can prove the caller may read it. Refused, plan or not
            // (MIK-7686, fail closed).
            return if stored.targets_recorded {
                Ok(())
            } else {
                Err(Error::Forbidden {
                    code: -32003,
                    status: 403,
                    message: "stored task result has no recorded provenance".to_owned(),
                })
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
}
