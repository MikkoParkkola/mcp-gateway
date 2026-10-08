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
        if !stored.serves_backend_output() {
            return None;
        }
        let refused = self
            .authorize_stored(stored, attestation, session, caller)
            .err();
        // COLLUDE.1 §13.3: a stored result or pending prompt delivered again
        // renews the reader's receipt; the delivery owner commits it.
        if refused.is_none() {
            self.stage_stored_receipt(caller.relay_caller(session), caller.api_key_name, stored);
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
        // MIK-7826: explicit identity fields, JSON-encoded so no value can
        // forge a separator. A subject's label is display only, so it is not
        // part of the caller; a Debug rendering would carry it.
        let task_and_caller = json!([
            stored.task.id(),
            caller.api_key_name,
            caller
                .grant_subject
                .as_ref()
                .map(|s| [s.authority.as_str(), s.subject.as_str()]),
            caller.agent_id.map(|a| (a.as_str(), a.proof())),
        ])
        .to_string();
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

impl MetaMcp {
    /// Stage the receipt a read of `stored` renews: its result, its pending
    /// input requests, or (MIK-7887) the peer's own error of a failed task. A
    /// multi-target task, an error the gateway wrote or whose author is not
    /// established, and a working or cancelled task stage nothing.
    pub(crate) fn stage_stored_receipt(
        &self,
        who: super::invoke::relay::RelayKey<'_>,
        api_key_name: Option<&str>,
        stored: &CommittedTask,
    ) {
        let [target] = stored.targets.as_slice() else {
            return;
        };
        if !self.relay_active() || !stored.serves_backend_output() {
            return;
        }
        let to = (target.server.as_str(), target.tool.as_str());
        match stored.task.status() {
            TaskStatus::Completed => {
                if let Some(result) = stored.backend_result() {
                    // MIK-7993.STORE.1: the members the gateway wrote into the
                    // stored result are its own text; restored into this
                    // read's record, the receipt (and its rebuild from what
                    // is delivered) leaves exactly those out.
                    super::invoke::gateway_writes::restore(&stored.gateway_writes);
                    self.stage_relay_receipt(who, to, result);
                }
            }
            TaskStatus::InputRequired => {
                if let Some(requests) = stored.task.input_requests() {
                    let prompt = serde_json::Value::Object(requests.clone());
                    let recorded = self.recorded_prompt(to, api_key_name, "tasks/get", &prompt);
                    self.stage_relay_receipt(who, to, &recorded);
                }
            }
            TaskStatus::Failed => {
                // Only an error the gateway established as the peer's is the
                // backend's text; its own errors receipt nothing (MIK-7887.RECEIPT.1).
                if let Some(error) = stored.backend_error()
                    && let Ok(error) = serde_json::to_value(error)
                {
                    // Classified like a pending prompt, so a sensitive error
                    // is recorded as sensitive without a `sources` rule.
                    let recorded = self.recorded_prompt(to, api_key_name, "tasks/get", &error);
                    self.stage_relay_receipt(who, to, &recorded);
                }
            }
            _ => {}
        }
    }
}

impl MetaMcp {
    /// MIK-7887.RECEIPT.1: a followed task's failure at settlement. A peer's
    /// own error replaces the working stub with its receipt, classified like a
    /// pending prompt as a read classifies it; any other error is the
    /// gateway's and drops the stub, so nothing it wrote is receipted.
    pub(crate) fn stage_followed_error(
        &self,
        who: super::invoke::relay::RelayKey<'_>,
        target: (&str, &str),
        error: &crate::protocol::JsonRpcError,
        author: crate::gateway::task_service::ErrorAuthor,
    ) {
        if !self.relay_active() {
            return;
        }
        if author == crate::gateway::task_service::ErrorAuthor::Peer
            && let Ok(error) = serde_json::to_value(error)
        {
            let recorded = self.recorded_prompt(target, None, "tasks/settle", &error);
            self.stage_upstream_result(who, target, &recorded);
        } else {
            super::invoke::relay::discard_staged();
        }
    }
}
