// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stored task result is re-authorized before it is delivered (#2450).
//!
//! `tasks/get` and a repeated task-augmented call both hand back a result the
//! caller already owns. Neither may do so once current policy blocks the calls
//! that produced it, the way a synchronous replay is refused (#2445).

use serde_json::json;

use super::visible::{self, AccountOutcome};
use super::{MetaMcp, MetaMcpCallerContext, error_response_preserving_status};
use crate::gateway::task_service::CommittedTask;
use crate::protocol::tasks::TaskStatus;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::{Error, Result};

impl MetaMcp {
    /// The refusal for delivering `stored` on a task read (tasks/get, a
    /// notification frame), or `None` when it may go out.
    ///
    /// A terminal task's output and a parked task's pending input requests
    /// (#2466) are both backend output, so both are checked. A working or
    /// cancelled task delivers none. `attestation` is the token this request
    /// presents. The request's account outcomes must already be filled by
    /// [`Self::prepare_stored_read`] (MIK-8392); a missing one answers
    /// retryable, never the output.
    pub(crate) fn refuse_stored_delivery(
        &self,
        id: &RequestId,
        stored: &CommittedTask,
        attestation: Option<&str>,
        session: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> Option<JsonRpcResponse> {
        self.refuse_stored(id, stored, (attestation, session), caller, StoredRead::Read)
    }

    /// [`Self::refuse_stored_delivery`] for a repeated task-augmented call
    /// (`BeginOutcome::Existing`). Its catalogue is judged here; its accounts
    /// are not: a call has a live path, so an account that is not live is
    /// answered by that call's own resolution after this returns `None`
    /// (MIK-8392 site-5 split, lead ruling 2026-10-12).
    pub(crate) fn refuse_stored_repeat(
        &self,
        id: &RequestId,
        stored: &CommittedTask,
        attestation: Option<&str>,
        session: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> Option<JsonRpcResponse> {
        self.refuse_stored(
            id,
            stored,
            (attestation, session),
            caller,
            StoredRead::RepeatedCall,
        )
    }

    /// Fill this request's account outcomes for `stored`'s targets, the
    /// async half of a stored read (MIK-8392): every read entry awaits this
    /// inside the request's memo, then judges synchronously.
    pub(crate) async fn prepare_stored_read(
        &self,
        stored: &CommittedTask,
        caller: crate::identity_propagation::CallerProof<'_>,
    ) {
        if !stored.serves_backend_output() {
            return;
        }
        let targets: Vec<(&str, &str)> = stored
            .targets
            .iter()
            .map(|target| (target.server.as_str(), target.tool.as_str()))
            .collect();
        self.fill_account_outcomes(&targets, caller).await;
        for &(server, tool) in &targets {
            self.settle_caller_view(server, tool, caller).await;
        }
    }

    /// The per-user half of a stored read (MIK-8392 B' and touch-on-read):
    /// a caller's live slot is touched so reading it keeps it from idle
    /// eviction; a cold one is re-established by the one reader that claims
    /// it, and only while its account reads live. Every other reader answers
    /// retryable until the lease ends.
    async fn settle_caller_view(
        &self,
        server: &str,
        tool: &str,
        caller: crate::identity_propagation::CallerProof<'_>,
    ) {
        let Some(backend) = self.backends.get(server) else {
            return;
        };
        if !backend.keeps_per_user_catalogues() {
            return;
        }
        let Some(principal) = self.principal_for(&backend, caller) else {
            return;
        };
        let id = principal.stable_actor_id();
        if let Some(binding) = backend.caller_slot_binding(&id) {
            backend.touch_caller_slot(&binding);
            return;
        }
        let account_live = self.target_account(server, tool).is_none_or(|account| {
            matches!(
                visible::account_outcome(server, &account),
                Some(AccountOutcome::Live | AccountOutcome::Unjudged)
            )
        });
        if account_live
            && backend.claim_cold_view(&id, COLD_RETRY_BACKOFF) == crate::backend::ColdClaim::Won
        {
            self.warm_cold_view((server, tool), &backend, caller).await;
        }
    }

    fn refuse_stored(
        &self,
        id: &RequestId,
        stored: &CommittedTask,
        (attestation, session): (Option<&str>, Option<&str>),
        caller: &MetaMcpCallerContext<'_>,
        read: StoredRead,
    ) -> Option<JsonRpcResponse> {
        if !stored.serves_backend_output() {
            return None;
        }
        // Visibility first, as on the live path: a withheld target answers
        // as absent even where policy would also refuse (MIK-8392 T12).
        let refused = match self.judge_stored_targets(stored, session, caller, read) {
            Err(StoredWithheld::Retry) => return Some(retry_later(id)),
            Err(StoredWithheld::Refused(error)) => Some(error),
            Ok(()) => self
                .authorize_stored(stored, attestation, session, caller)
                .err(),
        };
        // COLLUDE.1 §13.3: a stored result or pending prompt delivered again
        // renews the reader's receipt; the delivery owner commits it.
        if refused.is_none() {
            self.stage_stored_receipt(caller.relay_caller(session), caller.api_key_name, stored);
        }
        refused.map(|error| error_response_preserving_status(id.clone(), &error))
    }

    /// Each recorded target against this caller's current view (MIK-8392):
    /// its account (task reads only) as the pre-pass recorded it, then its
    /// catalogue through the one judgement [`MetaMcp::stored_target_view`],
    /// refused through the one guard [`visible::absent_if_withheld`].
    fn judge_stored_targets(
        &self,
        stored: &CommittedTask,
        session: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
        read: StoredRead,
    ) -> std::result::Result<(), StoredWithheld> {
        let scope = caller.scope();
        for target in &stored.targets {
            let (server, tool) = (target.server.as_str(), target.tool.as_str());
            if read == StoredRead::Read
                && let Some(account) = self.target_account(server, tool)
            {
                match visible::account_outcome(server, &account) {
                    // Unfilled: the pre-pass never ran for it. Fail closed,
                    // and retryable: nothing about the grant was learned.
                    None | Some(AccountOutcome::Unavailable) => {
                        return Err(StoredWithheld::Retry);
                    }
                    Some(AccountOutcome::NoView) => {
                        return Err(StoredWithheld::Refused(visible::absent_name(tool)));
                    }
                    Some(AccountOutcome::Live | AccountOutcome::Unjudged) => {}
                }
            }
            let Some(judged) = self.stored_target_view(server, tool, scope, session) else {
                return Err(StoredWithheld::Retry);
            };
            visible::absent_if_withheld(Some(judged), tool).map_err(StoredWithheld::Refused)?;
        }
        Ok(())
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

/// How long a claimed attempt to re-establish a cold view holds before
/// another reader may try (MIK-8392 B'): the idle reaper's own sweep, so a
/// cold state outlasts eviction by at most one sweep, and an outage costs at
/// most one resolution per caller per backend per minute.
const COLD_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_secs(60);

/// Which stored delivery is judged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StoredRead {
    /// A task read: tasks/get or a notification frame.
    Read,
    /// A repeated task-augmented call: its accounts are judged live.
    RepeatedCall,
}

/// Why a stored delivery does not go out.
enum StoredWithheld {
    /// Its target is withheld from this caller: the absent answer.
    Refused(Error),
    /// This caller's view is not settled yet: retry, never terminal.
    Retry,
}

/// The retryable answer (MIK-8392 s1-d1): -32603 with a `retryable` data
/// member, built here because the shared error converter keeps only listed
/// data keys. It carries no output.
fn retry_later(id: &RequestId) -> JsonRpcResponse {
    JsonRpcResponse::error_with_data(
        Some(id.clone()),
        -32603,
        "task result temporarily unavailable, retry",
        json!({ "retryable": true }),
    )
}
