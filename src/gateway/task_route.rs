// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `tasks/*` bodies both transports serve (MIK-7272.OWNER.2, design D6
//! rev 5 items 3–4, `docs/design/2026-09-30-sub4-stdio-owner.md`).
//!
//! HTTP and stdio differ only in who owns a task and in how a read is
//! re-authorized before delivery; both are handed in. Everything an owner
//! lookup, a round or a cancel says is decided here, once.

use std::future::Future;
use std::sync::Arc;

use serde_json::{Value, json};

use crate::gateway::task_service::{
    CommittedTask, InputOutcome, OwnedCallerContext, ServiceError, TaskExecutor, TaskService,
};
use crate::protocol::tasks::Task;
use crate::protocol::{JsonRpcResponse, RequestId};

/// Who asks. HTTP owner text comes from the route (`oidc:…`, `credential:…`
/// or the auth-disabled constant) and can never name the stdio operator: a
/// NUL-prefixed text is refused here, at the one place HTTP owner text enters
/// the task surface (invariant I-OWN).
pub(crate) enum TaskOwnerText {
    Http(String),
    LocalOperator,
}

impl TaskOwnerText {
    /// The principal the store keys on, or `None` for a refused HTTP text,
    /// which every lookup answers as an absent task.
    pub(crate) fn text(&self) -> Option<&str> {
        match self {
            Self::Http(text) => Some(text.as_str())
                .filter(|text| !text.starts_with(crate::gateway::meta_mcp::LOCAL_OPERATOR_PREFIX)),
            Self::LocalOperator => Some(crate::gateway::meta_mcp::LOCAL_OPERATOR_PRINCIPAL),
        }
    }
}

/// The store and executor one route serves from.
pub(crate) struct TaskRoute<'a> {
    pub(crate) service: &'a TaskService,
    pub(crate) executor: &'a Arc<TaskExecutor>,
    pub(crate) owner: &'a TaskOwnerText,
}

/// Tools that may be handed to the worker after the confirmation gate.
pub(crate) fn is_task_dispatchable(
    meta_mcp: &crate::gateway::meta_mcp::MetaMcp,
    tool_name: &str,
) -> bool {
    matches!(
        tool_name,
        "gateway_invoke" | "gateway_execute" | "gateway_run_playbook"
    ) || meta_mcp.surfaced_tool_server(tool_name).is_some()
}

/// The `taskId` a task method names, if it names one.
pub(crate) fn task_id_param(params: Option<&Value>) -> Option<&str> {
    params?.get("taskId")?.as_str()
}

/// The one answer a caller gets for a task that is absent, or that belongs to
/// another principal.
///
/// Deliberately names no task (the JSON-RPC id is still echoed): a message
/// naming the task would let a caller tell "not yours" from "never existed",
/// which is the whole disclosure the ownership rule exists to prevent.
pub(crate) fn missing_task_error(id: RequestId) -> JsonRpcResponse {
    JsonRpcResponse::error(Some(id), -32602, "no such task")
}

/// A stored task delivered to this request: its holds adopted into the
/// request's scope (MIK-8176 D4), then `Task::wire()` plus the envelope
/// discriminator the arm supplies. The task comes back for the arm's own
/// decisions; refusing after this only drops the request's clones, and the
/// row keeps the slot.
pub(crate) fn task_envelope(
    held: crate::gateway::meta_mcp::sealed_hold::Held<CommittedTask>,
    result_type: &str,
) -> (CommittedTask, Value) {
    let current = held.deliver(crate::gateway::meta_mcp::sealed_hold::HoldSink::Scope);
    let mut value = serde_json::to_value(current.task.wire()).unwrap_or(Value::Null);
    if let Some(object) = value.as_object_mut() {
        object.insert("resultType".into(), json!(result_type));
    }
    (current, value)
}

fn ack_complete() -> Value {
    json!({ "resultType": "complete" })
}

fn store_unavailable(id: RequestId) -> JsonRpcResponse {
    JsonRpcResponse::error(Some(id), -32603, "task store unavailable")
}

impl TaskRoute<'_> {
    fn lookup(&self, task_id: &str) -> Result<CommittedTask, ServiceError> {
        let owner = self.owner.text().ok_or(ServiceError::NotFound)?;
        self.service.get(owner, task_id)
    }

    fn lookup_held(
        &self,
        task_id: &str,
    ) -> Result<crate::gateway::meta_mcp::sealed_hold::Held<CommittedTask>, ServiceError> {
        let owner = self.owner.text().ok_or(ServiceError::NotFound)?;
        self.service.get_held(owner, task_id)
    }

    /// `tasks/get`. The owner-scoped lookup comes FIRST, so a foreign or
    /// missing task causes nothing below it. `recover` runs for a working task
    /// (HTTP's bounded upstream read; nothing on stdio). `refuse` is the
    /// transport's delivery check on the ONE snapshot returned, and `screen`
    /// its egress scan of what that snapshot serves (every transport passes
    /// the Meta-MCP's, under the task's recorded targets).
    pub(crate) async fn get<'p, R>(
        &self,
        id: RequestId,
        params: Option<&'p Value>,
        recover: impl FnOnce(&'p str) -> R,
        refuse: impl FnOnce(&CommittedTask) -> Option<JsonRpcResponse>,
        screen: impl FnOnce(&CommittedTask, &mut JsonRpcResponse),
    ) -> JsonRpcResponse
    where
        R: Future<Output = ()>,
    {
        let Some(task_id) = task_id_param(params) else {
            return missing_task_error(id);
        };
        let committed = match self.lookup(task_id) {
            Ok(committed) => committed,
            Err(ServiceError::NotFound) => return missing_task_error(id),
            Err(_) => return store_unavailable(id),
        };
        if committed.task.status() == crate::protocol::tasks::TaskStatus::Working {
            recover(task_id).await;
        }
        match self.lookup_held(task_id) {
            Ok(held) => {
                let (current, envelope) = task_envelope(held, "complete");
                refuse(&current).unwrap_or_else(|| {
                    // MIK-7116.MIN.2 (design §4.9): a stored task row keeps no
                    // reading of its output yet, so serving one counts as unread.
                    // A working row serves no backend output and reads nothing.
                    if current.serves_backend_output() {
                        crate::security::tenant_reads::note_restored(None);
                    }
                    let mut frame = JsonRpcResponse::success(id, envelope);
                    screen(&current, &mut frame);
                    frame
                })
            }
            Err(ServiceError::NotFound) => missing_task_error(id),
            Err(_) => store_unavailable(id),
        }
    }

    /// `tasks/update`. `caller` builds the resume's context from THIS update
    /// request's live identity, never the context that created the task.
    pub(crate) async fn update(
        &self,
        id: RequestId,
        params: Option<&Value>,
        caller: impl FnOnce(&str) -> OwnedCallerContext,
    ) -> JsonRpcResponse {
        let Some(task_id) = task_id_param(params) else {
            return missing_task_error(id);
        };
        let Some(owner) = self.owner.text() else {
            return missing_task_error(id);
        };
        let answers = params.and_then(|params| params.get("inputResponses"));
        if !crate::protocol::mrtr::input_responses_nonempty(answers) {
            return match self.service.update(owner, task_id, 0, json!({})).await {
                Ok(_) => JsonRpcResponse::success(id, ack_complete()),
                Err(ServiceError::NotFound) => missing_task_error(id),
                Err(_) => store_unavailable(id),
            };
        }
        let Some(Value::Object(answers)) = answers.cloned() else {
            return JsonRpcResponse::error(Some(id), -32602, "inputResponses must be an object");
        };
        // Owner-scoped first: a foreign or absent task is answered as absent
        // before anything about a round is said.
        match self.service.get(owner, task_id) {
            Ok(current)
                if current.task.status() == crate::protocol::tasks::TaskStatus::InputRequired => {}
            Ok(current) => return settled_or_no_round(id, &current.task),
            Err(ServiceError::NotFound) => return missing_task_error(id),
            Err(_) => return store_unavailable(id),
        }
        let outcome = self
            .executor
            .provide_input(caller(owner), owner, task_id, answers)
            .await;
        match outcome {
            InputOutcome::Accepted => JsonRpcResponse::success(id, ack_complete()),
            // A cancel may have landed between the look-up above and the write.
            InputOutcome::NotOutstanding => match self.service.get(owner, task_id) {
                Ok(current) => settled_or_no_round(id, &current.task),
                Err(ServiceError::NotFound) => missing_task_error(id),
                Err(_) => store_unavailable(id),
            },
            InputOutcome::TooLarge => JsonRpcResponse::error(
                Some(id),
                -32602,
                "inputResponses exceed the task record size limit",
            ),
            InputOutcome::Busy => JsonRpcResponse::error(Some(id), -32603, "task busy, retry"),
            InputOutcome::PoolFull => {
                JsonRpcResponse::error(Some(id), -32603, "task worker pool is full, retry")
            }
            InputOutcome::Closed(closed) => JsonRpcResponse::error(
                Some(id),
                -32602,
                format!(
                    "inputResponses refused: {}; the round is closed",
                    closed.reason()
                ),
            ),
            InputOutcome::NotFound => missing_task_error(id),
            InputOutcome::Unavailable => store_unavailable(id),
            InputOutcome::AuditUnavailable => {
                crate::gateway::meta_mcp::response_security::error_response_preserving_status(
                    id,
                    &crate::Error::AuditUnavailable,
                )
            }
        }
    }

    /// `tasks/cancel`.
    pub(crate) async fn cancel(&self, id: RequestId, params: Option<&Value>) -> JsonRpcResponse {
        let Some(task_id) = task_id_param(params) else {
            return missing_task_error(id);
        };
        let Some(owner) = self.owner.text() else {
            return missing_task_error(id);
        };
        let committed = match self.service.get(owner, task_id) {
            Ok(committed) => committed,
            Err(ServiceError::NotFound) => return missing_task_error(id),
            Err(_) => return store_unavailable(id),
        };
        match self
            .executor
            .cancel(owner, task_id, committed.revision)
            .await
        {
            Ok(_) => JsonRpcResponse::success(id, ack_complete()),
            Err(ServiceError::NotFound) => missing_task_error(id),
            Err(_) => store_unavailable(id),
        }
    }
}

/// A late answer to a settled task is told how it settled, with the reason it
/// carries (#2429); a live task without a round gets the plain refusal.
fn settled_or_no_round(id: RequestId, task: &Task) -> JsonRpcResponse {
    // Read through accessors, never the wire form: this refusal names the
    // status only, so it must not be able to carry the payload (MIK-8176 A1).
    use crate::protocol::tasks::TaskStatus;
    let status = match task.status() {
        TaskStatus::Completed => "completed",
        TaskStatus::Failed => "failed",
        TaskStatus::Cancelled => "cancelled",
        TaskStatus::Working | TaskStatus::InputRequired => return no_round(id),
    };
    let reason = task
        .status_message()
        .map_or_else(String::new, |message| format!(": {message}"));
    JsonRpcResponse::error(
        Some(id),
        -32602,
        format!("inputResponses refused: the task is {status}{reason}"),
    )
}

fn no_round(id: RequestId) -> JsonRpcResponse {
    JsonRpcResponse::error(
        Some(id),
        -32602,
        "inputResponses are not accepted until an input round is outstanding",
    )
}
