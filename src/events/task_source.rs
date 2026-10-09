// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `task.settled` (design §3.4): a task reaching a terminal status is an
//! event for its owner alone. The payload names the task and its status and
//! never the result: the subscriber reads that with `tasks/get`, which
//! applies its own ownership check.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use super::fanout::SourceEvent;
use super::types::{EventDescriptor, RpcError, SourceKind, Visibility};
use super::{EventSource, EventsHub};
use crate::gateway::task_service::TaskService;
use crate::protocol::tasks::TaskStatus;

const NAME: &str = "task.settled";

/// The task-settlement source. Ownership is the task store's: a principal
/// owns a task exactly when `tasks/get` would answer it.
pub(crate) struct TaskSource {
    pub service: Arc<TaskService>,
}

impl TaskSource {
    fn owns(&self, principal: &str, task_id: &str) -> bool {
        self.service.get(principal, task_id).is_ok()
    }
}

#[async_trait::async_trait]
impl EventSource for TaskSource {
    fn kind(&self) -> SourceKind {
        SourceKind::TaskSettled
    }

    fn descriptors(&self) -> Vec<EventDescriptor> {
        vec![EventDescriptor {
            name: NAME.into(),
            description: "One of your tasks reached a terminal status. Read the result \
                          with tasks/get."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {"taskId": {
                    "type": "string",
                    "description": "Only this task; omit for all of your tasks."}},
                "additionalProperties": false,
            }),
            payload_schema: json!({
                "type": "object",
                "properties": {
                    "taskId": {"type": "string"},
                    "status": {"type": "string"},
                    "settledAt": {"type": "string"},
                },
                "additionalProperties": false,
            }),
            scope: Visibility::Owner,
            kind: SourceKind::TaskSettled,
        }]
    }

    fn offers(&self, name: &str) -> bool {
        name == NAME
    }

    /// A named task must be the caller's own; an unknown one answers the
    /// same, so task ids cannot be probed.
    async fn authorize(
        &self,
        principal: &str,
        _name: &str,
        arguments: &Value,
    ) -> Result<(), RpcError> {
        let Some(task_id) = arguments.get("taskId").and_then(Value::as_str) else {
            return Ok(());
        };
        match self.service.get(principal, task_id) {
            Ok(_) => Ok(()),
            Err(crate::gateway::task_service::ServiceError::NotFound) => Err(RpcError::forbidden()),
            // The store could not answer: not a verdict on ownership.
            Err(_) => Err(RpcError::internal()),
        }
    }

    /// At delivery the occurrence was already matched to its owner (by the
    /// owner it carries), and a task never changes owner, so the store has
    /// nothing to add: once the expiry sweep removes the row, asking it would
    /// refuse the owner's own settlement and end the subscription (MIK-7940).
    async fn authorize_row(
        &self,
        _sub: &crate::events::records::Subscription,
    ) -> Result<(), RpcError> {
        Ok(())
    }

    fn matches(&self, principal: &str, arguments: &Value, event: &SourceEvent) -> bool {
        let Some(task_id) = event.data["taskId"].as_str() else {
            return false;
        };
        if arguments
            .get("taskId")
            .and_then(Value::as_str)
            .is_some_and(|want| want != task_id)
        {
            return false;
        }
        // The occurrence carries its owner (taken when the task committed), so
        // an expired row still reaches its owner and only its owner.
        match &event.owner {
            Some(owner) => self
                .service
                .owner(principal)
                .is_ok_and(|mine| mine.as_digest() == owner),
            None => self.owns(principal, task_id),
        }
    }
}

impl EventsHub {
    /// A task transition was committed: emit when it is terminal.
    pub(crate) fn task_published(
        &self,
        task_id: &str,
        status: TaskStatus,
        at: DateTime<Utc>,
        owner: Option<String>,
    ) {
        if !matches!(
            status,
            TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
        ) {
            return;
        }
        let status_name = serde_json::to_value(status).unwrap_or_default();
        self.emit(SourceEvent {
            kind: SourceKind::TaskSettled,
            name: NAME.into(),
            backend: "tasks".into(),
            scope: Visibility::Owner,
            owner,
            upstream_id: format!("{task_id}:{}", status_name.as_str().unwrap_or_default()),
            occurred_at: at,
            data: json!({
                "taskId": task_id,
                "status": status_name,
                "settledAt": at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            }),
            lifecycle_key: None,
        });
    }

    /// Offer `task.settled` over `service` and tell the hub of each commit.
    pub(crate) fn install_task_source(
        self: &Arc<Self>,
        service: Arc<TaskService>,
        executor: &crate::gateway::task_service::TaskExecutor,
    ) {
        self.register_source(Arc::new(TaskSource { service }));
        let hub = Arc::clone(self);
        executor.on_publication(Arc::new(move |id, status, at, owner| {
            hub.task_published(id, status, at, owner);
        }));
    }
}
