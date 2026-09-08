// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT

//! Flat Tasks extension wire state and legal in-memory lifecycle transitions.
//!
//! The owning service supplies timestamps, gateway input keys and atomic durable
//! commits. This model neither dispatches work nor owns persistence. Its private
//! snapshot retains consumed keys; its public projection exposes no execution
//! checkpoint, backend request state or tool identity.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use super::{JsonRpcError, mrtr::InputRequired};

/// Where a task has got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    /// Still running.
    Working,
    /// Waiting for client input.
    InputRequired,
    /// Finished, with a result.
    Completed,
    /// Finished, with a JSON-RPC failure.
    Failed,
    /// The gateway will not continue this task.
    Cancelled,
}

/// Per-record immutable timing values, chosen by admission.
#[derive(Debug, Clone, Copy)]
pub struct TaskOptions {
    /// Retention from creation; null represents unlimited on the wire.
    pub ttl_ms: Option<u64>,
    /// Optional suggested poll cadence.
    pub poll_interval_ms: Option<u64>,
}

/// A model event. The store supplies its commit timestamp and owns atomicity.
#[derive(Debug, Clone)]
pub enum TaskTransition {
    /// A normal tool result, including tool-level failures.
    Complete(Value),
    /// A JSON-RPC failure, preserving its original object.
    Fail(JsonRpcError),
    /// Cooperative cancellation, without promising reversal of backend work.
    Cancel,
    /// An already-parsed round using gateway-allocated unique keys.
    RequireInput(InputRequired),
    /// A JSON object of responses; malformed types reject before mutation.
    ProvideInput(Value),
    /// Optional human-readable progress information.
    StatusMessage(Option<String>),
}

/// Observed effect of a model transition, not a durable commit acknowledgement.
#[derive(Debug, Default)]
pub struct TaskChange {
    /// Whether the model changed.
    pub changed: bool,
    /// Only new answers accepted from currently outstanding keys.
    pub accepted_inputs: Map<String, Value>,
}

/// A transition or snapshot that cannot represent a legal task.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum TaskModelError {
    /// Payload has the wrong shape or reuses an input key.
    #[error("invalid task input")]
    InvalidInput,
    /// A live input round cannot be replaced by another round.
    #[error("invalid task transition")]
    InvalidTransition,
    /// A serialized private model cannot be restored safely.
    #[error("invalid task snapshot")]
    InvalidSnapshot,
}

/// Private model snapshot, separate from the public protocol projection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskSnapshot {
    version: u32,
    tool: String,
    task: TaskWire,
    issued_input_keys: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TaskWire {
    task_id: String,
    created_at: DateTime<Utc>,
    last_updated_at: DateTime<Utc>,
    // Custom deserialization makes absence an error while preserving explicit null.
    #[serde(deserialize_with = "nullable_ttl")]
    ttl_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    poll_interval_ms: Option<u64>,
    status: TaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(
        default,
        deserialize_with = "snapshot_error",
        skip_serializing_if = "Option::is_none"
    )]
    error: Option<JsonRpcError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    input_requests: Option<Map<String, Value>>,
}

fn nullable_ttl<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u64>, D::Error> {
    Option::deserialize(deserializer)
}

// Reuse JSON-RPC validation while retaining whether its optional data field
// was present. Option<Value>'s default decoder otherwise collapses null/absence.
fn snapshot_error<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<JsonRpcError>, D::Error> {
    Option::<Value>::deserialize(deserializer)?
        .map(|mut value| {
            let data = value
                .as_object_mut()
                .and_then(|object| object.remove("data"));
            let mut error: JsonRpcError =
                serde_json::from_value(value).map_err(serde::de::Error::custom)?;
            error.data = data;
            Ok(error)
        })
        .transpose()
}

/// A long-running call, addressable by handle.
#[derive(Debug, Clone)]
pub struct Task {
    tool: String,
    wire: TaskWire,
    issued_input_keys: BTreeSet<String>,
}

impl Task {
    /// Start a task with the release's default retention and poll cadence.
    #[must_use]
    pub fn create(tool: &str) -> Self {
        Self::create_at(
            tool,
            Utc::now(),
            TaskOptions {
                ttl_ms: Some(86_400_000),
                poll_interval_ms: Some(1_000),
            },
        )
    }

    /// Construct with a controlled creation time and immutable record options.
    #[must_use]
    pub fn create_at(tool: &str, at: DateTime<Utc>, options: TaskOptions) -> Self {
        Self {
            tool: tool.to_owned(),
            wire: TaskWire {
                task_id: format!("task-{}", uuid::Uuid::new_v4()),
                created_at: at,
                last_updated_at: at,
                ttl_ms: options.ttl_ms,
                poll_interval_ms: options.poll_interval_ms,
                status: TaskStatus::Working,
                status_message: None,
                result: None,
                error: None,
                input_requests: None,
            },
            issued_input_keys: BTreeSet::new(),
        }
    }

    /// The handle a client polls with.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.wire.task_id
    }

    /// Private tool identity for the owning service, never part of the wire task.
    #[must_use]
    pub fn tool(&self) -> &str {
        &self.tool
    }

    /// Where it has got to.
    #[must_use]
    pub const fn status(&self) -> TaskStatus {
        self.wire.status
    }

    /// The completed result; absence never invents an answer.
    #[must_use]
    pub const fn result(&self) -> Option<&Value> {
        self.wire.result.as_ref()
    }

    /// The actual JSON-RPC failure object, distinct from an unfinished task.
    #[must_use]
    pub const fn error(&self) -> Option<&JsonRpcError> {
        self.wire.error.as_ref()
    }

    /// Whether the record's own stamped retention has run out at `now`.
    ///
    /// Measured from `createdAt`, which is the anchor the record was stamped
    /// with; a null `ttlMs` is unlimited and never runs out. Crate-private and
    /// read-only, so a retention question costs no serialization of the wire
    /// task and no field of it becomes writable.
    ///
    /// Overflow-safe in both directions: a creation time in the future gives a
    /// negative age and answers no, and a TTL larger than any age this process
    /// can observe answers no rather than wrapping into an early deletion.
    #[must_use]
    pub(crate) fn retention_elapsed(&self, now: DateTime<Utc>) -> bool {
        let Some(ttl_ms) = self.wire.ttl_ms else {
            return false;
        };
        let age_ms = now
            .signed_duration_since(self.wire.created_at)
            .num_milliseconds();
        u64::try_from(age_ms).is_ok_and(|age_ms| age_ms >= ttl_ms)
    }

    /// A flat public protocol projection; no private model history is exposed.
    #[must_use]
    pub fn wire(&self) -> impl Serialize + '_ {
        &self.wire
    }

    /// Record an object result if the task is live. Late outcomes are ignored.
    pub fn complete(&mut self, result: Value) {
        let _ = self.transition(TaskTransition::Complete(result), Utc::now());
    }

    /// Record a JSON-RPC failure if live, preserving code, message and data.
    pub fn fail(&mut self, error: JsonRpcError) {
        let _ = self.transition(TaskTransition::Fail(error), Utc::now());
    }

    /// Apply a legal event at an explicit time supplied by the owning service.
    ///
    /// # Errors
    /// Rejects malformed input or replacement of an outstanding input round
    /// before changing state. The service validates nested protocol payloads.
    pub fn transition(
        &mut self,
        event: TaskTransition,
        at: DateTime<Utc>,
    ) -> Result<TaskChange, TaskModelError> {
        // Even ignored response keys must have a valid top-level response shape.
        if self.is_terminal() && !matches!(event, TaskTransition::ProvideInput(_)) {
            return Ok(TaskChange::default());
        }
        match event {
            TaskTransition::Complete(result) => {
                if !result.is_object() {
                    return Err(TaskModelError::InvalidInput);
                }
                self.wire.status = TaskStatus::Completed;
                self.wire.result = Some(result);
                self.wire.input_requests = None;
            }
            TaskTransition::Fail(error) => {
                self.wire.status = TaskStatus::Failed;
                self.wire.error = Some(error);
                self.wire.input_requests = None;
            }
            TaskTransition::Cancel => {
                self.wire.status = TaskStatus::Cancelled;
                self.wire.input_requests = None;
            }
            TaskTransition::RequireInput(input) => self.require_input(input)?,
            TaskTransition::StatusMessage(message) => {
                if self.wire.status_message == message {
                    return Ok(TaskChange::default());
                }
                self.wire.status_message = message;
            }
            TaskTransition::ProvideInput(responses) => return self.provide_input(responses, at),
        }
        self.wire.last_updated_at = self.wire.last_updated_at.max(at);
        Ok(TaskChange {
            changed: true,
            ..TaskChange::default()
        })
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.wire.status,
            TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
        )
    }

    fn require_input(&mut self, input: InputRequired) -> Result<(), TaskModelError> {
        if self.wire.status == TaskStatus::InputRequired {
            return Err(TaskModelError::InvalidTransition);
        }
        let mut requests = Map::new();
        for (key, value) in input.requests {
            if key.is_empty()
                || !value.is_object()
                || self.issued_input_keys.contains(&key)
                || requests.insert(key, value).is_some()
            {
                return Err(TaskModelError::InvalidInput);
            }
        }
        if requests.is_empty() {
            return Err(TaskModelError::InvalidInput);
        }
        self.issued_input_keys.extend(requests.keys().cloned());
        self.wire.input_requests = Some(requests);
        self.wire.status = TaskStatus::InputRequired;
        Ok(())
    }

    fn provide_input(
        &mut self,
        responses: Value,
        at: DateTime<Utc>,
    ) -> Result<TaskChange, TaskModelError> {
        let Value::Object(responses) = responses else {
            return Err(TaskModelError::InvalidInput);
        };
        if responses.values().any(|value| !value.is_object()) {
            return Err(TaskModelError::InvalidInput);
        }
        let Some(outstanding) = self.wire.input_requests.as_mut() else {
            return Ok(TaskChange::default());
        };
        let mut accepted_inputs = Map::new();
        for (key, value) in responses {
            if outstanding.remove(&key).is_some() {
                accepted_inputs.insert(key, value);
            }
        }
        if accepted_inputs.is_empty() {
            return Ok(TaskChange::default());
        }
        if outstanding.is_empty() {
            self.wire.input_requests = None;
            self.wire.status = TaskStatus::Working;
        }
        self.wire.last_updated_at = self.wire.last_updated_at.max(at);
        Ok(TaskChange {
            changed: true,
            accepted_inputs,
        })
    }

    /// Capture private state for the owning store's serialization boundary.
    #[must_use]
    pub fn snapshot(&self) -> TaskSnapshot {
        TaskSnapshot {
            version: 1,
            tool: self.tool.clone(),
            task: self.wire.clone(),
            issued_input_keys: self.issued_input_keys.clone(),
        }
    }

    /// Validate and restore a private model snapshot, without starting work.
    ///
    /// # Errors
    /// Rejects unsupported versions, invalid identity/time ordering and state
    /// payloads inconsistent with the task's status or issued-key history.
    pub fn from_snapshot(snapshot: TaskSnapshot) -> Result<Self, TaskModelError> {
        let id = snapshot
            .task
            .task_id
            .strip_prefix("task-")
            .and_then(|id| uuid::Uuid::parse_str(id).ok());
        if snapshot.version != 1
            || id.is_none_or(|id| {
                id.get_version_num() != 4 || format!("task-{id}") != snapshot.task.task_id
            })
            || snapshot.task.last_updated_at < snapshot.task.created_at
            || snapshot.issued_input_keys.iter().any(String::is_empty)
            || !snapshot.valid_payload()
        {
            return Err(TaskModelError::InvalidSnapshot);
        }
        Ok(Self {
            tool: snapshot.tool,
            wire: snapshot.task,
            issued_input_keys: snapshot.issued_input_keys,
        })
    }
}

impl TaskSnapshot {
    fn valid_payload(&self) -> bool {
        let task = &self.task;
        match task.status {
            TaskStatus::Working | TaskStatus::Cancelled => {
                task.result.is_none() && task.error.is_none() && task.input_requests.is_none()
            }
            TaskStatus::Completed => {
                task.result.as_ref().is_some_and(Value::is_object)
                    && task.error.is_none()
                    && task.input_requests.is_none()
            }
            TaskStatus::Failed => {
                task.error.is_some() && task.result.is_none() && task.input_requests.is_none()
            }
            TaskStatus::InputRequired => {
                task.result.is_none()
                    && task.error.is_none()
                    && task.input_requests.as_ref().is_some_and(|requests| {
                        !requests.is_empty()
                            && requests.iter().all(|(key, value)| {
                                self.issued_input_keys.contains(key) && value.is_object()
                            })
                    })
            }
        }
    }
}

#[cfg(test)]
mod lifecycle_tests;

#[cfg(test)]
mod snapshot_tests;
