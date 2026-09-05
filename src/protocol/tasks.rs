// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT

//! The tasks extension (`io.modelcontextprotocol/tasks`), for a call that
//! outlives the request that started it.
//!
//! Moved out of the core protocol into an official extension by MCP
//! 2026-07-28, and redesigned on the way: the blocking `tasks/result` was
//! replaced by polling via `tasks/get`.
//!
//! That redesign is what makes it the answer to re-issue safety for an
//! operation that cannot be made idempotent. Stream resumability is gone, so a
//! broken stream loses an in-flight request and the client re-issues it — which
//! turns one booking into two. A task has a handle instead, and asking about a
//! handle twice is safe in a way that re-sending a booking is not.

use serde_json::Value;

/// Where a task has got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    /// Still running.
    Working,
    /// Finished, with a result.
    Completed,
    /// Finished, without one.
    Failed,
}

/// A long-running call, addressable by handle.
#[derive(Debug, Clone)]
pub struct Task {
    id: String,
    tool: String,
    status: TaskStatus,
    result: Option<Value>,
    error: Option<String>,
}

impl Task {
    /// Start a task for a tool call.
    #[must_use]
    pub fn create(tool: &str) -> Self {
        Self {
            id: format!("task-{}", uuid::Uuid::new_v4()),
            tool: tool.to_string(),
            status: TaskStatus::Working,
            result: None,
            error: None,
        }
    }

    /// The handle a client polls with.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The tool this task is running.
    #[must_use]
    pub fn tool(&self) -> &str {
        &self.tool
    }

    /// Where it has got to.
    #[must_use]
    pub const fn status(&self) -> TaskStatus {
        self.status
    }

    /// The result, or `None` while it is still working or if it failed.
    ///
    /// `None` rather than a default: a default here is a booking reference
    /// nobody issued.
    #[must_use]
    pub const fn result(&self) -> Option<&Value> {
        self.result.as_ref()
    }

    /// Why it failed, if it did.
    ///
    /// Failure and "not finished" are different answers, and a caller that
    /// cannot tell them apart polls a dead task forever.
    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Record a result.
    ///
    /// A settled task stays settled. A late answer arriving after one was
    /// delivered must not overwrite it — the caller may have acted on the first
    /// already, and a task that changes its answer is worse than one that is
    /// slow.
    pub fn complete(&mut self, result: Value) {
        if self.status != TaskStatus::Working {
            return;
        }
        self.status = TaskStatus::Completed;
        self.result = Some(result);
    }

    /// Record a failure. Settled tasks stay settled, as above.
    pub fn fail(&mut self, error: impl Into<String>) {
        if self.status != TaskStatus::Working {
            return;
        }
        self.status = TaskStatus::Failed;
        self.error = Some(error.into());
    }
}
