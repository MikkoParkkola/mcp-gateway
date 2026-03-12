//! Audit log for agent tool invocations.
//!
//! Every tool call is recorded with:
//! - Agent identity (`client_id`, name)
//! - Scopes held by the agent
//! - Tool name and backend
//! - Timestamp (RFC 3339)
//! - Decision: `allow` or `deny` + reason
//!
//! Events are emitted via `tracing::info!` using structured fields, keeping
//! them queryable in any log aggregator (Loki, `CloudWatch`, Datadog, etc.).

use chrono::Utc;
use serde::Serialize;

/// Decision for a tool invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// The tool invocation was permitted.
    Allow,
    /// The tool invocation was denied.
    Deny,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny => write!(f, "deny"),
        }
    }
}

/// A structured audit log entry for a single tool invocation.
#[derive(Debug, Serialize)]
pub struct ToolInvocationAudit {
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Agent `client_id`.
    pub agent_id: String,
    /// Agent display name.
    pub agent_name: String,
    /// Backend the tool belongs to.
    pub backend: String,
    /// Tool being invoked.
    pub tool: String,
    /// Scopes the agent holds (raw scope strings).
    pub scopes: Vec<String>,
    /// Allow or deny.
    pub decision: Decision,
    /// Human-readable reason (always present for deny; optional for allow).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ToolInvocationAudit {
    /// Build an `allow` entry.
    pub fn allow(
        agent_id: impl Into<String>,
        agent_name: impl Into<String>,
        backend: impl Into<String>,
        tool: impl Into<String>,
        scopes: Vec<String>,
    ) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            agent_id: agent_id.into(),
            agent_name: agent_name.into(),
            backend: backend.into(),
            tool: tool.into(),
            scopes,
            decision: Decision::Allow,
            reason: None,
        }
    }

    /// Build a `deny` entry.
    pub fn deny(
        agent_id: impl Into<String>,
        agent_name: impl Into<String>,
        backend: impl Into<String>,
        tool: impl Into<String>,
        scopes: Vec<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            agent_id: agent_id.into(),
            agent_name: agent_name.into(),
            backend: backend.into(),
            tool: tool.into(),
            scopes,
            decision: Decision::Deny,
            reason: Some(reason.into()),
        }
    }
}

/// Emit a tool invocation audit event via structured tracing.
pub fn emit(entry: &ToolInvocationAudit) {
    match serde_json::to_string(entry) {
        Ok(ref json) => tracing::info!(
            audit = %json,
            agent = %entry.agent_id,
            tool = %entry.tool,
            backend = %entry.backend,
            decision = %entry.decision,
            "agent_tool_audit"
        ),
        Err(ref e) => tracing::warn!(error = %e, "Failed to serialize tool invocation audit"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_entry_has_correct_decision() {
        let entry = ToolInvocationAudit::allow(
            "agent-1",
            "My Agent",
            "surreal",
            "query",
            vec!["tools:surreal:*".to_string()],
        );

        assert_eq!(entry.decision, Decision::Allow);
        assert!(entry.reason.is_none());
        assert!(!entry.timestamp.is_empty());
        assert_eq!(entry.agent_id, "agent-1");
        assert_eq!(entry.backend, "surreal");
        assert_eq!(entry.tool, "query");
    }

    #[test]
    fn deny_entry_has_reason() {
        let entry = ToolInvocationAudit::deny(
            "agent-2",
            "Restricted Agent",
            "brave",
            "search",
            vec![],
            "Insufficient scope",
        );

        assert_eq!(entry.decision, Decision::Deny);
        assert_eq!(entry.reason.as_deref(), Some("Insufficient scope"));
    }

    #[test]
    fn entries_serialize_to_json() {
        let allow_entry = ToolInvocationAudit::allow(
            "a",
            "A",
            "b",
            "t",
            vec!["tools:*".to_string()],
        );
        let deny_entry = ToolInvocationAudit::deny(
            "a",
            "A",
            "b",
            "t",
            vec![],
            "reason",
        );

        assert!(serde_json::to_string(&allow_entry).is_ok());
        assert!(serde_json::to_string(&deny_entry).is_ok());
    }

    #[test]
    fn emit_does_not_panic() {
        let entry = ToolInvocationAudit::allow("a", "A", "b", "t", vec![]);
        emit(&entry); // should not panic
    }

    #[test]
    fn decision_display() {
        assert_eq!(Decision::Allow.to_string(), "allow");
        assert_eq!(Decision::Deny.to_string(), "deny");
    }
}
