//! Structured JSONL audit log for the Slack control plane (SLACKCTL.AUDIT.6, SLACKCTL.AUDIT.7).
//!
//! Every received event, auth decision, dispatched action, and reply is written
//! to a structured, queryable audit log (JSONL), including Slack user-ID,
//! channel, ts, instruction text, and verdict.
//!
//! Each entry carries a unique attribution ID (B1-IDENT) tying it to the Slack
//! origin event — no anonymous exec.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A single audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEntry {
    /// Unique attribution ID (B1-IDENT) tying this action to its origin event.
    pub attribution_id: String,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// The audit event phase.
    pub event: AuditEvent,
    /// Slack user ID that triggered the action.
    pub user_id: String,
    /// Slack channel ID.
    pub channel: String,
    /// Slack message timestamp (thread_ts or ts).
    pub slack_ts: String,
    /// The instruction text (may be empty for non-instruction events).
    pub instruction: String,
    /// The auth/policy verdict.
    pub verdict: AuditVerdict,
}

/// Audit event phases.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEvent {
    /// Event received from Slack.
    EventReceived,
    /// Authorization decision made.
    AuthDecision,
    /// Action dispatched to agent.
    ActionDispatched,
    /// Reply posted to Slack thread.
    ReplyPosted,
    /// Confirmation requested in thread.
    ConfirmationRequested,
}

/// Auth/policy verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditVerdict {
    /// Allowed — instruction will execute.
    Allow,
    /// Denied — user not authorized.
    Deny,
    /// Requires confirmation — destructive or unknown instruction.
    RequireConfirmation,
    /// Executed successfully.
    Executed,
    /// Error during processing.
    Error,
}

/// Generate a unique attribution ID for a Slack origin event.
///
/// Format: `slack-ctl-{uuid}` ensuring B1-IDENT uniqueness.
pub fn generate_attribution_id() -> String {
    format!("slack-ctl-{}", Uuid::new_v4())
}

/// Append-only JSONL audit logger for the Slack control plane.
pub struct AuditLog {
    inner: Mutex<AuditLogInner>,
}

struct AuditLogInner {
    writer: BufWriter<File>,
}

impl AuditLog {
    /// Open or create the audit log file.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the parent directory cannot be created or
    /// the file cannot be opened.
    pub fn open(path: &Path) -> io::Result<Self> {
        let expanded = expand_tilde(path);

        if let Some(parent) = expanded.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&expanded)?;

        Ok(Self {
            inner: Mutex::new(AuditLogInner {
                writer: BufWriter::new(file),
            }),
        })
    }

    /// Write an audit entry to the log.
    ///
    /// # Errors
    ///
    /// Returns `io::Error` if serialisation or the file write fails.
    pub fn log(&self, entry: &AuditEntry) -> io::Result<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("audit log mutex poisoned"))?;

        let line = serde_json::to_string(entry).map_err(io::Error::other)?;
        writeln!(inner.writer, "{line}")?;
        inner.writer.flush()?;
        Ok(())
    }

    /// Create an audit entry for a received event and log it.
    ///
    /// Returns the generated attribution ID.
    pub fn log_event_received(
        &self,
        user_id: &str,
        channel: &str,
        slack_ts: &str,
        instruction: &str,
    ) -> io::Result<String> {
        let attribution_id = generate_attribution_id();
        let entry = AuditEntry {
            attribution_id: attribution_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            event: AuditEvent::EventReceived,
            user_id: user_id.to_string(),
            channel: channel.to_string(),
            slack_ts: slack_ts.to_string(),
            instruction: instruction.to_string(),
            verdict: AuditVerdict::Allow,
        };
        self.log(&entry)?;
        Ok(attribution_id)
    }

    /// Log an auth decision.
    pub fn log_auth_decision(
        &self,
        attribution_id: &str,
        user_id: &str,
        channel: &str,
        slack_ts: &str,
        instruction: &str,
        verdict: AuditVerdict,
    ) -> io::Result<()> {
        let entry = AuditEntry {
            attribution_id: attribution_id.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            event: AuditEvent::AuthDecision,
            user_id: user_id.to_string(),
            channel: channel.to_string(),
            slack_ts: slack_ts.to_string(),
            instruction: instruction.to_string(),
            verdict,
        };
        self.log(&entry)
    }

    /// Log an action dispatch.
    pub fn log_action_dispatched(
        &self,
        attribution_id: &str,
        user_id: &str,
        channel: &str,
        slack_ts: &str,
        instruction: &str,
    ) -> io::Result<()> {
        let entry = AuditEntry {
            attribution_id: attribution_id.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            event: AuditEvent::ActionDispatched,
            user_id: user_id.to_string(),
            channel: channel.to_string(),
            slack_ts: slack_ts.to_string(),
            instruction: instruction.to_string(),
            verdict: AuditVerdict::Executed,
        };
        self.log(&entry)
    }

    /// Log a reply posted to Slack.
    pub fn log_reply_posted(
        &self,
        attribution_id: &str,
        user_id: &str,
        channel: &str,
        slack_ts: &str,
        instruction: &str,
    ) -> io::Result<()> {
        let entry = AuditEntry {
            attribution_id: attribution_id.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            event: AuditEvent::ReplyPosted,
            user_id: user_id.to_string(),
            channel: channel.to_string(),
            slack_ts: slack_ts.to_string(),
            instruction: instruction.to_string(),
            verdict: AuditVerdict::Executed,
        };
        self.log(&entry)
    }
}

/// Read all entries from an audit log file.
pub fn read_audit_log(path: &Path) -> io::Result<Vec<AuditEntry>> {
    let expanded = expand_tilde(path);
    let content = std::fs::read_to_string(&expanded)?;
    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(trimmed).map_err(io::Error::other)?;
        entries.push(entry);
    }
    Ok(entries)
}

fn expand_tilde(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest);
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn attribution_ids_are_unique() {
        let id1 = generate_attribution_id();
        let id2 = generate_attribution_id();
        assert_ne!(id1, id2);
        assert!(id1.starts_with("slack-ctl-"));
        assert!(id2.starts_with("slack-ctl-"));
    }

    #[test]
    fn audit_log_writes_and_reads_back() {
        let tmp = NamedTempFile::new().unwrap();
        let log = AuditLog::open(tmp.path()).unwrap();

        let attribution_id = log
            .log_event_received("U123", "C456", "1234567890.123456", "what is 2+2")
            .unwrap();

        log.log_auth_decision(
            &attribution_id,
            "U123",
            "C456",
            "1234567890.123456",
            "what is 2+2",
            AuditVerdict::Allow,
        )
        .unwrap();

        log.log_action_dispatched(
            &attribution_id,
            "U123",
            "C456",
            "1234567890.123456",
            "what is 2+2",
        )
        .unwrap();

        log.log_reply_posted(
            &attribution_id,
            "U123",
            "C456",
            "1234567890.123456",
            "what is 2+2",
        )
        .unwrap();

        let entries = read_audit_log(tmp.path()).unwrap();
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].event, AuditEvent::EventReceived);
        assert_eq!(entries[1].event, AuditEvent::AuthDecision);
        assert_eq!(entries[1].verdict, AuditVerdict::Allow);
        assert_eq!(entries[2].event, AuditEvent::ActionDispatched);
        assert_eq!(entries[3].event, AuditEvent::ReplyPosted);

        // All entries share the same attribution_id
        for entry in &entries {
            assert_eq!(entry.attribution_id, attribution_id);
            assert_eq!(entry.user_id, "U123");
            assert_eq!(entry.channel, "C456");
        }
    }
}
