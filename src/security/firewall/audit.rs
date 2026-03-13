//! Structured NDJSON audit log for every tool invocation through the firewall.
//!
//! Every entry is a single JSON line (NDJSON format) containing:
//!
//! * `timestamp` — RFC 3339 timestamp of the event.
//! * `event` — `"request"` or `"response"`.
//! * `session_id`, `server`, `tool`, `caller` — identity fields.
//! * `args_hash` — SHA-256 hash of the request arguments (request events only).
//!   Raw argument values are **never** logged.
//! * `action` — `"allow"`, `"warn"`, or `"block"`.
//! * `findings_count`, `findings` — structured finding details.
//! * `anomaly_score` — optional float from the anomaly detector.
//!
//! The logger is thread-safe via an internal `Mutex<BufWriter>`.

use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;

use chrono::Utc;
use serde::Serialize;
use serde_json::Value;

use super::{Finding, FirewallAction, FirewallVerdict};
use crate::security::hash_argument;

/// Append-only NDJSON audit logger.
pub struct AuditLogger {
    writer: Mutex<Box<dyn Write + Send>>,
}

/// A single audit log entry (serialised as one JSON line).
#[derive(Serialize)]
struct AuditEntry<'a> {
    timestamp: String,
    event: &'a str,
    session_id: &'a str,
    server: &'a str,
    tool: &'a str,
    caller: &'a str,
    /// SHA-256 hash of the request arguments, or `null` for response events.
    args_hash: Option<String>,
    action: &'a str,
    findings_count: usize,
    findings: &'a [Finding],
    anomaly_score: Option<f64>,
}

impl AuditLogger {
    /// Open an audit log file for append-only writing.
    ///
    /// The parent directory is created if it does not exist.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the file cannot be opened or the parent
    /// directory cannot be created.
    pub fn new(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            writer: Mutex::new(Box::new(BufWriter::new(file))),
        })
    }

    /// Create a logger that writes to stderr (fallback when file cannot be opened).
    pub fn stderr() -> Self {
        Self {
            writer: Mutex::new(Box::new(io::stderr())),
        }
    }

    /// Log a pre-invocation (request) event.
    ///
    /// `args` are hashed via `hash_argument` — raw values are never logged.
    pub fn log_request(
        &self,
        session_id: &str,
        server: &str,
        tool: &str,
        caller: &str,
        args: &Value,
        verdict: &FirewallVerdict,
    ) {
        let entry = AuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            event: "request",
            session_id,
            server,
            tool,
            caller,
            args_hash: Some(hash_argument(args)),
            action: action_str(verdict.action),
            findings_count: verdict.findings.len(),
            findings: &verdict.findings,
            anomaly_score: verdict.anomaly_score,
        };
        self.write_entry(&entry);
    }

    /// Log a post-invocation (response) event.
    pub fn log_response(
        &self,
        session_id: &str,
        server: &str,
        tool: &str,
        caller: &str,
        verdict: &FirewallVerdict,
    ) {
        let entry = AuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            event: "response",
            session_id,
            server,
            tool,
            caller,
            args_hash: None,
            action: action_str(verdict.action),
            findings_count: verdict.findings.len(),
            findings: &verdict.findings,
            anomaly_score: verdict.anomaly_score,
        };
        self.write_entry(&entry);
    }

    fn write_entry<T: Serialize>(&self, entry: &T) {
        if let Ok(json) = serde_json::to_string(entry) {
            if let Ok(mut w) = self.writer.lock() {
                let _ = writeln!(w, "{json}");
                let _ = w.flush();
            }
        }
    }
}

fn action_str(action: FirewallAction) -> &'static str {
    match action {
        FirewallAction::Allow => "allow",
        FirewallAction::Warn => "warn",
        FirewallAction::Block => "block",
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::{FindingLocation, FirewallAction, ScanType, Severity};
    use super::*;
    use serde_json::json;
    use tempfile::NamedTempFile;

    fn clean_verdict() -> FirewallVerdict {
        FirewallVerdict {
            allowed: true,
            action: FirewallAction::Allow,
            findings: vec![],
            anomaly_score: None,
        }
    }

    fn blocked_verdict() -> FirewallVerdict {
        FirewallVerdict {
            allowed: false,
            action: FirewallAction::Block,
            findings: vec![Finding {
                scan_type: ScanType::ShellInjection,
                severity: Severity::High,
                description: "Shell injection in cmd".to_string(),
                matched: "; rm -rf /".to_string(),
                location: FindingLocation::RequestArgs,
            }],
            anomaly_score: Some(0.85),
        }
    }

    fn read_lines(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect()
    }

    // ── Structural validity ───────────────────────────────────────────────────

    #[test]
    fn audit_entry_is_valid_ndjson() {
        let tmp = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(tmp.path()).unwrap();
        let args = json!({ "cmd": "ls" });
        logger.log_request("sess1", "srv", "tool", "caller", &args, &clean_verdict());

        let lines = read_lines(tmp.path());
        assert_eq!(lines.len(), 1);
        // Each line must parse as valid JSON.
        let _: serde_json::Value =
            serde_json::from_str(&lines[0]).expect("line must be valid JSON");
    }

    #[test]
    fn audit_contains_required_fields() {
        let tmp = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(tmp.path()).unwrap();
        let args = json!({ "x": 1 });
        logger.log_request(
            "my-session",
            "backend",
            "my_tool",
            "api-key-1",
            &args,
            &clean_verdict(),
        );

        let line = &read_lines(tmp.path())[0];
        let entry: serde_json::Value = serde_json::from_str(line).unwrap();

        assert!(entry.get("timestamp").is_some(), "missing timestamp");
        assert_eq!(entry["event"], "request");
        assert_eq!(entry["session_id"], "my-session");
        assert_eq!(entry["server"], "backend");
        assert_eq!(entry["tool"], "my_tool");
        assert_eq!(entry["caller"], "api-key-1");
        assert_eq!(entry["action"], "allow");
        assert!(
            entry.get("findings_count").is_some(),
            "missing findings_count"
        );
    }

    #[test]
    fn audit_args_hash_not_raw_value() {
        let tmp = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(tmp.path()).unwrap();
        let args = json!({ "secret_key": "super-secret-value-that-must-not-appear" });
        logger.log_request("sess", "srv", "tool", "caller", &args, &clean_verdict());

        let line = &read_lines(tmp.path())[0];
        // The raw secret must NOT appear in the log line.
        assert!(
            !line.contains("super-secret-value-that-must-not-appear"),
            "Raw argument value leaked into audit log: {line}"
        );
        // A hash field must be present.
        let entry: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(
            entry.get("args_hash").and_then(|v| v.as_str()).is_some(),
            "args_hash must be a non-null string"
        );
    }

    #[test]
    fn audit_response_event_has_no_args_hash() {
        let tmp = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(tmp.path()).unwrap();
        logger.log_response("sess", "srv", "tool", "caller", &clean_verdict());

        let line = &read_lines(tmp.path())[0];
        let entry: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(entry["event"], "response");
        assert!(
            entry["args_hash"].is_null(),
            "Response entries must not carry args_hash"
        );
    }

    #[test]
    fn audit_findings_serialised_correctly() {
        let tmp = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(tmp.path()).unwrap();
        let args = json!({});
        logger.log_request("sess", "srv", "tool", "caller", &args, &blocked_verdict());

        let line = &read_lines(tmp.path())[0];
        let entry: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(entry["action"], "block");
        assert_eq!(entry["findings_count"], 1);
        assert!(entry["anomaly_score"].as_f64().is_some());
    }

    #[test]
    fn audit_multiple_entries_are_separate_lines() {
        let tmp = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(tmp.path()).unwrap();
        let args = json!({});
        for i in 0..5 {
            logger.log_request(
                &format!("sess{i}"),
                "srv",
                "tool",
                "caller",
                &args,
                &clean_verdict(),
            );
        }
        let lines = read_lines(tmp.path());
        assert_eq!(lines.len(), 5);
        for line in &lines {
            let _: serde_json::Value =
                serde_json::from_str(line).expect("every line must be valid JSON");
        }
    }

    // ── File creation ─────────────────────────────────────────────────────────

    #[test]
    fn creates_parent_directory_if_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subdir/audit.jsonl");
        let logger = AuditLogger::new(&path).unwrap();
        let args = json!({});
        logger.log_request("s", "srv", "t", "c", &args, &clean_verdict());
        assert!(path.exists());
    }
}
