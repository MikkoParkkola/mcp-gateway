//! Tool invocation data flow tracing for security analysis — Issue #82.
//!
//! Maps how user-supplied arguments travel through the gateway:
//!
//! ```text
//! User args → sanitize → server selection → tool invocation → response
//! ```
//!
//! For every invocation the module:
//!
//! 1. **Hashes** each argument value (SHA-256, truncated to 16 hex chars) so
//!    arguments can be correlated across log lines without storing their raw
//!    content.
//! 2. **Audits** sanitization transformations (null bytes stripped, control
//!    characters removed, etc.).
//! 3. **Classifies** the tool into a security category (read-only / write /
//!    execute / admin) based on name heuristics and annotations.
//! 4. **Logs** the full data-flow record as a structured JSON event via
//!    [`tracing::info!`].
//!
//! # Privacy
//!
//! Raw argument values are **never** logged.  Only the SHA-256 hash prefix
//! (first 16 hex characters, 64-bit entropy) is stored, sufficient to
//! correlate a specific value across a session while preserving confidentiality.

use std::collections::HashMap;

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::protocol::ToolAnnotations;

// ============================================================================
// Tool security category
// ============================================================================

/// Security category for a tool — determines audit verbosity and policy gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCategory {
    /// Tool only reads data; no side effects (e.g. `read_file`, `search`).
    ReadOnly,
    /// Tool writes or modifies data (e.g. `write_file`, `update_record`).
    Write,
    /// Tool executes external commands or code (e.g. `run_command`, `eval`).
    Execute,
    /// Tool has administrative / system-level impact (e.g. `drop_database`).
    Admin,
}

impl ToolCategory {
    /// Derive a category from the tool name and optional MCP annotations.
    ///
    /// Precedence:
    /// 1. Annotation hints (`readOnlyHint`, `destructiveHint`) when present.
    /// 2. Name-based heuristics as fallback.
    #[must_use]
    pub fn classify(tool_name: &str, annotations: Option<&ToolAnnotations>) -> Self {
        // Annotation-first: authoritative
        if let Some(ann) = annotations {
            if ann.read_only_hint == Some(true) {
                return Self::ReadOnly;
            }
            if ann.destructive_hint == Some(true) {
                return Self::Execute;
            }
        }

        // Name heuristics
        let lower = tool_name.to_lowercase();
        if ADMIN_PREFIXES.iter().any(|p| lower.starts_with(p))
            || ADMIN_SUFFIXES.iter().any(|s| lower.ends_with(s))
            || ADMIN_EXACT.iter().any(|e| lower == *e)
        {
            return Self::Admin;
        }
        if EXECUTE_PREFIXES.iter().any(|p| lower.starts_with(p))
            || EXECUTE_EXACT.iter().any(|e| lower == *e)
        {
            return Self::Execute;
        }
        if WRITE_PREFIXES.iter().any(|p| lower.starts_with(p))
            || WRITE_EXACT.iter().any(|e| lower == *e)
        {
            return Self::Write;
        }
        Self::ReadOnly
    }

    /// Return the minimum required log level for this category.
    #[must_use]
    pub fn audit_level(self) -> &'static str {
        match self {
            Self::ReadOnly => "debug",
            Self::Write => "info",
            Self::Execute => "warn",
            Self::Admin => "error",
        }
    }
}

const ADMIN_EXACT: &[&str] = &[
    "drop_table",
    "drop_database",
    "truncate_table",
    "shutdown",
    "reboot",
    "kill_process",
];
const ADMIN_PREFIXES: &[&str] = &["admin_", "sys_", "root_"];
const ADMIN_SUFFIXES: &[&str] = &["_database", "_schema"];

const EXECUTE_EXACT: &[&str] = &["eval", "exec", "shell_exec", "run_script"];
const EXECUTE_PREFIXES: &[&str] = &["run_", "execute_", "spawn_", "launch_"];

const WRITE_PREFIXES: &[&str] = &[
    "write_", "create_", "insert_", "update_", "delete_", "remove_", "move_", "rename_", "append_",
    "patch_", "put_", "post_", "upsert_",
];
const WRITE_EXACT: &[&str] = &["save", "store", "persist", "commit", "push", "upload"];

// ============================================================================
// Argument hash
// ============================================================================

/// SHA-256 hash of a JSON value's canonical representation, truncated to 16
/// hex characters (64-bit prefix).
///
/// Two invocations with identical argument values produce identical hashes,
/// enabling cross-request correlation without exposing raw data.
#[must_use]
pub fn hash_argument(value: &Value) -> String {
    let repr = match value {
        // Compact canonical JSON for objects/arrays; raw for scalars.
        Value::Object(_) | Value::Array(_) => serde_json::to_string(value).unwrap_or_default(),
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
    };
    let digest = Sha256::digest(repr.as_bytes());
    // Take the first 8 bytes → 16 hex chars
    digest[..8]
        .iter()
        .fold(String::with_capacity(16), |mut s, b| {
            write!(s, "{b:02x}").expect("write to String is infallible");
            s
        })
}

// ============================================================================
// Sanitization audit record
// ============================================================================

/// Records a single sanitization transformation applied to an argument.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SanitizationRecord {
    /// Argument key name.
    pub key: String,
    /// Hash of the *original* value (pre-sanitization).
    pub original_hash: String,
    /// Hash of the *sanitized* value (post-sanitization).
    pub sanitized_hash: String,
    /// Whether the value changed as a result of sanitization.
    pub was_modified: bool,
    /// Human-readable description of the transformation applied.
    pub transformation: String,
}

/// Audit all arguments for sanitization changes.
///
/// Compares `original` values against `sanitized` values, recording
/// each argument that was modified.
#[must_use]
pub fn audit_sanitization(
    original: &serde_json::Map<String, Value>,
    sanitized: &serde_json::Map<String, Value>,
) -> Vec<SanitizationRecord> {
    let mut records = Vec::new();
    for (key, orig_val) in original {
        let san_val = sanitized.get(key).unwrap_or(&Value::Null);
        let orig_hash = hash_argument(orig_val);
        let san_hash = hash_argument(san_val);
        let was_modified = orig_hash != san_hash;
        let transformation = if was_modified {
            describe_transformation(orig_val, san_val)
        } else {
            "pass-through".to_string()
        };
        records.push(SanitizationRecord {
            key: key.clone(),
            original_hash: orig_hash,
            sanitized_hash: san_hash,
            was_modified,
            transformation,
        });
    }
    records
}

/// Heuristically describe what changed between `orig` and `san`.
fn describe_transformation(orig: &Value, san: &Value) -> String {
    match (orig, san) {
        (Value::String(o), Value::String(s)) => {
            let removed = o.len().saturating_sub(s.len());
            if removed > 0 {
                format!("stripped {removed} char(s)")
            } else if s.len() > o.len() {
                "escaped".to_string()
            } else {
                "normalized".to_string()
            }
        }
        (_, Value::Null) => "removed".to_string(),
        _ => "transformed".to_string(),
    }
}

// ============================================================================
// DataFlowPoint — a single waypoint in the flow
// ============================================================================

/// A transformation waypoint in the data-flow audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowPoint {
    /// Stage label (e.g. `"sanitize"`, `"route"`, `"invoke"`, `"respond"`).
    pub stage: String,
    /// Argument hashes at this stage (key → hash).
    pub arg_hashes: HashMap<String, String>,
    /// Free-form annotation for the stage.
    pub note: Option<String>,
}

// ============================================================================
// DataFlowRecord — the complete per-invocation record
// ============================================================================

/// Complete data-flow audit record for a single tool invocation.
#[derive(Debug, Clone, Serialize)]
pub struct DataFlowRecord {
    /// Gateway trace ID (correlates with distributed tracing spans).
    pub trace_id: String,
    /// Target server name.
    pub server: String,
    /// Tool name.
    pub tool: String,
    /// Derived security category.
    pub category: ToolCategory,
    /// Ordered list of data-flow waypoints.
    pub flow: Vec<DataFlowPoint>,
    /// Sanitization audit results.
    pub sanitization: Vec<SanitizationRecord>,
    /// Whether any argument was modified by sanitization.
    pub sanitization_modified: bool,
}

impl DataFlowRecord {
    /// Emit this record as a structured JSON log event and return it.
    ///
    /// The log level is determined by the tool's security [`ToolCategory`].
    pub fn emit(&self) {
        let json = serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string());
        match self.category {
            ToolCategory::ReadOnly => {
                tracing::debug!(
                    trace_id = %self.trace_id,
                    server   = %self.server,
                    tool     = %self.tool,
                    category = "read_only",
                    "data_flow {json}"
                );
            }
            ToolCategory::Write => {
                tracing::info!(
                    trace_id = %self.trace_id,
                    server   = %self.server,
                    tool     = %self.tool,
                    category = "write",
                    "data_flow {json}"
                );
            }
            ToolCategory::Execute => {
                tracing::warn!(
                    trace_id = %self.trace_id,
                    server   = %self.server,
                    tool     = %self.tool,
                    category = "execute",
                    "data_flow {json}"
                );
            }
            ToolCategory::Admin => {
                tracing::error!(
                    trace_id = %self.trace_id,
                    server   = %self.server,
                    tool     = %self.tool,
                    category = "admin",
                    "data_flow {json}"
                );
            }
        }
    }
}

// ============================================================================
// DataFlowTracer — builder for a single invocation
// ============================================================================

/// Builds and logs a [`DataFlowRecord`] for one tool invocation.
///
/// # Example
///
/// ```rust,ignore
/// use mcp_gateway::security::data_flow::DataFlowTracer;
/// use serde_json::json;
///
/// let original = json!({"query": "hello\x07world"});
/// let sanitized = json!({"query": "helloworld"});
///
/// DataFlowTracer::new("trace-abc", "brave", "search", None)
///     .record_sanitization(original.as_object().unwrap(),
///                          sanitized.as_object().unwrap())
///     .add_stage("route", sanitized.as_object().unwrap(), Some("direct"))
///     .add_stage("invoke", sanitized.as_object().unwrap(), None)
///     .finish();
/// ```
pub struct DataFlowTracer {
    trace_id: String,
    server: String,
    tool: String,
    category: ToolCategory,
    flow: Vec<DataFlowPoint>,
    sanitization: Vec<SanitizationRecord>,
}

impl DataFlowTracer {
    /// Create a new tracer.
    #[must_use]
    pub fn new(
        trace_id: impl Into<String>,
        server: impl Into<String>,
        tool: impl Into<String>,
        annotations: Option<&ToolAnnotations>,
    ) -> Self {
        let tool_str: String = tool.into();
        let category = ToolCategory::classify(&tool_str, annotations);
        Self {
            trace_id: trace_id.into(),
            server: server.into(),
            tool: tool_str,
            category,
            flow: Vec::new(),
            sanitization: Vec::new(),
        }
    }

    /// Record the sanitization diff between `original` and `sanitized` args.
    #[must_use]
    pub fn record_sanitization(
        mut self,
        original: &serde_json::Map<String, Value>,
        sanitized: &serde_json::Map<String, Value>,
    ) -> Self {
        self.sanitization = audit_sanitization(original, sanitized);
        self
    }

    /// Add a data-flow waypoint at `stage` with the current argument `args`.
    #[must_use]
    pub fn add_stage(
        mut self,
        stage: impl Into<String>,
        args: &serde_json::Map<String, Value>,
        note: Option<&str>,
    ) -> Self {
        let arg_hashes = args
            .iter()
            .map(|(k, v)| (k.clone(), hash_argument(v)))
            .collect();
        self.flow.push(DataFlowPoint {
            stage: stage.into(),
            arg_hashes,
            note: note.map(String::from),
        });
        self
    }

    /// Emit the record and return it.
    #[must_use]
    pub fn finish(self) -> DataFlowRecord {
        let sanitization_modified = self.sanitization.iter().any(|r| r.was_modified);
        let record = DataFlowRecord {
            trace_id: self.trace_id,
            server: self.server,
            tool: self.tool,
            category: self.category,
            flow: self.flow,
            sanitization: self.sanitization,
            sanitization_modified,
        };
        record.emit();
        record
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // ── ToolCategory::classify ────────────────────────────────────────

    #[test]
    fn classify_read_file_is_read_only() {
        assert_eq!(
            ToolCategory::classify("read_file", None),
            ToolCategory::ReadOnly
        );
    }

    #[test]
    fn classify_search_is_read_only() {
        assert_eq!(
            ToolCategory::classify("search", None),
            ToolCategory::ReadOnly
        );
    }

    #[test]
    fn classify_write_file_is_write() {
        assert_eq!(
            ToolCategory::classify("write_file", None),
            ToolCategory::Write
        );
    }

    #[test]
    fn classify_create_directory_is_write() {
        assert_eq!(
            ToolCategory::classify("create_directory", None),
            ToolCategory::Write
        );
    }

    #[test]
    fn classify_delete_record_is_write() {
        assert_eq!(
            ToolCategory::classify("delete_record", None),
            ToolCategory::Write
        );
    }

    #[test]
    fn classify_run_command_is_execute() {
        assert_eq!(
            ToolCategory::classify("run_command", None),
            ToolCategory::Execute
        );
    }

    #[test]
    fn classify_execute_script_is_execute() {
        assert_eq!(
            ToolCategory::classify("execute_script", None),
            ToolCategory::Execute
        );
    }

    #[test]
    fn classify_eval_is_execute() {
        assert_eq!(ToolCategory::classify("eval", None), ToolCategory::Execute);
    }

    #[test]
    fn classify_drop_table_is_admin() {
        assert_eq!(
            ToolCategory::classify("drop_table", None),
            ToolCategory::Admin
        );
    }

    #[test]
    fn classify_shutdown_is_admin() {
        assert_eq!(
            ToolCategory::classify("shutdown", None),
            ToolCategory::Admin
        );
    }

    #[test]
    fn classify_annotation_read_only_overrides_name() {
        let ann = ToolAnnotations {
            read_only_hint: Some(true),
            ..Default::default()
        };
        // "run_" prefix would normally classify as Execute
        assert_eq!(
            ToolCategory::classify("run_analytics", Some(&ann)),
            ToolCategory::ReadOnly
        );
    }

    #[test]
    fn classify_annotation_destructive_overrides_name() {
        let ann = ToolAnnotations {
            destructive_hint: Some(true),
            ..Default::default()
        };
        // Plain name would be ReadOnly, but annotation overrides
        assert_eq!(
            ToolCategory::classify("custom_tool", Some(&ann)),
            ToolCategory::Execute
        );
    }

    #[test]
    fn classify_save_is_write() {
        assert_eq!(ToolCategory::classify("save", None), ToolCategory::Write);
    }

    // ── hash_argument ─────────────────────────────────────────────────

    #[test]
    fn hash_argument_is_16_hex_chars() {
        let h = hash_argument(&json!("hello"));
        assert_eq!(h.len(), 16);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_argument_is_deterministic() {
        let v = json!({"key": "value", "num": 42});
        assert_eq!(hash_argument(&v), hash_argument(&v));
    }

    #[test]
    fn hash_argument_differs_for_different_values() {
        let a = hash_argument(&json!("hello"));
        let b = hash_argument(&json!("world"));
        assert_ne!(a, b);
    }

    #[test]
    fn hash_argument_null_has_stable_hash() {
        let h1 = hash_argument(&Value::Null);
        let h2 = hash_argument(&Value::Null);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_argument_bool_differs_true_false() {
        assert_ne!(hash_argument(&json!(true)), hash_argument(&json!(false)));
    }

    // ── audit_sanitization ────────────────────────────────────────────

    #[test]
    fn audit_sanitization_detects_modification() {
        let orig = json!({"q": "hello\x07world"});
        let san = json!({"q": "helloworld"});
        let records = audit_sanitization(orig.as_object().unwrap(), san.as_object().unwrap());
        assert_eq!(records.len(), 1);
        assert!(records[0].was_modified);
        assert_eq!(records[0].key, "q");
    }

    #[test]
    fn audit_sanitization_pass_through_not_modified() {
        let orig = json!({"q": "clean input"});
        let san = json!({"q": "clean input"});
        let records = audit_sanitization(orig.as_object().unwrap(), san.as_object().unwrap());
        assert_eq!(records.len(), 1);
        assert!(!records[0].was_modified);
        assert_eq!(records[0].transformation, "pass-through");
    }

    #[test]
    fn audit_sanitization_multiple_keys() {
        let orig = json!({"a": "ok", "b": "bad\x00val"});
        let san = json!({"a": "ok", "b": Value::Null});
        let records = audit_sanitization(orig.as_object().unwrap(), san.as_object().unwrap());
        assert_eq!(records.len(), 2);
        let b_rec = records.iter().find(|r| r.key == "b").unwrap();
        assert!(b_rec.was_modified);
    }

    // ── DataFlowTracer ────────────────────────────────────────────────

    #[test]
    fn tracer_classifies_tool_correctly() {
        let record = DataFlowTracer::new("tid", "server", "write_file", None).finish();
        assert_eq!(record.category, ToolCategory::Write);
    }

    #[test]
    fn tracer_records_flow_stages() {
        let args = json!({"query": "hello"});
        let record = DataFlowTracer::new("tid", "brave", "search", None)
            .add_stage("sanitize", args.as_object().unwrap(), Some("clean"))
            .add_stage("invoke", args.as_object().unwrap(), None)
            .finish();
        assert_eq!(record.flow.len(), 2);
        assert_eq!(record.flow[0].stage, "sanitize");
        assert_eq!(record.flow[0].note.as_deref(), Some("clean"));
        assert_eq!(record.flow[1].stage, "invoke");
    }

    #[test]
    fn tracer_sanitization_modified_flag_set_when_changed() {
        let orig = json!({"q": "dirty\x07val"});
        let san = json!({"q": "dirtyval"});
        let record = DataFlowTracer::new("tid", "srv", "search", None)
            .record_sanitization(orig.as_object().unwrap(), san.as_object().unwrap())
            .finish();
        assert!(record.sanitization_modified);
    }

    #[test]
    fn tracer_sanitization_modified_flag_clear_when_unchanged() {
        let args = json!({"q": "clean"});
        let record = DataFlowTracer::new("tid", "srv", "search", None)
            .record_sanitization(args.as_object().unwrap(), args.as_object().unwrap())
            .finish();
        assert!(!record.sanitization_modified);
    }

    #[test]
    fn tracer_arg_hashes_in_flow_match_individual_hashes() {
        let args = json!({"query": "hello", "limit": 10});
        let record = DataFlowTracer::new("tid", "srv", "search", None)
            .add_stage("invoke", args.as_object().unwrap(), None)
            .finish();
        let stage = &record.flow[0];
        assert_eq!(
            stage.arg_hashes.get("query").map(String::as_str),
            Some(hash_argument(&json!("hello")).as_str())
        );
    }

    #[test]
    fn tool_category_ordering_read_only_lowest() {
        assert!(ToolCategory::ReadOnly < ToolCategory::Write);
        assert!(ToolCategory::Write < ToolCategory::Execute);
        assert!(ToolCategory::Execute < ToolCategory::Admin);
    }

    #[test]
    fn audit_level_matches_category() {
        assert_eq!(ToolCategory::ReadOnly.audit_level(), "debug");
        assert_eq!(ToolCategory::Write.audit_level(), "info");
        assert_eq!(ToolCategory::Execute.audit_level(), "warn");
        assert_eq!(ToolCategory::Admin.audit_level(), "error");
    }
}
