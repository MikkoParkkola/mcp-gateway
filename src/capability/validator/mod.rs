//! Structural validator for capability YAML definitions.
//!
//! Catches schema format errors, malformed providers, dangling URL placeholders,
//! and other structural issues that cause silent runtime failures.
//!
//! # Design
//!
//! Validation is split into independent checks, each returning zero or more
//! [`Issue`] items.  A single pass collects all issues so the caller receives a
//! complete picture rather than stopping at the first error.
//!
//! Checks are categorised by [`IssueSeverity`]:
//! - `Error` — the capability **cannot** function correctly.
//! - `Warning` — the capability may function but has a structural smell.
//!
//! # Example
//!
//! ```rust
//! use mcp_gateway::capability::validator::{validate_capability_definition, IssueSeverity};
//! use mcp_gateway::capability::CapabilityDefinition;
//!
//! let yaml = r#"
//! name: my_tool
//! description: Does something useful.
//! providers:
//!   primary:
//!     config:
//!       base_url: https://api.example.com
//!       path: /v1/items/{id}
//! schema:
//!   input:
//!     type: object
//!     properties:
//!       id:
//!         type: string
//!         description: The item identifier
//! "#;
//!
//! let cap: CapabilityDefinition = serde_yaml::from_str(yaml).unwrap();
//! let issues = validate_capability_definition(&cap, None);
//! assert!(issues.iter().all(|i| i.severity == IssueSeverity::Warning));
//! ```

use std::collections::HashMap;

use super::CapabilityDefinition;

mod checks;

#[cfg(test)]
mod tests;

// ── Public types ──────────────────────────────────────────────────────────────

/// Severity of a structural validation issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IssueSeverity {
    /// The capability cannot function correctly; it will be skipped at load time.
    Error,
    /// The capability may work but has a structural smell that should be fixed.
    Warning,
}

impl std::fmt::Display for IssueSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Error => f.write_str("ERROR"),
            Self::Warning => f.write_str("WARN"),
        }
    }
}

/// A single structural validation finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    /// Severity level.
    pub severity: IssueSeverity,
    /// Short code identifying the check (e.g. `"CAP-001"`).
    pub code: &'static str,
    /// Human-readable description of the issue.
    pub message: String,
    /// Optional YAML field path for context (e.g. `"schema.input"`).
    pub field: Option<&'static str>,
}

impl Issue {
    pub(crate) fn error(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: IssueSeverity::Error,
            code,
            message: message.into(),
            field: None,
        }
    }

    pub(crate) fn warning(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: IssueSeverity::Warning,
            code,
            message: message.into(),
            field: None,
        }
    }

    pub(crate) fn with_field(mut self, field: &'static str) -> Self {
        self.field = Some(field);
        self
    }
}

impl std::fmt::Display for Issue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(field) = self.field {
            write!(
                f,
                "[{}] {} ({}): {}",
                self.severity, self.code, field, self.message
            )
        } else {
            write!(f, "[{}] {}: {}", self.severity, self.code, self.message)
        }
    }
}

// ── Entry points ──────────────────────────────────────────────────────────────

/// Validate a single parsed capability definition.
///
/// `file_path` is used only in duplicate-detection messages; pass `None` when
/// validating in isolation (e.g., from `cap validate`).
///
/// Returns all [`Issue`]s found across every structural check.  An empty vec
/// means the definition is structurally sound.
#[must_use]
pub fn validate_capability_definition(
    cap: &CapabilityDefinition,
    file_path: Option<&str>,
) -> Vec<Issue> {
    let mut issues = Vec::new();

    checks::check_name(&cap.name, &mut issues);
    checks::check_description(&cap.description, &mut issues);
    checks::check_schema_input(&cap.schema.input, &mut issues);
    checks::check_schema_output(&cap.schema.output, &mut issues);
    checks::check_providers(cap, &mut issues);

    if let Some(path) = file_path {
        checks::check_path_label(path, &cap.name, &mut issues);
    }

    issues
}

/// Validate a set of capabilities loaded from one or more directories.
///
/// Runs per-capability checks on every definition and then cross-capability
/// duplicate-name detection.
///
/// Returns a map from capability name to its list of issues.  Only capabilities
/// that have at least one issue appear in the map.
#[must_use]
pub fn validate_capabilities(
    caps: &[(String, CapabilityDefinition)], // (file_path, definition)
) -> HashMap<String, Vec<Issue>> {
    let mut results: HashMap<String, Vec<Issue>> = HashMap::new();

    for (path, cap) in caps {
        let issues = validate_capability_definition(cap, Some(path));
        if !issues.is_empty() {
            results.insert(path.clone(), issues);
        }
    }

    // Cross-capability: duplicate name detection
    let duplicate_issues = checks::check_duplicate_names(caps);
    for (path, issue) in duplicate_issues {
        results.entry(path).or_default().push(issue);
    }

    results
}
