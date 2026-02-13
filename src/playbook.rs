//! Playbook engine for multi-step tool chains.
//!
//! A playbook collapses multiple sequential tool calls into a single
//! meta-tool invocation, eliminating round-trip framing overhead.
//!
//! ```text
//! Agent calls: gateway_run_playbook(name="research", inputs={query: "Rust MCP"})
//!       │
//!       ▼
//! ┌──────────────────────────────────────────────────┐
//! │  Playbook Engine                                  │
//! │  Step 1: brave_search(query=$inputs.query)        │
//! │  Step 2: brave_grounding(query=$search.result)    │
//! │  Return: collapsed result                         │
//! └──────────────────────────────────────────────────┘
//! ```

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::transform::{parse_json_path, resolve_path_single};

// ============================================================================
// Configuration types (deserialized from YAML)
// ============================================================================

/// A playbook definition loaded from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookDefinition {
    /// Format version.
    #[serde(default = "default_playbook_version")]
    pub playbook: String,

    /// Unique name (becomes the tool name: `gateway_run_{name}`).
    pub name: String,

    /// Human-readable description.
    pub description: String,

    /// Input schema (JSON Schema).
    #[serde(default)]
    pub inputs: Value,

    /// Ordered execution steps.
    pub steps: Vec<PlaybookStep>,

    /// Output mapping.
    #[serde(default)]
    pub output: Option<PlaybookOutput>,

    /// Error handling strategy.
    #[serde(default = "default_on_error")]
    pub on_error: ErrorStrategy,

    /// Maximum retries per step.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Total timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

fn default_playbook_version() -> String {
    "1.0".to_string()
}

fn default_on_error() -> ErrorStrategy {
    ErrorStrategy::Abort
}

const fn default_max_retries() -> u32 {
    1
}

const fn default_timeout() -> u64 {
    60
}

/// A single step in a playbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStep {
    /// Step name (used as variable prefix: `$name.path`).
    pub name: String,

    /// Tool to invoke.
    pub tool: String,

    /// Server/backend that hosts the tool.
    #[serde(default = "default_server")]
    pub server: String,

    /// Arguments with variable interpolation (`$step.path` syntax).
    #[serde(default)]
    pub arguments: HashMap<String, Value>,

    /// Condition expression (skip step if evaluates to false).
    #[serde(default)]
    pub condition: Option<String>,
}

fn default_server() -> String {
    "capabilities".to_string()
}

/// Output mapping definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookOutput {
    /// JSON Schema type.
    #[serde(rename = "type", default)]
    pub output_type: String,

    /// Property mappings.
    #[serde(default)]
    pub properties: HashMap<String, OutputMapping>,
}

/// Single output field mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputMapping {
    /// Variable path to extract (`$step.json.path`).
    pub path: String,

    /// Fallback value if path resolves to null.
    #[serde(default)]
    pub fallback: Option<Value>,
}

/// Error handling strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ErrorStrategy {
    /// Stop playbook on first error.
    Abort,
    /// Skip failed step, continue with next.
    Continue,
    /// Retry failed step up to `max_retries`.
    Retry,
}

// ============================================================================
// Runtime context
// ============================================================================

/// Runtime state during playbook execution.
pub(crate) struct PlaybookContext {
    /// Input arguments.
    pub(crate) inputs: Value,
    /// Results from completed steps, keyed by step name.
    pub(crate) step_results: HashMap<String, Value>,
}

impl PlaybookContext {
    pub(crate) fn new(inputs: Value) -> Self {
        Self {
            inputs,
            step_results: HashMap::new(),
        }
    }

    /// Resolve a variable reference like `$inputs.query` or `$search.web.results[0].title`.
    pub(crate) fn resolve_var(&self, var_ref: &str) -> Value {
        let trimmed = var_ref.trim_start_matches('$');
        let (step_name, remainder) = trimmed
            .split_once('.')
            .unwrap_or((trimmed, ""));

        let source = if step_name == "inputs" {
            &self.inputs
        } else {
            match self.step_results.get(step_name) {
                Some(v) => v,
                None => return Value::Null,
            }
        };

        if remainder.is_empty() {
            return source.clone();
        }

        let path = parse_json_path(remainder);
        resolve_path_single(source, &path)
    }

    /// Interpolate variable references in a JSON value.
    ///
    /// String values starting with `$` are fully resolved.
    /// Strings containing `$var` embedded in text get string interpolation.
    pub(crate) fn interpolate(&self, value: &Value) -> Value {
        match value {
            Value::String(s) => self.interpolate_string(s),
            Value::Object(map) => {
                let interpolated: serde_json::Map<String, Value> = map
                    .iter()
                    .map(|(k, v)| (k.clone(), self.interpolate(v)))
                    .collect();
                Value::Object(interpolated)
            }
            Value::Array(arr) => {
                Value::Array(arr.iter().map(|v| self.interpolate(v)).collect())
            }
            other => other.clone(),
        }
    }

    /// Interpolate a string value.
    ///
    /// - Pure reference (`"$inputs.query"`) returns the resolved value as-is (preserving type).
    /// - Embedded references (`"search for $inputs.query"`) render as string.
    pub(crate) fn interpolate_string(&self, s: &str) -> Value {
        let trimmed = s.trim();

        // Pure variable reference: return the resolved value directly.
        if trimmed.starts_with('$') && !trimmed.contains(' ') && !trimmed.contains('+') {
            return self.resolve_var(trimmed);
        }

        // Embedded references: replace all `$var.path` occurrences.
        let mut result = s.to_string();
        let var_refs = extract_var_refs(s);
        for var_ref in var_refs {
            let resolved = self.resolve_var(&var_ref);
            let replacement = match &resolved {
                Value::String(sv) => sv.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                Value::Null => String::new(),
                other => other.to_string(),
            };
            result = result.replace(&var_ref, &replacement);
        }
        Value::String(result)
    }
}

/// Extract all `$var.path` references from a string.
pub(crate) fn extract_var_refs(s: &str) -> Vec<String> {
    let mut refs = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '$' {
            let start = i;
            i += 1;
            // Consume identifier: [a-zA-Z0-9_.\[\]]
            while i < chars.len()
                && (chars[i].is_alphanumeric()
                    || chars[i] == '_'
                    || chars[i] == '.'
                    || chars[i] == '['
                    || chars[i] == ']')
            {
                i += 1;
            }
            if i > start + 1 {
                refs.push(chars[start..i].iter().collect());
            }
        } else {
            i += 1;
        }
    }
    refs
}

// ============================================================================
// Condition evaluator
// ============================================================================

/// Evaluate a simple condition expression against the playbook context.
///
/// Supported forms:
/// - `"$var.path"` -- truthy check (non-null, non-empty, non-false).
/// - `"$var.path == 'value'"` -- string equality.
/// - `"$var.path | length > 0"` -- array/string length comparison.
pub(crate) fn evaluate_condition(condition: &str, ctx: &PlaybookContext) -> bool {
    let trimmed = condition.trim();

    // Length comparison: "$var | length > N"
    if let Some((var_part, rest)) = trimmed.split_once('|') {
        let var_ref = var_part.trim();
        let resolved = ctx.resolve_var(var_ref);
        let rest = rest.trim();

        if let Some(len_expr) = rest.strip_prefix("length") {
            let len_expr = len_expr.trim();
            let actual_len = match &resolved {
                Value::Array(arr) => arr.len(),
                Value::String(s) => s.len(),
                Value::Object(map) => map.len(),
                _ => 0,
            };

            if let Some(threshold) = len_expr.strip_prefix('>') {
                if let Ok(n) = threshold.trim().parse::<usize>() {
                    return actual_len > n;
                }
            } else if let Some(threshold) = len_expr.strip_prefix(">=") {
                if let Ok(n) = threshold.trim().parse::<usize>() {
                    return actual_len >= n;
                }
            }
        }

        return is_truthy(&ctx.resolve_var(var_ref));
    }

    // Equality: "$var == 'value'" or "$var == \"value\""
    if let Some((lhs, rhs)) = trimmed.split_once("==") {
        let lhs_val = ctx.resolve_var(lhs.trim());
        let rhs_str = rhs.trim().trim_matches('\'').trim_matches('"');
        return match &lhs_val {
            Value::String(s) => s == rhs_str,
            Value::Number(n) => n.to_string() == rhs_str,
            Value::Bool(b) => b.to_string() == rhs_str,
            _ => false,
        };
    }

    // Simple truthy check.
    is_truthy(&ctx.resolve_var(trimmed))
}

/// Check if a JSON value is "truthy".
pub(crate) fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(arr) => !arr.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

// ============================================================================
// Playbook result
// ============================================================================

/// Result of a playbook execution.
#[derive(Debug, Clone, Serialize)]
pub struct PlaybookResult {
    /// Final output (after output mapping).
    pub output: Value,
    /// Steps that executed successfully.
    pub steps_completed: Vec<String>,
    /// Steps that were skipped (condition=false).
    pub steps_skipped: Vec<String>,
    /// Steps that failed.
    pub steps_failed: Vec<String>,
    /// Total execution time in milliseconds.
    pub duration_ms: u64,
}

// ============================================================================
// Playbook engine
// ============================================================================

/// Trait for invoking tools (allows mocking in tests).
#[async_trait::async_trait]
pub trait ToolInvoker: Send + Sync {
    /// Invoke a tool on a server with the given arguments.
    async fn invoke(&self, server: &str, tool: &str, arguments: Value) -> crate::Result<Value>;
}

pub mod engine;
pub use engine::PlaybookEngine;
