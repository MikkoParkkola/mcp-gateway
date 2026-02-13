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
use std::path::Path;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, warn};

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
struct PlaybookContext {
    /// Input arguments.
    inputs: Value,
    /// Results from completed steps, keyed by step name.
    step_results: HashMap<String, Value>,
}

impl PlaybookContext {
    fn new(inputs: Value) -> Self {
        Self {
            inputs,
            step_results: HashMap::new(),
        }
    }

    /// Resolve a variable reference like `$inputs.query` or `$search.web.results[0].title`.
    fn resolve_var(&self, var_ref: &str) -> Value {
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
    fn interpolate(&self, value: &Value) -> Value {
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
    fn interpolate_string(&self, s: &str) -> Value {
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
fn extract_var_refs(s: &str) -> Vec<String> {
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
fn evaluate_condition(condition: &str, ctx: &PlaybookContext) -> bool {
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
fn is_truthy(value: &Value) -> bool {
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

/// Engine that loads and executes playbooks.
pub struct PlaybookEngine {
    definitions: HashMap<String, PlaybookDefinition>,
}

impl PlaybookEngine {
    /// Create an empty engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            definitions: HashMap::new(),
        }
    }

    /// Load playbooks from a directory (reads all `*.yaml` files).
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be read.
    pub fn load_from_directory(&mut self, dir: &str) -> crate::Result<usize> {
        let path = Path::new(dir);
        if !path.is_dir() {
            return Ok(0);
        }

        let mut count = 0;
        for entry in std::fs::read_dir(path).map_err(|e| {
            crate::Error::Config(format!("Failed to read playbooks directory '{dir}': {e}"))
        })? {
            let entry = entry.map_err(|e| {
                crate::Error::Config(format!("Failed to read directory entry: {e}"))
            })?;

            let file_path = entry.path();
            if file_path.extension().and_then(|e| e.to_str()) == Some("yaml") {
                match std::fs::read_to_string(&file_path) {
                    Ok(content) => match serde_yaml::from_str::<PlaybookDefinition>(&content) {
                        Ok(def) => {
                            debug!(name = %def.name, path = %file_path.display(), "Loaded playbook");
                            self.definitions.insert(def.name.clone(), def);
                            count += 1;
                        }
                        Err(e) => {
                            warn!(path = %file_path.display(), error = %e, "Failed to parse playbook");
                        }
                    },
                    Err(e) => {
                        warn!(path = %file_path.display(), error = %e, "Failed to read playbook file");
                    }
                }
            }
        }

        Ok(count)
    }

    /// Register a playbook definition directly.
    pub fn register(&mut self, definition: PlaybookDefinition) {
        self.definitions.insert(definition.name.clone(), definition);
    }

    /// Get a playbook definition by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&PlaybookDefinition> {
        self.definitions.get(name)
    }

    /// List all playbook names.
    pub fn list(&self) -> Vec<&str> {
        self.definitions.keys().map(String::as_str).collect()
    }

    /// Get the number of loaded playbooks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.definitions.len()
    }

    /// Check if there are no loaded playbooks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.definitions.is_empty()
    }

    /// Execute a playbook by name.
    ///
    /// # Errors
    ///
    /// Returns an error if the playbook is not found, a step fails (with abort strategy),
    /// or the total timeout is exceeded.
    pub async fn execute(
        &self,
        name: &str,
        inputs: Value,
        invoker: &dyn ToolInvoker,
    ) -> crate::Result<PlaybookResult> {
        let definition = self.get(name).ok_or_else(|| {
            crate::Error::Config(format!("Playbook not found: {name}"))
        })?;

        self.execute_definition(definition, inputs, invoker).await
    }

    /// Execute a playbook from its definition.
    async fn execute_definition(
        &self,
        definition: &PlaybookDefinition,
        inputs: Value,
        invoker: &dyn ToolInvoker,
    ) -> crate::Result<PlaybookResult> {
        let start = Instant::now();
        let timeout = std::time::Duration::from_secs(definition.timeout);
        let mut ctx = PlaybookContext::new(inputs);

        let mut steps_completed = Vec::new();
        let mut steps_skipped = Vec::new();
        let mut steps_failed = Vec::new();

        for step in &definition.steps {
            // Check timeout
            if start.elapsed() > timeout {
                return Err(crate::Error::Internal(format!(
                    "Playbook '{}' exceeded timeout of {}s",
                    definition.name, definition.timeout
                )));
            }

            // Evaluate condition
            if let Some(ref condition) = step.condition {
                if !evaluate_condition(condition, &ctx) {
                    debug!(step = %step.name, "Step skipped (condition false)");
                    steps_skipped.push(step.name.clone());
                    continue;
                }
            }

            // Interpolate arguments
            let arguments = ctx.interpolate(&Value::Object(
                step.arguments.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            ));

            // Execute with retry
            let mut last_error = None;
            let max_attempts = if definition.on_error == ErrorStrategy::Retry {
                definition.max_retries.max(1)
            } else {
                1
            };

            let mut succeeded = false;
            for attempt in 0..max_attempts {
                if attempt > 0 {
                    debug!(step = %step.name, attempt, "Retrying step");
                }

                match invoker.invoke(&step.server, &step.tool, arguments.clone()).await {
                    Ok(result) => {
                        debug!(step = %step.name, "Step completed");
                        ctx.step_results.insert(step.name.clone(), result);
                        steps_completed.push(step.name.clone());
                        succeeded = true;
                        break;
                    }
                    Err(e) => {
                        warn!(step = %step.name, error = %e, "Step failed");
                        last_error = Some(e);
                    }
                }
            }

            if !succeeded {
                steps_failed.push(step.name.clone());
                match definition.on_error {
                    ErrorStrategy::Abort => {
                        return Err(last_error.unwrap_or_else(|| {
                            crate::Error::Internal(format!(
                                "Step '{}' failed in playbook '{}'",
                                step.name, definition.name
                            ))
                        }));
                    }
                    ErrorStrategy::Continue | ErrorStrategy::Retry => {
                        // Already retried if Retry; continue to next step.
                        ctx.step_results.insert(step.name.clone(), Value::Null);
                    }
                }
            }
        }

        // Build output
        let output = build_output(definition, &ctx);
        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(PlaybookResult {
            output,
            steps_completed,
            steps_skipped,
            steps_failed,
            duration_ms,
        })
    }
}

impl Default for PlaybookEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the final output from output mappings or raw step results.
fn build_output(definition: &PlaybookDefinition, ctx: &PlaybookContext) -> Value {
    let Some(ref output_def) = definition.output else {
        // No output mapping: return all step results.
        return Value::Object(
            ctx.step_results
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        );
    };

    let mut result = serde_json::Map::new();
    for (prop_name, mapping) in &output_def.properties {
        let resolved = ctx.resolve_var(&mapping.path);
        if resolved.is_null() {
            if let Some(ref fallback) = mapping.fallback {
                result.insert(prop_name.clone(), fallback.clone());
            } else {
                result.insert(prop_name.clone(), Value::Null);
            }
        } else {
            result.insert(prop_name.clone(), resolved);
        }
    }
    Value::Object(result)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Variable extraction ─────────────────────────────────────────────

    #[test]
    fn extract_var_refs_simple() {
        let refs = extract_var_refs("$inputs.query");
        assert_eq!(refs, vec!["$inputs.query"]);
    }

    #[test]
    fn extract_var_refs_embedded() {
        let refs = extract_var_refs("search for $inputs.query on $inputs.site");
        assert_eq!(refs, vec!["$inputs.query", "$inputs.site"]);
    }

    #[test]
    fn extract_var_refs_with_brackets() {
        let refs = extract_var_refs("$search.results[0].title");
        assert_eq!(refs, vec!["$search.results[0].title"]);
    }

    #[test]
    fn extract_var_refs_no_vars() {
        let refs = extract_var_refs("no variables here");
        assert!(refs.is_empty());
    }

    #[test]
    fn extract_var_refs_dollar_at_end() {
        let refs = extract_var_refs("cost is $");
        assert!(refs.is_empty());
    }

    // ── PlaybookContext::resolve_var ─────────────────────────────────────

    #[test]
    fn resolve_var_inputs() {
        let ctx = PlaybookContext::new(json!({"query": "rust", "count": 5}));
        assert_eq!(ctx.resolve_var("$inputs.query"), json!("rust"));
        assert_eq!(ctx.resolve_var("$inputs.count"), json!(5));
    }

    #[test]
    fn resolve_var_step_result() {
        let mut ctx = PlaybookContext::new(json!({}));
        ctx.step_results.insert(
            "search".to_string(),
            json!({"web": {"results": [{"title": "Rust"}]}}),
        );
        assert_eq!(
            ctx.resolve_var("$search.web.results[0].title"),
            json!("Rust")
        );
    }

    #[test]
    fn resolve_var_missing_step_returns_null() {
        let ctx = PlaybookContext::new(json!({}));
        assert_eq!(ctx.resolve_var("$missing.field"), Value::Null);
    }

    #[test]
    fn resolve_var_missing_field_returns_null() {
        let ctx = PlaybookContext::new(json!({"query": "rust"}));
        assert_eq!(ctx.resolve_var("$inputs.nonexistent"), Value::Null);
    }

    #[test]
    fn resolve_var_step_name_only() {
        let mut ctx = PlaybookContext::new(json!({}));
        ctx.step_results
            .insert("search".to_string(), json!({"data": 42}));
        assert_eq!(ctx.resolve_var("$search"), json!({"data": 42}));
    }

    // ── PlaybookContext::interpolate ─────────────────────────────────────

    #[test]
    fn interpolate_pure_reference() {
        let ctx = PlaybookContext::new(json!({"query": "rust"}));
        let result = ctx.interpolate(&json!("$inputs.query"));
        assert_eq!(result, json!("rust"));
    }

    #[test]
    fn interpolate_embedded_reference() {
        let ctx = PlaybookContext::new(json!({"query": "rust"}));
        let result = ctx.interpolate(&json!("search for $inputs.query"));
        assert_eq!(result, json!("search for rust"));
    }

    #[test]
    fn interpolate_object_recursion() {
        let ctx = PlaybookContext::new(json!({"q": "test", "n": 5}));
        let input = json!({"query": "$inputs.q", "count": "$inputs.n"});
        let result = ctx.interpolate(&input);
        assert_eq!(result, json!({"query": "test", "count": 5}));
    }

    #[test]
    fn interpolate_array_recursion() {
        let ctx = PlaybookContext::new(json!({"a": 1, "b": 2}));
        let input = json!(["$inputs.a", "$inputs.b"]);
        let result = ctx.interpolate(&input);
        assert_eq!(result, json!([1, 2]));
    }

    #[test]
    fn interpolate_non_string_passthrough() {
        let ctx = PlaybookContext::new(json!({}));
        assert_eq!(ctx.interpolate(&json!(42)), json!(42));
        assert_eq!(ctx.interpolate(&json!(true)), json!(true));
        assert_eq!(ctx.interpolate(&Value::Null), Value::Null);
    }

    #[test]
    fn interpolate_preserves_number_type() {
        let ctx = PlaybookContext::new(json!({"count": 5}));
        let result = ctx.interpolate(&json!("$inputs.count"));
        // Pure reference should preserve the number type
        assert_eq!(result, json!(5));
    }

    // ── evaluate_condition ──────────────────────────────────────────────

    #[test]
    fn condition_truthy_string() {
        let ctx = PlaybookContext::new(json!({"query": "rust"}));
        assert!(evaluate_condition("$inputs.query", &ctx));
    }

    #[test]
    fn condition_falsy_null() {
        let ctx = PlaybookContext::new(json!({"query": null}));
        assert!(!evaluate_condition("$inputs.query", &ctx));
    }

    #[test]
    fn condition_falsy_empty_string() {
        let ctx = PlaybookContext::new(json!({"query": ""}));
        assert!(!evaluate_condition("$inputs.query", &ctx));
    }

    #[test]
    fn condition_equality_match() {
        let ctx = PlaybookContext::new(json!({"depth": "thorough"}));
        assert!(evaluate_condition("$inputs.depth == 'thorough'", &ctx));
    }

    #[test]
    fn condition_equality_mismatch() {
        let ctx = PlaybookContext::new(json!({"depth": "quick"}));
        assert!(!evaluate_condition("$inputs.depth == 'thorough'", &ctx));
    }

    #[test]
    fn condition_length_greater_than() {
        let mut ctx = PlaybookContext::new(json!({}));
        ctx.step_results.insert(
            "search".to_string(),
            json!({"web": {"results": [1, 2, 3]}}),
        );
        assert!(evaluate_condition(
            "$search.web.results | length > 0",
            &ctx
        ));
        assert!(!evaluate_condition(
            "$search.web.results | length > 5",
            &ctx
        ));
    }

    #[test]
    fn condition_length_empty_array() {
        let mut ctx = PlaybookContext::new(json!({}));
        ctx.step_results
            .insert("search".to_string(), json!({"results": []}));
        assert!(!evaluate_condition(
            "$search.results | length > 0",
            &ctx
        ));
    }

    #[test]
    fn condition_truthy_array() {
        let mut ctx = PlaybookContext::new(json!({}));
        ctx.step_results
            .insert("s".to_string(), json!({"items": [1]}));
        assert!(evaluate_condition("$s.items", &ctx));
    }

    #[test]
    fn condition_falsy_empty_array() {
        let mut ctx = PlaybookContext::new(json!({}));
        ctx.step_results
            .insert("s".to_string(), json!({"items": []}));
        assert!(!evaluate_condition("$s.items", &ctx));
    }

    // ── is_truthy ───────────────────────────────────────────────────────

    #[test]
    fn truthy_values() {
        assert!(is_truthy(&json!(true)));
        assert!(is_truthy(&json!(1)));
        assert!(is_truthy(&json!("hello")));
        assert!(is_truthy(&json!([1])));
        assert!(is_truthy(&json!({"k": "v"})));
    }

    #[test]
    fn falsy_values() {
        assert!(!is_truthy(&Value::Null));
        assert!(!is_truthy(&json!(false)));
        assert!(!is_truthy(&json!(0)));
        assert!(!is_truthy(&json!("")));
        assert!(!is_truthy(&json!([])));
        assert!(!is_truthy(&json!({})));
    }

    // ── PlaybookEngine ──────────────────────────────────────────────────

    #[test]
    fn engine_new_is_empty() {
        let engine = PlaybookEngine::new();
        assert!(engine.is_empty());
        assert_eq!(engine.len(), 0);
    }

    #[test]
    fn engine_register_and_get() {
        let mut engine = PlaybookEngine::new();
        engine.register(PlaybookDefinition {
            playbook: "1.0".to_string(),
            name: "test".to_string(),
            description: "A test playbook".to_string(),
            inputs: json!({}),
            steps: vec![],
            output: None,
            on_error: ErrorStrategy::Abort,
            max_retries: 1,
            timeout: 60,
        });
        assert_eq!(engine.len(), 1);
        assert!(engine.get("test").is_some());
        assert!(engine.get("missing").is_none());
        assert_eq!(engine.list(), vec!["test"]);
    }

    // ── PlaybookEngine::execute (with mock invoker) ─────────────────────

    struct MockInvoker {
        responses: HashMap<String, Value>,
    }

    impl MockInvoker {
        fn new() -> Self {
            Self {
                responses: HashMap::new(),
            }
        }

        fn respond(mut self, tool: &str, response: Value) -> Self {
            self.responses.insert(tool.to_string(), response);
            self
        }
    }

    #[async_trait::async_trait]
    impl ToolInvoker for MockInvoker {
        async fn invoke(
            &self,
            _server: &str,
            tool: &str,
            _arguments: Value,
        ) -> crate::Result<Value> {
            self.responses
                .get(tool)
                .cloned()
                .ok_or_else(|| crate::Error::Internal(format!("Mock: tool not found: {tool}")))
        }
    }

    #[tokio::test]
    async fn execute_simple_playbook() {
        let mut engine = PlaybookEngine::new();
        engine.register(PlaybookDefinition {
            playbook: "1.0".to_string(),
            name: "simple".to_string(),
            description: "Simple test".to_string(),
            inputs: json!({}),
            steps: vec![PlaybookStep {
                name: "step1".to_string(),
                tool: "my_tool".to_string(),
                server: "test".to_string(),
                arguments: HashMap::from([("q".to_string(), json!("hello"))]),
                condition: None,
            }],
            output: None,
            on_error: ErrorStrategy::Abort,
            max_retries: 1,
            timeout: 60,
        });

        let invoker = MockInvoker::new().respond("my_tool", json!({"result": "world"}));
        let result = engine.execute("simple", json!({}), &invoker).await.unwrap();
        assert_eq!(result.steps_completed, vec!["step1"]);
        assert!(result.steps_failed.is_empty());
        assert_eq!(result.output["step1"], json!({"result": "world"}));
    }

    #[tokio::test]
    async fn execute_with_variable_interpolation() {
        let mut engine = PlaybookEngine::new();
        engine.register(PlaybookDefinition {
            playbook: "1.0".to_string(),
            name: "interp".to_string(),
            description: "Interpolation test".to_string(),
            inputs: json!({}),
            steps: vec![
                PlaybookStep {
                    name: "search".to_string(),
                    tool: "brave_search".to_string(),
                    server: "cap".to_string(),
                    arguments: HashMap::from([("query".to_string(), json!("$inputs.query"))]),
                    condition: None,
                },
                PlaybookStep {
                    name: "ground".to_string(),
                    tool: "brave_grounding".to_string(),
                    server: "cap".to_string(),
                    arguments: HashMap::from([(
                        "query".to_string(),
                        json!("$search.top_result"),
                    )]),
                    condition: None,
                },
            ],
            output: Some(PlaybookOutput {
                output_type: "object".to_string(),
                properties: HashMap::from([
                    (
                        "answer".to_string(),
                        OutputMapping {
                            path: "$ground.answer".to_string(),
                            fallback: Some(json!("No answer")),
                        },
                    ),
                    (
                        "query".to_string(),
                        OutputMapping {
                            path: "$search.top_result".to_string(),
                            fallback: None,
                        },
                    ),
                ]),
            }),
            on_error: ErrorStrategy::Abort,
            max_retries: 1,
            timeout: 60,
        });

        let invoker = MockInvoker::new()
            .respond("brave_search", json!({"top_result": "Rust Language"}))
            .respond("brave_grounding", json!({"answer": "Rust is great"}));

        let result = engine
            .execute("interp", json!({"query": "Rust"}), &invoker)
            .await
            .unwrap();

        assert_eq!(result.steps_completed, vec!["search", "ground"]);
        assert_eq!(result.output["answer"], json!("Rust is great"));
        assert_eq!(result.output["query"], json!("Rust Language"));
    }

    #[tokio::test]
    async fn execute_with_condition_skip() {
        let mut engine = PlaybookEngine::new();
        engine.register(PlaybookDefinition {
            playbook: "1.0".to_string(),
            name: "cond".to_string(),
            description: "Condition test".to_string(),
            inputs: json!({}),
            steps: vec![
                PlaybookStep {
                    name: "always".to_string(),
                    tool: "tool_a".to_string(),
                    server: "s".to_string(),
                    arguments: HashMap::new(),
                    condition: None,
                },
                PlaybookStep {
                    name: "conditional".to_string(),
                    tool: "tool_b".to_string(),
                    server: "s".to_string(),
                    arguments: HashMap::new(),
                    condition: Some("$inputs.deep == 'true'".to_string()),
                },
            ],
            output: None,
            on_error: ErrorStrategy::Abort,
            max_retries: 1,
            timeout: 60,
        });

        let invoker = MockInvoker::new()
            .respond("tool_a", json!({"ok": true}))
            .respond("tool_b", json!({"deep": true}));

        // With condition false
        let result = engine
            .execute("cond", json!({"deep": "false"}), &invoker)
            .await
            .unwrap();
        assert_eq!(result.steps_completed, vec!["always"]);
        assert_eq!(result.steps_skipped, vec!["conditional"]);

        // With condition true
        let result = engine
            .execute("cond", json!({"deep": "true"}), &invoker)
            .await
            .unwrap();
        assert_eq!(result.steps_completed, vec!["always", "conditional"]);
        assert!(result.steps_skipped.is_empty());
    }

    #[tokio::test]
    async fn execute_abort_on_error() {
        let mut engine = PlaybookEngine::new();
        engine.register(PlaybookDefinition {
            playbook: "1.0".to_string(),
            name: "abort_test".to_string(),
            description: "Abort test".to_string(),
            inputs: json!({}),
            steps: vec![
                PlaybookStep {
                    name: "fail".to_string(),
                    tool: "nonexistent".to_string(),
                    server: "s".to_string(),
                    arguments: HashMap::new(),
                    condition: None,
                },
                PlaybookStep {
                    name: "never_reached".to_string(),
                    tool: "tool_a".to_string(),
                    server: "s".to_string(),
                    arguments: HashMap::new(),
                    condition: None,
                },
            ],
            output: None,
            on_error: ErrorStrategy::Abort,
            max_retries: 1,
            timeout: 60,
        });

        let invoker = MockInvoker::new().respond("tool_a", json!({"ok": true}));
        let err = engine
            .execute("abort_test", json!({}), &invoker)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("nonexistent"));
    }

    #[tokio::test]
    async fn execute_continue_on_error() {
        let mut engine = PlaybookEngine::new();
        engine.register(PlaybookDefinition {
            playbook: "1.0".to_string(),
            name: "continue_test".to_string(),
            description: "Continue test".to_string(),
            inputs: json!({}),
            steps: vec![
                PlaybookStep {
                    name: "fail".to_string(),
                    tool: "nonexistent".to_string(),
                    server: "s".to_string(),
                    arguments: HashMap::new(),
                    condition: None,
                },
                PlaybookStep {
                    name: "after_fail".to_string(),
                    tool: "tool_a".to_string(),
                    server: "s".to_string(),
                    arguments: HashMap::new(),
                    condition: None,
                },
            ],
            output: None,
            on_error: ErrorStrategy::Continue,
            max_retries: 1,
            timeout: 60,
        });

        let invoker = MockInvoker::new().respond("tool_a", json!({"ok": true}));
        let result = engine
            .execute("continue_test", json!({}), &invoker)
            .await
            .unwrap();
        assert_eq!(result.steps_failed, vec!["fail"]);
        assert_eq!(result.steps_completed, vec!["after_fail"]);
    }

    #[tokio::test]
    async fn execute_output_with_fallback() {
        let mut engine = PlaybookEngine::new();
        engine.register(PlaybookDefinition {
            playbook: "1.0".to_string(),
            name: "fallback_test".to_string(),
            description: "Fallback test".to_string(),
            inputs: json!({}),
            steps: vec![PlaybookStep {
                name: "step1".to_string(),
                tool: "tool_a".to_string(),
                server: "s".to_string(),
                arguments: HashMap::new(),
                condition: None,
            }],
            output: Some(PlaybookOutput {
                output_type: "object".to_string(),
                properties: HashMap::from([
                    (
                        "found".to_string(),
                        OutputMapping {
                            path: "$step1.data".to_string(),
                            fallback: None,
                        },
                    ),
                    (
                        "missing".to_string(),
                        OutputMapping {
                            path: "$step1.nonexistent".to_string(),
                            fallback: Some(json!("default_value")),
                        },
                    ),
                    (
                        "null_no_fallback".to_string(),
                        OutputMapping {
                            path: "$step1.nonexistent".to_string(),
                            fallback: None,
                        },
                    ),
                ]),
            }),
            on_error: ErrorStrategy::Abort,
            max_retries: 1,
            timeout: 60,
        });

        let invoker = MockInvoker::new().respond("tool_a", json!({"data": "found_it"}));
        let result = engine
            .execute("fallback_test", json!({}), &invoker)
            .await
            .unwrap();

        assert_eq!(result.output["found"], json!("found_it"));
        assert_eq!(result.output["missing"], json!("default_value"));
        assert_eq!(result.output["null_no_fallback"], Value::Null);
    }

    #[tokio::test]
    async fn execute_playbook_not_found() {
        let engine = PlaybookEngine::new();
        let invoker = MockInvoker::new();
        let err = engine
            .execute("nonexistent", json!({}), &invoker)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Playbook not found"));
    }

    // ── YAML deserialization ────────────────────────────────────────────

    #[test]
    fn deserialize_playbook_from_yaml() {
        let yaml = r#"
playbook: "1.0"
name: research_topic
description: Search and ground a topic
inputs:
  type: object
  properties:
    query:
      type: string
  required: [query]
steps:
  - name: search
    tool: brave_search
    server: capabilities
    arguments:
      query: "$inputs.query"
      count: 5
  - name: ground
    tool: brave_grounding
    server: capabilities
    arguments:
      query: "$search.web.results[0].title"
    condition: "$search.web.results | length > 0"
output:
  type: object
  properties:
    summary:
      path: "$ground.answer"
      fallback: "No grounding available"
    sources:
      path: "$search.web.results[].url"
on_error: continue
max_retries: 2
timeout: 30
"#;
        let def: PlaybookDefinition = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(def.name, "research_topic");
        assert_eq!(def.steps.len(), 2);
        assert_eq!(def.steps[0].name, "search");
        assert_eq!(def.steps[1].condition, Some("$search.web.results | length > 0".to_string()));
        assert!(def.output.is_some());
        assert_eq!(def.on_error, ErrorStrategy::Continue);
        assert_eq!(def.max_retries, 2);
        assert_eq!(def.timeout, 30);
    }

    #[test]
    fn deserialize_minimal_playbook() {
        let yaml = r#"
name: minimal
description: Minimal playbook
steps:
  - name: step1
    tool: some_tool
"#;
        let def: PlaybookDefinition = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(def.name, "minimal");
        assert_eq!(def.playbook, "1.0");
        assert_eq!(def.on_error, ErrorStrategy::Abort);
        assert_eq!(def.max_retries, 1);
        assert_eq!(def.timeout, 60);
        assert_eq!(def.steps[0].server, "capabilities");
    }

    // ── build_output ────────────────────────────────────────────────────

    #[test]
    fn build_output_no_mapping_returns_all_results() {
        let def = PlaybookDefinition {
            playbook: "1.0".to_string(),
            name: "test".to_string(),
            description: "test".to_string(),
            inputs: json!({}),
            steps: vec![],
            output: None,
            on_error: ErrorStrategy::Abort,
            max_retries: 1,
            timeout: 60,
        };
        let mut ctx = PlaybookContext::new(json!({}));
        ctx.step_results
            .insert("s1".to_string(), json!({"data": 1}));

        let output = build_output(&def, &ctx);
        assert_eq!(output["s1"], json!({"data": 1}));
    }
}
