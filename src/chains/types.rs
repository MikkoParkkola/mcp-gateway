//! Core types for durable capability chains.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ============================================================================
// Chain definition
// ============================================================================

/// A named sequence of tool invocation steps.
///
/// # Example
///
/// ```rust
/// use mcp_gateway::chains::{Chain, ChainStep};
/// use serde_json::json;
///
/// let chain = Chain::new("my-chain")
///     .step(ChainStep::new("search", "brave_search")
///         .input(json!({"query": "Rust async"})));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chain {
    /// Unique chain identifier (stable across resumptions).
    pub id: String,
    /// Ordered steps to execute.
    pub steps: Vec<ChainStep>,
    /// Optional total timeout in seconds (default: 300).
    #[serde(default = "default_chain_timeout")]
    pub timeout_secs: u64,
}

fn default_chain_timeout() -> u64 {
    300
}

impl Chain {
    /// Create a new chain with the given ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            steps: Vec::new(),
            timeout_secs: default_chain_timeout(),
        }
    }

    /// Append a step, returning `self` for fluent construction.
    #[must_use]
    pub fn step(mut self, step: ChainStep) -> Self {
        self.steps.push(step);
        self
    }

    /// Override the total timeout.
    #[must_use]
    pub fn timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }
}

// ============================================================================
// Step definition
// ============================================================================

/// A single tool invocation within a chain.
///
/// Inputs support `$step_name.json.path` variable interpolation referencing
/// outputs from earlier steps.
///
/// # Example
///
/// ```rust
/// use mcp_gateway::chains::ChainStep;
/// use serde_json::json;
///
/// let step = ChainStep::new("extract", "brave_grounding")
///     .server("capabilities")
///     .input(json!({"query": "$search.results[0].title"}));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStep {
    /// Step name — used as variable namespace (`$name.path`).
    pub name: String,
    /// Tool to invoke.
    pub tool: String,
    /// Backend server (default: `"capabilities"`).
    #[serde(default = "default_step_server")]
    pub server: String,
    /// Tool input arguments (supports variable interpolation).
    #[serde(default)]
    pub input: Value,
    /// Whether this step may be skipped on failure (default: false).
    #[serde(default)]
    pub optional: bool,
}

fn default_step_server() -> String {
    "capabilities".to_string()
}

impl ChainStep {
    /// Create a step with name and tool, using the default server.
    #[must_use]
    pub fn new(name: impl Into<String>, tool: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            tool: tool.into(),
            server: default_step_server(),
            input: Value::Object(serde_json::Map::new()),
            optional: false,
        }
    }

    /// Override the backend server.
    #[must_use]
    pub fn server(mut self, server: impl Into<String>) -> Self {
        self.server = server.into();
        self
    }

    /// Set the input arguments.
    #[must_use]
    pub fn input(mut self, input: Value) -> Self {
        self.input = input;
        self
    }

    /// Mark this step as optional (failures are skipped rather than aborting).
    #[must_use]
    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }
}

// ============================================================================
// Runtime state
// ============================================================================

/// Execution state of a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainState {
    /// Not yet started.
    Pending,
    /// Currently executing.
    Running,
    /// All steps completed successfully.
    Completed,
    /// One or more steps failed and chain was aborted.
    Failed,
    /// Partially completed — can be resumed.
    Partial,
}

/// Execution state of a single step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    /// Not yet started.
    Pending,
    /// Completed successfully.
    Completed,
    /// Failed (and not skipped).
    Failed,
    /// Skipped (optional step that failed).
    Skipped,
}

// ============================================================================
// Checkpoint
// ============================================================================

/// Serializable checkpoint capturing state at a step boundary.
///
/// Stored as one JSONL record per completed step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainCheckpoint {
    /// Chain ID this checkpoint belongs to.
    pub chain_id: String,
    /// Step name that was completed.
    pub step_name: String,
    /// Step output value.
    pub output: Value,
    /// Number of attempts taken.
    pub attempts: u32,
    /// Wall-clock timestamp when this step completed.
    pub completed_at: DateTime<Utc>,
    /// Step execution duration in milliseconds.
    pub duration_ms: u64,
}

// ============================================================================
// Step result (runtime)
// ============================================================================

/// Result of a single step execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStepResult {
    /// Step name.
    pub name: String,
    /// Final state.
    pub state: StepState,
    /// Output (None if failed/skipped).
    pub output: Option<Value>,
    /// Error message if failed.
    pub error: Option<String>,
    /// Attempts taken.
    pub attempts: u32,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

// ============================================================================
// Chain result
// ============================================================================

/// Result of executing (or resuming) a chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainResult {
    /// Chain ID.
    pub chain_id: String,
    /// Final chain state.
    pub state: ChainState,
    /// Per-step results.
    pub steps: Vec<ChainStepResult>,
    /// Combined outputs keyed by step name.
    pub outputs: HashMap<String, Value>,
    /// Total execution duration in milliseconds (this run only).
    pub duration_ms: u64,
    /// Number of steps resumed from checkpoint.
    pub resumed_steps: usize,
}

impl ChainResult {
    /// Return `true` if all required steps completed successfully.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.state == ChainState::Completed
    }
}
