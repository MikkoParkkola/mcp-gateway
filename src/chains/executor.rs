//! Chain execution engine with checkpoint/retry/observability.
//!
//! [`ChainExecutor`] orchestrates the full lifecycle of a [`Chain`]:
//! 1. Load prior checkpoints (for resume).
//! 2. For each step, if a checkpoint exists, restore it.
//! 3. Otherwise execute the step with retry.
//! 4. Persist each successful step to disk.
//! 5. Emit structured observability events throughout.
//!
//! # Variable Interpolation
//!
//! Step inputs support `$step_name.json.path` references to prior step outputs,
//! mirroring the playbook engine's interpolation syntax.
//!
//! # Example
//!
//! ```rust,no_run
//! use mcp_gateway::chains::{Chain, ChainExecutor, ChainRetryPolicy, ChainStep};
//! use mcp_gateway::playbook::ToolInvoker;
//! use serde_json::{Value, json};
//! use std::time::Duration;
//!
//! async fn run_example(invoker: &dyn ToolInvoker) {
//!     let executor = ChainExecutor::with_temp_store().unwrap();
//!     let chain = Chain::new("demo-001")
//!         .step(ChainStep::new("search", "brave_search")
//!             .input(json!({"query": "MCP gateway"})));
//!     let result = executor.execute(&chain, json!({}), invoker).await.unwrap();
//!     assert!(result.is_success());
//! }
//! ```

use std::collections::HashMap;
use std::time::Instant;

use serde_json::Value;

use crate::chains::checkpoint::ChainCheckpointStore;
use crate::chains::interpolation::interpolate_inputs;
use crate::chains::observability::ChainObservability;
use crate::chains::retry::{ChainRetryPolicy, retry_step};
use crate::chains::types::{
    Chain, ChainCheckpoint, ChainResult, ChainState, ChainStepResult, StepState,
};
use crate::playbook::ToolInvoker;
use crate::{Error, Result};

// ============================================================================
// ChainExecutor
// ============================================================================

/// Executes chains with checkpoint/retry/observability.
///
/// # Thread safety
///
/// `ChainExecutor` is `Clone + Send + Sync` — clone it freely for use
/// across tasks.
#[derive(Clone)]
pub struct ChainExecutor {
    store: ChainCheckpointStore,
    retry_policy: ChainRetryPolicy,
}

impl ChainExecutor {
    /// Create an executor with an explicit checkpoint store and retry policy.
    #[must_use]
    pub fn new(store: ChainCheckpointStore, retry_policy: ChainRetryPolicy) -> Self {
        Self {
            store,
            retry_policy,
        }
    }

    /// Create an executor using the default store (`~/.mcp-gateway/chains/`).
    ///
    /// # Errors
    ///
    /// Returns `Error::Config` if the home directory cannot be determined.
    pub fn with_default_store() -> Result<Self> {
        Ok(Self::new(
            ChainCheckpointStore::default_store()?,
            ChainRetryPolicy::default(),
        ))
    }

    /// Create an executor using a temporary directory (useful in tests).
    ///
    /// # Errors
    ///
    /// Returns `Error::Io` if the temp dir cannot be created.
    pub fn with_temp_store() -> Result<Self> {
        let tmp = std::env::temp_dir().join(format!("mcp-gateway-chains-{}", uuid::Uuid::new_v4()));
        Ok(Self::new(
            ChainCheckpointStore::new(&tmp)?,
            ChainRetryPolicy::default(),
        ))
    }

    /// Execute a chain from scratch or resume from the last checkpoint.
    ///
    /// `chain_inputs` are top-level values available as `$inputs.key` in
    /// step argument interpolation.
    ///
    /// # Errors
    ///
    /// Returns `Error::Internal` on timeout or when a required step exhausts
    /// all retry attempts.
    #[allow(clippy::cast_possible_truncation, clippy::too_many_lines)]
    pub async fn execute(
        &self,
        chain: &Chain,
        chain_inputs: Value,
        invoker: &dyn ToolInvoker,
    ) -> Result<ChainResult> {
        let obs = ChainObservability::new(&chain.id);
        let prior = self.store.load_map(&chain.id).await?;
        let run_start = Instant::now();

        let resumed_steps = prior.len();
        let remaining = chain.steps.len().saturating_sub(resumed_steps);

        if resumed_steps > 0 {
            obs.chain_resumed(resumed_steps, remaining);
        } else {
            obs.chain_started(chain.steps.len());
        }

        let timeout = std::time::Duration::from_secs(chain.timeout_secs);
        let mut outputs: HashMap<String, Value> = prior
            .iter()
            .map(|(k, v)| (k.clone(), v.output.clone()))
            .collect();

        let mut step_results: Vec<ChainStepResult> = Vec::with_capacity(chain.steps.len());
        let mut total_resumed = 0usize;

        for (idx, step) in chain.steps.iter().enumerate() {
            // Timeout guard
            if run_start.elapsed() > timeout {
                let elapsed_ms = run_start.elapsed().as_millis() as u64;
                obs.chain_timed_out(chain.timeout_secs, elapsed_ms);
                return Err(Error::Internal(format!(
                    "Chain '{}' exceeded timeout of {}s",
                    chain.id, chain.timeout_secs
                )));
            }

            // Restore from checkpoint if available
            if let Some(cp) = prior.get(&step.name) {
                obs.step_restored(&step.name);
                total_resumed += 1;
                step_results.push(ChainStepResult {
                    name: step.name.clone(),
                    state: StepState::Completed,
                    output: Some(cp.output.clone()),
                    error: None,
                    attempts: cp.attempts,
                    duration_ms: cp.duration_ms,
                });
                continue;
            }

            obs.step_started(&step.name, idx, chain.steps.len());

            // Interpolate step inputs
            let interpolated = interpolate_inputs(&step.input, &outputs, &chain_inputs);

            let step_start = Instant::now();
            let server = step.server.clone();
            let tool = step.tool.clone();
            let invoker_ref = invoker;

            let retry_result = retry_step(&self.retry_policy, &step.name, || {
                let args = interpolated.clone();
                let srv = server.clone();
                let tl = tool.clone();
                async move { invoker_ref.invoke(&srv, &tl, args).await }
            })
            .await;

            let duration_ms = step_start.elapsed().as_millis() as u64;

            match retry_result {
                Ok((output, attempts)) => {
                    obs.step_completed(&step.name, idx, attempts, duration_ms);

                    // Persist checkpoint
                    self.store
                        .append(&ChainCheckpoint {
                            chain_id: chain.id.clone(),
                            step_name: step.name.clone(),
                            output: output.clone(),
                            attempts,
                            completed_at: chrono::Utc::now(),
                            duration_ms,
                        })
                        .await?;

                    outputs.insert(step.name.clone(), output.clone());
                    step_results.push(ChainStepResult {
                        name: step.name.clone(),
                        state: StepState::Completed,
                        output: Some(output),
                        error: None,
                        attempts,
                        duration_ms,
                    });
                }
                Err(e) if step.optional => {
                    let err_msg = e.to_string();
                    obs.step_skipped(&step.name, &err_msg);
                    step_results.push(ChainStepResult {
                        name: step.name.clone(),
                        state: StepState::Skipped,
                        output: None,
                        error: Some(err_msg),
                        attempts: self.retry_policy.max_attempts,
                        duration_ms,
                    });
                }
                Err(e) => {
                    let err_msg = e.to_string();
                    obs.step_failed(&step.name, self.retry_policy.max_attempts, &err_msg);
                    step_results.push(ChainStepResult {
                        name: step.name.clone(),
                        state: StepState::Failed,
                        output: None,
                        error: Some(err_msg.clone()),
                        attempts: self.retry_policy.max_attempts,
                        duration_ms,
                    });

                    let total_duration = run_start.elapsed().as_millis() as u64;
                    obs.chain_failed(&step.name, total_duration);

                    return Ok(ChainResult {
                        chain_id: chain.id.clone(),
                        state: ChainState::Failed,
                        steps: step_results,
                        outputs,
                        duration_ms: total_duration,
                        resumed_steps: total_resumed,
                    });
                }
            }
        }

        let duration_ms = run_start.elapsed().as_millis() as u64;
        let steps_done = step_results
            .iter()
            .filter(|s| s.state == StepState::Completed)
            .count();
        let steps_skipped = step_results
            .iter()
            .filter(|s| s.state == StepState::Skipped)
            .count();

        obs.chain_completed(steps_done, steps_skipped, total_resumed, duration_ms);

        // Clean up checkpoint file on full success
        self.store.delete(&chain.id).await?;

        Ok(ChainResult {
            chain_id: chain.id.clone(),
            state: ChainState::Completed,
            steps: step_results,
            outputs,
            duration_ms,
            resumed_steps: total_resumed,
        })
    }

    /// Resume a chain that was previously interrupted.
    ///
    /// This is a convenience wrapper: supply the same [`Chain`] definition and
    /// the executor will automatically skip already-checkpointed steps.
    ///
    /// # Errors
    ///
    /// Returns `Error::Internal` if the chain has no prior checkpoints.
    pub async fn resume(
        &self,
        chain: &Chain,
        chain_inputs: Value,
        invoker: &dyn ToolInvoker,
    ) -> Result<ChainResult> {
        let prior = self.store.load(&chain.id).await?;
        if prior.is_empty() {
            return Err(Error::Internal(format!(
                "No checkpoint found for chain '{}'; cannot resume",
                chain.id
            )));
        }
        self.execute(chain, chain_inputs, invoker).await
    }

    /// List all chain IDs that have partial checkpoint files.
    ///
    /// # Errors
    ///
    /// Propagates store read errors.
    pub async fn list_partial_chains(&self) -> Result<Vec<String>> {
        self.store.list_chain_ids().await
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::interpolation::{
        PathSegment, extract_var_refs, interpolate_inputs, resolve_path, tokenize_path,
    };
    use crate::chains::types::{Chain, ChainStep};
    use serde_json::json;

    // ── Mock ToolInvoker ────────────────────────────────────────────────────

    struct MockInvoker {
        responses: std::sync::RwLock<HashMap<String, Value>>,
        call_log: std::sync::Mutex<Vec<String>>,
    }

    impl MockInvoker {
        fn new() -> Self {
            Self {
                responses: std::sync::RwLock::new(HashMap::new()),
                call_log: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn respond(self, tool: &str, value: Value) -> Self {
            self.responses
                .write()
                .unwrap()
                .insert(tool.to_string(), value);
            self
        }

        fn calls(&self) -> Vec<String> {
            self.call_log.lock().unwrap().clone()
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
            self.call_log.lock().unwrap().push(tool.to_string());
            self.responses
                .read()
                .unwrap()
                .get(tool)
                .cloned()
                .ok_or_else(|| Error::BackendNotFound(format!("tool not found: {tool}")))
        }
    }

    fn fast_policy() -> ChainRetryPolicy {
        ChainRetryPolicy::new(2, std::time::Duration::from_millis(1))
    }

    fn make_executor() -> ChainExecutor {
        let tmp = std::env::temp_dir().join(format!("chain-test-{}", uuid::Uuid::new_v4()));
        ChainExecutor::new(ChainCheckpointStore::new(&tmp).unwrap(), fast_policy())
    }

    // ── execute: basic happy path ───────────────────────────────────────────

    #[tokio::test]
    async fn execute_single_step_success() {
        // GIVEN a chain with one step that succeeds
        let executor = make_executor();
        let invoker = MockInvoker::new().respond("search_tool", json!({"results": ["a"]}));
        let chain = Chain::new("chain-1")
            .step(ChainStep::new("search", "search_tool").input(json!({"q": "rust"})));
        // WHEN executed
        let result = executor.execute(&chain, json!({}), &invoker).await.unwrap();
        // THEN chain succeeds and output is populated
        assert!(result.is_success());
        assert_eq!(result.state, ChainState::Completed);
        assert_eq!(result.outputs["search"], json!({"results": ["a"]}));
    }

    #[tokio::test]
    async fn execute_multi_step_chain() {
        // GIVEN a two-step chain
        let executor = make_executor();
        let invoker = MockInvoker::new()
            .respond("step_a_tool", json!({"data": 1}))
            .respond("step_b_tool", json!({"data": 2}));
        let chain = Chain::new("chain-2")
            .step(ChainStep::new("step_a", "step_a_tool"))
            .step(ChainStep::new("step_b", "step_b_tool"));
        // WHEN executed
        let result = executor.execute(&chain, json!({}), &invoker).await.unwrap();
        // THEN both steps are present in results
        assert!(result.is_success());
        assert_eq!(result.steps.len(), 2);
        assert_eq!(result.steps[0].state, StepState::Completed);
        assert_eq!(result.steps[1].state, StepState::Completed);
    }

    // ── execute: failure handling ───────────────────────────────────────────

    #[tokio::test]
    async fn required_step_failure_aborts_chain() {
        // GIVEN a chain where the second step always fails
        let executor = make_executor();
        let invoker = MockInvoker::new().respond("step_a_tool", json!("ok"));
        // step_b_tool has no response → BackendNotFound (non-retryable)
        let chain = Chain::new("chain-3")
            .step(ChainStep::new("step_a", "step_a_tool"))
            .step(ChainStep::new("step_b", "missing_tool"));
        // WHEN executed
        let result = executor.execute(&chain, json!({}), &invoker).await.unwrap();
        // THEN chain state is Failed
        assert_eq!(result.state, ChainState::Failed);
        assert_eq!(result.steps[1].state, StepState::Failed);
    }

    #[tokio::test]
    async fn optional_step_failure_continues_chain() {
        // GIVEN a chain with an optional step that fails
        let executor = make_executor();
        let invoker = MockInvoker::new()
            .respond("step_a_tool", json!("ok"))
            .respond("step_c_tool", json!("done"));
        let chain = Chain::new("chain-4")
            .step(ChainStep::new("step_a", "step_a_tool"))
            .step(ChainStep::new("step_b", "missing_tool").optional())
            .step(ChainStep::new("step_c", "step_c_tool"));
        // WHEN executed
        let result = executor.execute(&chain, json!({}), &invoker).await.unwrap();
        // THEN chain completes despite the optional step being skipped
        assert_eq!(result.state, ChainState::Completed);
        assert_eq!(result.steps[1].state, StepState::Skipped);
        assert_eq!(result.steps[2].state, StepState::Completed);
    }

    // ── resume from checkpoint ──────────────────────────────────────────────

    #[tokio::test]
    async fn resume_skips_already_completed_steps() {
        // GIVEN a checkpoint exists for step_a
        let tmp = std::env::temp_dir().join(format!("chain-resume-test-{}", uuid::Uuid::new_v4()));
        let store = ChainCheckpointStore::new(&tmp).unwrap();
        store
            .append(&ChainCheckpoint {
                chain_id: "chain-5".into(),
                step_name: "step_a".into(),
                output: json!({"cached": true}),
                attempts: 1,
                completed_at: chrono::Utc::now(),
                duration_ms: 5,
            })
            .await
            .unwrap();

        let executor = ChainExecutor::new(store, fast_policy());
        // step_a_tool is NOT registered — proving it was skipped from checkpoint
        let invoker = MockInvoker::new().respond("step_b_tool", json!({"new": true}));
        let chain = Chain::new("chain-5")
            .step(ChainStep::new("step_a", "step_a_tool"))
            .step(ChainStep::new("step_b", "step_b_tool"));

        // WHEN resumed
        let result = executor.execute(&chain, json!({}), &invoker).await.unwrap();

        // THEN step_a is restored from checkpoint (not re-executed)
        assert!(result.is_success());
        assert_eq!(result.resumed_steps, 1);
        assert_eq!(result.outputs["step_a"], json!({"cached": true}));
        assert_eq!(result.outputs["step_b"], json!({"new": true}));
    }

    #[tokio::test]
    async fn resume_fails_when_no_checkpoint_exists() {
        // GIVEN an executor with no checkpoints
        let executor = make_executor();
        let invoker = MockInvoker::new();
        let chain = Chain::new("never-started");
        // WHEN trying to resume
        let result = executor.resume(&chain, json!({}), &invoker).await;
        // THEN an error is returned
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("No checkpoint found")
        );
    }

    // ── variable interpolation ──────────────────────────────────────────────

    #[test]
    fn interpolate_pure_string_ref_preserves_type() {
        // GIVEN a pure variable reference to a number
        let mut outputs = HashMap::new();
        outputs.insert("step".into(), json!({"count": 42}));
        let inputs = json!({});
        // WHEN interpolated
        let result = interpolate_inputs(&json!("$step.count"), &outputs, &inputs);
        // THEN numeric type is preserved
        assert_eq!(result, json!(42));
    }

    #[test]
    fn interpolate_embedded_ref_renders_as_string() {
        // GIVEN an embedded reference in a string template
        let mut outputs = HashMap::new();
        outputs.insert("search".into(), json!({"query": "rust"}));
        let inputs = json!({});
        // WHEN interpolated
        let result =
            interpolate_inputs(&json!("results for $search.query found"), &outputs, &inputs);
        // THEN the reference is replaced inline
        assert_eq!(result, json!("results for rust found"));
    }

    #[test]
    fn interpolate_inputs_ref_uses_chain_inputs() {
        // GIVEN chain inputs with a query
        let outputs = HashMap::new();
        let inputs = json!({"topic": "async Rust"});
        // WHEN interpolated
        let result = interpolate_inputs(&json!("$inputs.topic"), &outputs, &inputs);
        // THEN input value is resolved
        assert_eq!(result, json!("async Rust"));
    }

    #[test]
    fn resolve_path_handles_array_index() {
        // GIVEN a JSON array
        let value = json!({"results": ["first", "second", "third"]});
        // WHEN resolving with array index
        let result = resolve_path(&value, "results[1]");
        // THEN correct element is returned
        assert_eq!(result, json!("second"));
    }

    #[test]
    fn resolve_path_returns_null_for_missing_key() {
        // GIVEN a JSON object
        let value = json!({"a": 1});
        // WHEN resolving a missing key
        let result = resolve_path(&value, "missing");
        // THEN null is returned
        assert_eq!(result, Value::Null);
    }

    #[test]
    fn extract_var_refs_finds_multiple_refs() {
        // GIVEN a string with two variable refs
        let refs = extract_var_refs("from $step_a.out to $step_b.data[0]");
        // THEN both are extracted
        assert_eq!(refs.len(), 2);
        assert!(refs.contains(&"$step_a.out".to_string()));
        assert!(refs.contains(&"$step_b.data[0]".to_string()));
    }

    #[test]
    fn tokenize_path_handles_bracket_notation() {
        // GIVEN a path with both dot and bracket notation
        let segments = tokenize_path("results[0].title");
        // THEN three segments are produced
        assert_eq!(segments.len(), 3);
        assert!(matches!(&segments[0], PathSegment::Key(k) if k == "results"));
        assert!(matches!(&segments[1], PathSegment::Index(0)));
        assert!(matches!(&segments[2], PathSegment::Key(k) if k == "title"));
    }

    // ── list_partial_chains ─────────────────────────────────────────────────

    #[tokio::test]
    async fn list_partial_chains_returns_active_chains() {
        // GIVEN two partially-completed chains
        let executor = make_executor();
        let store_ref = &executor.store;
        store_ref
            .append(&ChainCheckpoint {
                chain_id: "partial-1".into(),
                step_name: "s1".into(),
                output: json!(null),
                attempts: 1,
                completed_at: chrono::Utc::now(),
                duration_ms: 1,
            })
            .await
            .unwrap();
        store_ref
            .append(&ChainCheckpoint {
                chain_id: "partial-2".into(),
                step_name: "s1".into(),
                output: json!(null),
                attempts: 1,
                completed_at: chrono::Utc::now(),
                duration_ms: 1,
            })
            .await
            .unwrap();
        // WHEN listed
        let mut ids = executor.list_partial_chains().await.unwrap();
        ids.sort();
        // THEN both appear
        assert_eq!(ids, vec!["partial-1", "partial-2"]);
    }

    #[tokio::test]
    async fn checkpoint_deleted_after_successful_completion() {
        // GIVEN a chain that completes successfully
        let tmp = std::env::temp_dir().join(format!("chain-cleanup-{}", uuid::Uuid::new_v4()));
        let store = ChainCheckpointStore::new(&tmp).unwrap();
        let executor = ChainExecutor::new(store.clone(), fast_policy());
        let invoker = MockInvoker::new().respond("the_tool", json!("ok"));
        let chain = Chain::new("cleanup-chain").step(ChainStep::new("step1", "the_tool"));
        // WHEN executed to completion
        executor.execute(&chain, json!({}), &invoker).await.unwrap();
        // THEN checkpoint file is deleted
        let partial = executor.list_partial_chains().await.unwrap();
        assert!(!partial.contains(&"cleanup-chain".to_string()));
    }

    #[tokio::test]
    async fn step_call_order_is_correct() {
        // GIVEN a three-step chain
        let executor = make_executor();
        let invoker = MockInvoker::new()
            .respond("t1", json!(1))
            .respond("t2", json!(2))
            .respond("t3", json!(3));
        let chain = Chain::new("order-chain")
            .step(ChainStep::new("s1", "t1"))
            .step(ChainStep::new("s2", "t2"))
            .step(ChainStep::new("s3", "t3"));
        // WHEN executed
        let result = executor.execute(&chain, json!({}), &invoker).await.unwrap();
        // THEN all three outputs are present
        assert_eq!(result.outputs["s1"], json!(1));
        assert_eq!(result.outputs["s2"], json!(2));
        assert_eq!(result.outputs["s3"], json!(3));
        // AND calls occurred in order
        let calls = invoker.calls();
        assert_eq!(calls, vec!["t1", "t2", "t3"]);
    }
}
