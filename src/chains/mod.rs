//! Durable Capability Chains — step-level checkpoint + retry for multi-tool pipelines.
//!
//! When an agent chains multiple tool calls (e.g., search → extract → summarize),
//! each step is checkpointed to disk. If any step fails, the chain can resume
//! from the last successful checkpoint instead of restarting from scratch.
//!
//! # Architecture
//!
//! ```text
//! Agent calls: gateway_execute_chain(definition)
//!        │
//!        ▼
//! ┌──────────────────────────────────────────────────────────┐
//! │  ChainExecutor                                            │
//! │  ┌─────────────┐   ┌───────────────┐   ┌─────────────┐  │
//! │  │  Checkpoint  │   │     Retry     │   │Observability│  │
//! │  │  (JSONL)    │   │  (exp. back.) │   │ (tracing)   │  │
//! │  └─────────────┘   └───────────────┘   └─────────────┘  │
//! └──────────────────────────────────────────────────────────┘
//!        │
//!        ▼
//! ~/.mcp-gateway/chains/<chain_id>.jsonl
//! ```
//!
//! # Example
//!
//! ```rust
//! use mcp_gateway::chains::{Chain, ChainStep, ChainExecutor, ChainRetryPolicy};
//! use serde_json::json;
//!
//! async fn run_research(executor: &ChainExecutor) {
//!     let chain = Chain::new("research-001")
//!         .step(ChainStep::new("search", "brave_search")
//!             .input(json!({"query": "Rust MCP"})))
//!         .step(ChainStep::new("summarize", "gateway_invoke")
//!             .input(json!({"tool": "summarize", "data": "$search.results"})));
//!     // execute returns ChainResult with all step outputs
//! }
//! ```

mod checkpoint;
mod executor;
pub(crate) mod interpolation;
mod observability;
mod retry;
mod types;

pub use checkpoint::ChainCheckpointStore;
pub use executor::ChainExecutor;
pub use observability::ChainObservability;
pub use retry::ChainRetryPolicy;
pub use types::{
    Chain, ChainCheckpoint, ChainResult, ChainState, ChainStep, ChainStepResult, StepState,
};
