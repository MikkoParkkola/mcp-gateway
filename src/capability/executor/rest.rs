//! REST protocol executor
//!
//! Implements [`ProtocolExecutor`] for HTTP/REST APIs — the original and
//! default protocol adapter. All existing capability YAML definitions
//! route through this executor.

use async_trait::async_trait;
use serde_json::Value;

use super::CapabilityExecutor;
use crate::capability::definition::ProtocolConfig;
use crate::{Error, Result};

/// Context passed to every protocol executor invocation.
///
/// Carries request-scoped metadata that is protocol-agnostic: the
/// capability definition, timeout, auth configuration, etc.
///
/// This struct is intentionally cheap to clone (all fields are references
/// or small values) so dispatchers can construct it per-call without
/// allocation overhead.
pub struct ExecutionContext<'a> {
    /// The full capability definition (for auth, caching, transform, etc.)
    pub capability: &'a crate::capability::CapabilityDefinition,
    /// The provider-level timeout in seconds
    pub timeout_secs: u64,
}

/// Trait for protocol-specific execution adapters.
///
/// Each protocol (REST, GraphQL, gRPC, JSON-RPC, CLI, WASM, ...) implements
/// this trait. The [`CapabilityExecutor`] dispatcher selects the right
/// implementation based on [`ProtocolConfig::protocol_name()`].
///
/// # Adding a new protocol
///
/// 1. Add a variant to [`ProtocolConfig`].
/// 2. Implement `ProtocolExecutor` for the new protocol.
/// 3. Register it in [`CapabilityExecutor::new()`] via `register_executor()`.
///
/// No changes to the dispatcher or existing executors are needed.
#[async_trait]
pub trait ProtocolExecutor: Send + Sync {
    /// Returns the protocol name this executor handles (e.g. `"rest"`).
    ///
    /// Must match the value returned by [`ProtocolConfig::protocol_name()`]
    /// for the corresponding config variant.
    fn protocol_name(&self) -> &'static str;

    /// Execute a request using the protocol-specific configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Protocol-specific configuration (the executor should
    ///   extract its own variant via pattern matching).
    /// * `params` - Caller-supplied parameters (JSON object).
    /// * `ctx` - Request-scoped context (capability definition, timeout, etc.)
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails, credentials cannot be resolved,
    /// or the response is invalid.
    async fn execute(
        &self,
        config: &ProtocolConfig,
        params: Value,
        ctx: &ExecutionContext<'_>,
    ) -> Result<Value>;
}

/// REST protocol executor — wraps the existing HTTP execution logic.
///
/// This is a thin adapter that delegates to the methods already implemented
/// on [`CapabilityExecutor`] (URL building, header injection, response
/// handling, etc.) via a shared reference.
pub struct RestExecutor<'a> {
    /// Shared reference to the parent executor (owns the HTTP client,
    /// credential stores, etc.)
    pub(super) executor: &'a CapabilityExecutor,
}

#[async_trait]
impl ProtocolExecutor for RestExecutor<'_> {
    fn protocol_name(&self) -> &'static str {
        "rest"
    }

    async fn execute(
        &self,
        config: &ProtocolConfig,
        params: Value,
        ctx: &ExecutionContext<'_>,
    ) -> Result<Value> {
        let rest_config = config.as_rest().ok_or_else(|| {
            Error::Config(format!(
                "RestExecutor received non-REST config: {}",
                config.protocol_name()
            ))
        })?;

        // Delegate to the existing execute_provider logic which is still
        // on CapabilityExecutor. The ProviderConfig is reconstructed
        // minimally for the call.
        let provider = crate::capability::ProviderConfig {
            service: "rest".to_string(),
            cost_per_call: 0.0,
            timeout: ctx.timeout_secs,
            config: rest_config.clone(),
        };

        self.executor
            .execute_provider(ctx.capability, &provider, &params)
            .await
    }
}
