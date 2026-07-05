//! `McpProvider` — adapts an existing [`Backend`] to the [`Provider`] trait.
//!
//! This is the Phase 1 adapter described in RFC-0032.  The existing
//! `Backend` (stdio/HTTP MCP connection) is wrapped without modification;
//! the adapter delegates all calls through the same code paths.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use super::{Provider, ProviderHealth, flatten_tool_call_result};
use crate::Result;
use crate::backend::Backend;
use crate::protocol::{Resource, Tool};

/// Provider adapter that wraps an existing MCP [`Backend`].
///
/// All tool listing and invocation is delegated to the backend's existing
/// transport layer (stdio or HTTP), preserving the full failsafe pipeline
/// (circuit breaker, retry policy, semaphore).
///
/// # Example
///
/// ```rust
/// use std::sync::Arc;
/// use mcp_gateway::provider::McpProvider;
///
/// // Assuming `backend` is an `Arc<Backend>`:
/// // let provider = Arc::new(McpProvider::new(backend));
/// ```
pub struct McpProvider {
    backend: Arc<Backend>,
}

impl McpProvider {
    /// Wrap an existing backend as a provider.
    #[must_use]
    pub fn new(backend: Arc<Backend>) -> Self {
        Self { backend }
    }

    /// Access the underlying backend (e.g. for status queries).
    #[must_use]
    pub fn backend(&self) -> &Arc<Backend> {
        &self.backend
    }
}

#[async_trait]
impl Provider for McpProvider {
    fn name(&self) -> &str {
        &self.backend.name
    }

    async fn list_tools(&self) -> Result<Vec<Tool>> {
        self.backend.get_tools().await
    }

    async fn invoke(&self, tool: &str, args: Value) -> Result<Value> {
        // MIK-6741 (PROV.1, IDP.2 fail-closed): the `Provider` trait carries no
        // per-user identity, so this adapter cannot resolve or attach a per-user
        // credential. Dispatching a propagation-required backend here would
        // silently reuse the shared gateway session and bypass enforcement. No
        // live server route reaches this adapter today (confirmed by source
        // search, MIK-6734 r4); this guard fails closed so a future wiring
        // cannot become a silent identity bypass.
        if self
            .backend
            .identity_propagation_config()
            .is_some_and(|c| c.required)
        {
            return Err(crate::Error::Protocol(format!(
                "backend '{}' requires end-user identity propagation, which the Provider \
                 adapter path cannot supply; refusing to dispatch over a shared session \
                 (MIK-6741, IDP.2 fail-closed)",
                self.backend.name
            )));
        }

        let params = serde_json::json!({
            "name": tool,
            "arguments": args,
        });

        let response = self.backend.request("tools/call", Some(params)).await?;

        // Decode the JSON-RPC result into the shared provider content shape.
        if let Some(result_val) = response.result {
            return flatten_tool_call_result(serde_json::from_value(result_val)?);
        }

        if let Some(err) = response.error {
            return Err(crate::Error::Protocol(format!(
                "Tool call error {}: {}",
                err.code, err.message
            )));
        }

        Ok(Value::Null)
    }

    async fn health(&self) -> ProviderHealth {
        if self.backend.is_running() {
            ProviderHealth::Healthy
        } else {
            ProviderHealth::Unavailable(format!("Backend '{}' is not running", self.backend.name))
        }
    }

    async fn list_resources(&self) -> Result<Vec<Resource>> {
        self.backend.get_resources().await
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // McpProvider construction is lightweight — just wraps an Arc.
    // Full integration tests require a live MCP server; unit tests cover
    // the adapter wiring.

    fn _make_provider_name_matches_backend() {
        // We cannot create a real Backend without a running process,
        // but we can verify the type constraints compile correctly.
        fn _assert_provider<T: Provider>(_: &T) {}
    }

    #[test]
    fn mcp_provider_is_send_sync() {
        // Compile-time check: McpProvider can be stored in Arc<dyn Provider>.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<McpProvider>();
    }

    // MIK-6741 (PROV.2): the adapter must fail closed for a propagation-required
    // backend, since the `Provider` trait cannot carry the per-user identity.
    // The guard short-circuits before any transport call, so no live backend is
    // needed. If a future change wires this adapter into a live route, this test
    // fails unless enforcement is added — the intended tripwire.
    #[tokio::test]
    async fn invoke_fails_closed_for_propagation_required_backend() {
        use crate::backend::Backend;
        use crate::config::BackendConfig;
        use crate::identity_propagation::{
            IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
        };

        let backend = Arc::new(Backend::new(
            "b",
            BackendConfig {
                identity_propagation: Some(IdentityPropagationConfig {
                    strategy: PropagationStrategyKind::SignedAssertion,
                    audience: "https://backend.example".to_string(),
                    required: true,
                    session_mode: SessionMode::Stateless,
                    token_exchange_endpoint: None,
                    token_exchange_scope: None,
                }),
                ..BackendConfig::default()
            },
            &crate::config::FailsafeConfig::default(),
            std::time::Duration::from_secs(60),
        ));
        let provider = McpProvider::new(backend);
        let err = provider
            .invoke("some_tool", serde_json::json!({}))
            .await
            .expect_err("propagation-required backend must fail closed via the adapter");
        let msg = err.to_string();
        assert!(
            msg.contains("MIK-6741"),
            "expected the fail-closed guard, got: {msg}"
        );
    }

    // A backend with no identity_propagation config must NOT be blocked by the
    // guard (the check is opt-in on `required`). We can't complete a real
    // dispatch without a transport, so we assert the guard does not short-circuit
    // by observing a transport-level error rather than the MIK-6741 refusal.
    #[tokio::test]
    async fn invoke_not_blocked_for_non_propagation_backend() {
        use crate::backend::Backend;
        use crate::config::BackendConfig;

        let backend = Arc::new(Backend::new(
            "plain",
            BackendConfig::default(),
            &crate::config::FailsafeConfig::default(),
            std::time::Duration::from_secs(60),
        ));
        let provider = McpProvider::new(backend);
        let err = provider
            .invoke("some_tool", serde_json::json!({}))
            .await
            .expect_err("no transport connected, so dispatch errors");
        assert!(
            !err.to_string().contains("MIK-6741"),
            "guard must not fire for a non-propagation backend: {err}"
        );
    }
}
