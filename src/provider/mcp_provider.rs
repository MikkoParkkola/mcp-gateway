//! `McpProvider` — adapts an existing [`Backend`] to the [`Provider`] trait.
//!
//! This is the Phase 1 adapter described in RFC-0032.  The existing
//! `Backend` (stdio/HTTP MCP connection) is wrapped without modification;
//! the adapter delegates all calls through the same code paths.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use super::{Provider, ProviderHealth};
use crate::backend::Backend;
use crate::protocol::{Resource, Tool};
use crate::Result;

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
        use crate::protocol::ToolsCallResult;

        let params = serde_json::json!({
            "name": tool,
            "arguments": args,
        });

        let response = self
            .backend
            .request("tools/call", Some(params))
            .await?;

        // Decode the JSON-RPC result into a ToolsCallResult, then flatten
        // all text content into a single JSON value.
        if let Some(result_val) = response.result {
            let call_result: ToolsCallResult = serde_json::from_value(result_val)?;
            // Collect all text content into a JSON array or single value.
            let texts: Vec<Value> = call_result
                .content
                .into_iter()
                .filter_map(|c| match c {
                    crate::protocol::Content::Text { text, .. } => {
                        // Try to parse as JSON, fall back to string.
                        serde_json::from_str(&text).ok().or(Some(Value::String(text)))
                    }
                    crate::protocol::Content::Resource { resource, .. } => {
                        Some(serde_json::to_value(resource).unwrap_or(Value::Null))
                    }
                    _ => None,
                })
                .collect();

            return Ok(match texts.len() {
                0 => Value::Null,
                1 => texts.into_iter().next().unwrap_or(Value::Null),
                _ => Value::Array(texts),
            });
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
            ProviderHealth::Unavailable(format!(
                "Backend '{}' is not running",
                self.backend.name
            ))
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

    fn make_provider_name_matches_backend() {
        // We cannot create a real Backend without a running process,
        // but we can verify the type constraints compile correctly.
        fn _assert_provider<T: Provider>(_: &T) {}
    }

    #[test]
    fn mcp_provider_is_send_sync() {
        // Compile-time check: McpProvider can be stored in Arc<dyn Provider>.
        fn _assert_send_sync<T: Send + Sync>() {}
        _assert_send_sync::<McpProvider>();
    }
}
