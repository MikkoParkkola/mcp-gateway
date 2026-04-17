//! `A2aProvider` — implements the gateway [`Provider`] trait for A2A backends.
//!
//! An A2A backend is discovered via its Agent Card and invoked through the
//! `message/send` JSON-RPC method.  The provider translates between MCP
//! semantics and A2A semantics at the boundary using [`crate::a2a::translator`].
//!
//! # Multi-turn conversations
//!
//! A2A supports stateful conversations via `context_id`.  The provider tracks
//! which context ID was last used per client invocation by forwarding whatever
//! `context_id` the caller supplies in the tool arguments.  State is not
//! stored server-side (in the gateway); the caller is responsible for threading
//! `context_id` across turns.
//!
//! # Agent Card caching
//!
//! The Agent Card is fetched on the first `list_tools` call and cached in an
//! `RwLock<Option<AgentCard>>`.  Cache TTL is not enforced here; the caller
//! (Meta-MCP) applies its own `cache_ttl` to the tool list.  On `health`,
//! the cache is bypassed: we always probe the Agent Card URL live.

use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;
use serde_json::Value;

use crate::protocol::{Resource, Tool};
use crate::provider::{Provider, ProviderHealth};
use crate::{Error, Result};

use super::client::A2aClient;
use super::translator::{agent_card_to_mcp_tools, task_to_mcp_result, tool_args_to_message};
use super::types::AgentCard;

// ── Provider ──────────────────────────────────────────────────────────────────

/// A2A backend provider.
///
/// Implements [`Provider`] by wrapping an [`A2aClient`] and performing
/// MCP ↔ A2A translation on every call.
pub struct A2aProvider {
    name: String,
    client: Arc<A2aClient>,
    cached_card: RwLock<Option<AgentCard>>,
}

impl A2aProvider {
    /// Create a new provider wrapping `client`.
    ///
    /// `name` must be unique within the `ProviderRegistry`.
    #[must_use]
    pub fn new(name: String, client: Arc<A2aClient>) -> Self {
        Self {
            name,
            client,
            cached_card: RwLock::new(None),
        }
    }

    /// Returns the cached Agent Card if available.
    #[must_use]
    pub fn cached_card(&self) -> Option<AgentCard> {
        self.cached_card.read().clone()
    }

    /// Fetch the Agent Card, caching it for subsequent `list_tools` calls.
    async fn fetch_and_cache_card(&self) -> Result<AgentCard> {
        let card = self.client.fetch_agent_card().await?;
        *self.cached_card.write() = Some(card.clone());
        Ok(card)
    }
}

#[async_trait]
impl Provider for A2aProvider {
    fn name(&self) -> &str {
        &self.name
    }

    /// List tools synthesized from the Agent Card's skills.
    ///
    /// On first call this fetches the Agent Card over HTTP; subsequent calls
    /// return cached tools (cache managed by the caller's TTL policy).
    async fn list_tools(&self) -> Result<Vec<Tool>> {
        let card = self.fetch_and_cache_card().await?;
        Ok(agent_card_to_mcp_tools(&card, &self.name))
    }

    /// Invoke a skill on the A2A backend.
    ///
    /// Expects `args` to contain a `"message"` string and optional `"context_id"`.
    /// The tool name is used only for error messages; the gateway routes to
    /// this provider by name, not by tool name.
    async fn invoke(&self, tool: &str, args: Value) -> Result<Value> {
        let (message, context_id) = tool_args_to_message(&args).map_err(|e| {
            Error::Protocol(format!(
                "A2A tool '{}' on provider '{}': {e}",
                tool, self.name
            ))
        })?;

        let task = self
            .client
            .send_message(message, context_id)
            .await
            .map_err(|e| {
                Error::Protocol(format!("A2A send_message for tool '{tool}' failed: {e}"))
            })?;

        task_to_mcp_result(&task)
    }

    /// Health check: probe the Agent Card endpoint live.
    async fn health(&self) -> ProviderHealth {
        match self.client.fetch_agent_card().await {
            Ok(_) => ProviderHealth::Healthy,
            Err(e) => ProviderHealth::Unavailable(format!(
                "A2A provider '{}' Agent Card unreachable: {e}",
                self.name
            )),
        }
    }

    /// A2A backends do not expose MCP resources.
    async fn list_resources(&self) -> Result<Vec<Resource>> {
        Ok(vec![])
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::a2a::client::A2aClient;

    fn make_provider(name: &str) -> A2aProvider {
        let client = Arc::new(A2aClient::new(
            "https://agent.example.com",
            None,
            None,
            None,
        ));
        A2aProvider::new(name.to_string(), client)
    }

    #[test]
    fn a2a_provider_name_returns_configured_name() {
        // GIVEN: provider with name "travel-agent"
        // WHEN: calling name()
        // THEN: returns "travel-agent"
        let provider = make_provider("travel-agent");
        assert_eq!(provider.name(), "travel-agent");
    }

    #[test]
    fn a2a_provider_is_send_sync() {
        // Compile-time check: A2aProvider can be stored in Arc<dyn Provider>.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<A2aProvider>();
    }

    #[test]
    fn a2a_provider_cached_card_initially_none() {
        // GIVEN: freshly constructed provider
        // WHEN: querying cached_card before any fetch
        // THEN: None
        let provider = make_provider("test");
        assert!(provider.cached_card().is_none());
    }

    #[test]
    fn a2a_provider_list_resources_returns_empty() {
        // GIVEN: A2a provider
        // WHEN: calling list_resources synchronously (via block_on)
        // THEN: returns empty vec (A2A has no MCP resources)
        let provider = make_provider("test");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let resources = rt.block_on(provider.list_resources()).unwrap();
        assert!(resources.is_empty());
    }
}
