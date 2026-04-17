//! A2A (`Agent2Agent`) transport adapter — Phase 1.
//!
//! Enables the gateway to proxy A2A backends as if they were MCP tool
//! sources.  An MCP client connects to the gateway's existing Meta-MCP
//! surface; the gateway translates tool calls to A2A `message/send`
//! operations behind the scenes.
//!
//! # Module layout
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`types`] | A2A wire-format types (`AgentCard`, `A2aTask`, `Part`, …) |
//! | [`client`] | Async HTTP client for A2A JSON-RPC calls |
//! | [`translator`] | Pure MCP ↔ A2A translation functions |
//! | [`provider`] | [`Provider`] implementation for A2A backends |
//!
//! # Feature flag
//!
//! This module is compiled when the `a2a` Cargo feature is enabled.
//! The `a2a` feature is included in `default`, so it is active unless
//! the caller opts out with `default-features = false`.
//!
//! # Example: wire up an A2A backend
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use mcp_gateway::a2a::{client::A2aClient, provider::A2aProvider};
//! use mcp_gateway::provider::ProviderRegistry;
//!
//! let client = Arc::new(A2aClient::new(
//!     "https://travel.example.com".to_string(),
//!     None,   // no extra headers
//!     None,   // default agent card path
//!     None,   // no explicit timeout
//! ));
//! let provider = Arc::new(A2aProvider::new("travel-agent".to_string(), client));
//! let registry = ProviderRegistry::new();
//! registry.register(provider);
//! ```

pub mod client;
pub mod provider;
pub mod translator;
pub mod types;

pub use provider::A2aProvider;
pub use types::{A2aTask, AgentCard, TaskState};
