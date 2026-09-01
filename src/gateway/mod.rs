// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Gateway server implementation

pub mod auth;
pub(crate) mod authz;
pub mod destructive_confirmation;
mod differential;
mod http_error;
mod meta_mcp;
mod meta_mcp_helpers;
mod meta_mcp_tool_defs;
mod middleware;
pub mod oauth;
pub mod proxy;
pub mod recovery;
mod router;
pub(crate) mod search_disclosure;
mod server;
pub mod session_lifecycle;
pub mod state;
pub mod streaming;
pub mod subscription_registry;
pub mod trace;
#[cfg(feature = "webui")]
pub mod ui;
pub mod webhooks;
mod ws_listener;

pub use auth::{AuthState, ResolvedAuthConfig, auth_middleware};
pub use oauth::{
    AgentAuthState, AgentIdentity, AgentRegistry, GatewayKeyPair, agent_auth_middleware,
};
pub use proxy::ProxyManager;
pub use server::Gateway;
pub(crate) use server::{next_start_refusal, reload_posture_refusal};
pub use streaming::{NotificationMultiplexer, TaggedNotification};
pub use webhooks::WebhookRegistry;

/// Public test helpers for integration tests in `tests/`.
///
/// Exposes internal types (`AppState`, `MetaMcp`, `create_router`) that are
/// not part of the public API but are needed to build an in-process router
/// without starting a real TCP server.
///
/// Hidden from docs; only used in the `tests/` directory.
#[doc(hidden)]
pub mod test_helpers {
    pub use super::meta_mcp::MetaMcp;
    pub use super::meta_mcp::prune_constant_signals;
    pub use super::meta_mcp::{CacheKeyDeriver, stable_tool_order, tool_schema_fingerprint};
    pub use super::router::{AppState, create_router};
}
