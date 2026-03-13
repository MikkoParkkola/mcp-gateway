//! Gateway server implementation

pub mod auth;
mod differential;
mod meta_mcp;
mod meta_mcp_helpers;
mod meta_mcp_tool_defs;
pub mod oauth;
pub mod proxy;
mod router;
mod server;
pub mod streaming;
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
    pub use super::router::{AppState, create_router};
}
