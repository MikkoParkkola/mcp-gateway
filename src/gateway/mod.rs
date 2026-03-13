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
mod ws_listener;
pub mod trace;
#[cfg(feature = "webui")]
pub mod ui;
pub mod webhooks;

pub use auth::{AuthState, ResolvedAuthConfig, auth_middleware};
pub use oauth::{AgentAuthState, AgentIdentity, AgentRegistry, GatewayKeyPair, agent_auth_middleware};
pub use proxy::ProxyManager;
pub use server::Gateway;
pub use streaming::{NotificationMultiplexer, TaggedNotification};
pub use webhooks::WebhookRegistry;
