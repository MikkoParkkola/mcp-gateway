//! Gateway server implementation

pub mod auth;
mod differential;
mod meta_mcp;
mod meta_mcp_helpers;
pub mod proxy;
mod router;
mod server;
pub mod streaming;
pub mod trace;
pub mod webhooks;

pub use auth::{AuthState, ResolvedAuthConfig, auth_middleware};
pub use proxy::ProxyManager;
pub use server::Gateway;
pub use streaming::{NotificationMultiplexer, TaggedNotification};
pub use webhooks::WebhookRegistry;
