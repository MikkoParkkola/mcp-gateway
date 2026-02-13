//! Gateway server implementation

pub mod auth;
mod meta_mcp;
mod meta_mcp_helpers;
mod router;
mod server;
pub mod streaming;

pub use auth::{ResolvedAuthConfig, auth_middleware};
pub use server::Gateway;
pub use streaming::{NotificationMultiplexer, TaggedNotification};
