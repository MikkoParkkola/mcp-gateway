//! Gateway server implementation

mod meta_mcp;
mod router;
mod server;
pub mod streaming;

pub use server::Gateway;
pub use streaming::{NotificationMultiplexer, TaggedNotification};
