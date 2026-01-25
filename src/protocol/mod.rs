//! MCP Protocol types (version 2024-11-05)

mod messages;
mod types;

pub use messages::*;
pub use types::*;

/// MCP Protocol version
pub const PROTOCOL_VERSION: &str = "2024-11-05";
