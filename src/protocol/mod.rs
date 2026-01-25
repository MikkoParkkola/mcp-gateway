//! MCP Protocol types (version 2025-11-25)

mod messages;
mod types;

pub use messages::*;
pub use types::*;

/// MCP Protocol version
pub const PROTOCOL_VERSION: &str = "2025-11-25";
