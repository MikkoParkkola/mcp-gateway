//! Security modules for the MCP gateway.
//!
//! Provides input sanitization, SSRF protection, and tool access policies.

pub mod policy;
pub mod sanitize;
pub mod ssrf;

pub use policy::{ToolPolicy, ToolPolicyConfig};
pub use sanitize::{sanitize_json_value, sanitize_optional_json};
pub use ssrf::validate_url_not_ssrf;
