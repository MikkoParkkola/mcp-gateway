//! Security modules for the MCP gateway.
//!
//! Provides input sanitization, SSRF protection, tool access policies,
//! tool definition integrity checking (anti-rug-pull), scope collision
//! detection, and response content scanning for prompt injection.
//!
//! # Doyensec MCP Security Audit (Issue #100)
//!
//! Modules added per the Doyensec MCP AuthN/Z research:
//! - [`tool_integrity`]: Anti-rug-pull — hash tool schemas, detect mutations
//! - [`scope_collision`]: Namespace collision detection + tool name validation
//! - [`response_scanner`]: Prompt injection pattern detection in tool responses
//! - [`firewall`]: Unified request/response security firewall (RFC-0071)

pub mod data_flow;
#[cfg(feature = "firewall")]
pub mod firewall;
pub mod message_signing;
pub mod policy;
pub mod response_inspect;
pub mod response_scanner;
pub mod sanitize;
pub mod scope_collision;
pub mod ssrf;
pub mod tool_integrity;

pub use data_flow::{
    DataFlowRecord, DataFlowTracer, SanitizationRecord, ToolCategory, audit_sanitization,
    hash_argument,
};
pub use policy::{ToolPolicy, ToolPolicyConfig};
pub use response_scanner::ResponseScanner;
pub use sanitize::{
    SanitizedResourceMeta, sanitize_json_value, sanitize_optional_json, sanitize_resource_metadata,
};
pub use scope_collision::{detect_collisions, validate_tool_name};
pub use ssrf::{check_host_not_ssrf, validate_redirect_chain, validate_url_not_ssrf};
pub use tool_integrity::ToolIntegrityChecker;
