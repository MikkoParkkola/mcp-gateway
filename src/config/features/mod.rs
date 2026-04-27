//! Feature-specific configuration types.
//!
//! Each domain has its own sub-module; this `mod.rs` re-exports everything so
//! callers continue to use `crate::config::KeyServerConfig`, etc.

mod auth;
mod cache;
mod capability;
mod code_mode;
mod failsafe;
mod key_server;
mod playbooks;
mod security;
mod streaming;
mod webhooks;

pub use auth::{AgentAuthConfig, AgentDefinitionConfig, ApiKeyConfig, AuthConfig};
pub use cache::CacheConfig;
pub use capability::CapabilityConfig;
pub use code_mode::CodeModeConfig;
pub use failsafe::{
    CircuitBreakerConfig, FailsafeConfig, HealthCheckConfig, RateLimitConfig, RetryConfig,
};
pub use key_server::{
    KeyServerConfig, KeyServerOidcConfig, KeyServerPolicyConfig, KeyServerProviderConfig,
    PolicyMatchConfig, PolicyScopesConfig,
};
pub use playbooks::PlaybooksConfig;
pub use security::{
    AgentIdentityConfig, ResponseContractConfig, SecurityConfig, ToolContractConfig,
};
pub use streaming::StreamingConfig;
pub use webhooks::WebhookConfig;
