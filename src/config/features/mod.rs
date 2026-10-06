// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Feature-specific configuration types.
//!
//! Each domain has its own sub-module; this `mod.rs` re-exports everything so
//! callers continue to use `crate::config::KeyServerConfig`, etc.

mod api_key;
mod auth;
mod cache;
mod capability;
mod code_mode;
mod error_budget;
mod events;
mod failsafe;
mod idempotency;
mod key_server;
mod playbooks;
mod runtime;
mod security;
mod signature_chain;
mod streaming;
mod tasks;
mod webhooks;

pub use api_key::{ApiKeyConfig, ApiKeyKind, api_key_digest_spec};
pub(crate) use api_key::{api_key_expired, parse_api_key_digest};
pub use auth::{AgentAuthConfig, AgentDefinitionConfig, AuthConfig, DashboardSessionConfig};
pub use cache::CacheConfig;
pub use capability::{CapabilityConfig, FileRoots, ProcessCommand, ProcessExecution};
pub use code_mode::CodeModeConfig;
pub use error_budget::{CapabilityErrorBudgetSection, ErrorBudgetSection};
pub(crate) use events::parse_cidr;
pub use events::{
    EventsConfig, EventsRateLimit, EventsScheduleConfig, EventsSourcesConfig, EventsWatchConfig,
};
pub use failsafe::{
    CircuitBreakerConfig, FailsafeConfig, HealthCheckConfig, RateLimitConfig, RetryConfig,
};
pub use idempotency::{IdempotencyConfig, IdempotencyReadOnlyTool};
pub use key_server::{
    KeyServerConfig, KeyServerOidcConfig, KeyServerPolicyConfig, KeyServerProviderConfig,
    PolicyMatchConfig, PolicyScopesConfig,
};
pub use playbooks::PlaybooksConfig;
pub use runtime::{RuntimeAvailabilityConfig, RuntimeConfig, RuntimeProfileConfig};
pub use security::{
    AgentIdentityConfig, ContextIntegrityConfig, ContextIntegrityPresetConfig,
    IdentityGrantsConfig, RemoteServerSigningConfig, ResponseContractConfig, SecurityConfig,
    ToolContractConfig,
};
pub(crate) use signature_chain::validate_backend_chains;
pub use signature_chain::{ChainEmit, ChainMode, SignatureChainConfig};
pub use streaming::StreamingConfig;
pub use tasks::{DEFAULT_MAX_WORKERS, TasksConfig};
pub use webhooks::WebhookConfig;
