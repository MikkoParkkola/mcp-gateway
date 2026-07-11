// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Backend management

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::Semaphore;

use crate::config::BackendConfig;
use crate::protocol::{Prompt, Resource, ResourceTemplate, Tool};
use crate::runtime::RuntimePlan;

mod annotations;
mod cached_metadata;
mod lifecycle;
mod metadata;
mod ops;
mod pool;
mod registry;

use cached_metadata::CachedMetadata;
use pool::{PoolKey, PooledEntry};

pub(crate) use annotations::normalize_tool_annotations;
pub use lifecycle::runtime_plan_for_backend;
pub use registry::{BackendRegistry, BackendRuntimeState, BackendRuntimeStatus, BackendStatus};

/// MCP Backend - manages connection to a single MCP server
pub struct Backend {
    /// Backend name
    pub name: String,
    /// Configuration
    config: BackendConfig,
    /// Runtime plan compiled from the backend's configured runtime profile.
    runtime_plan: Option<RuntimePlan>,
    /// Per-identity transport/session pool (MIK-6735). Always holds the
    /// canonical [`PoolKey::Shared`] slot; gains one [`PoolKey::PerUser`] slot
    /// per caller identity when `session_mode = per_user`. Each slot carries its
    /// own transport and start lock, so concurrent warm-start/client requests do
    /// not spawn duplicate connections for the same slot and distinct users
    /// never share a session (IDP.7).
    pool: DashMap<PoolKey, Arc<PooledEntry>>,
    /// Failsafe configuration, cloned so a freshly created pool slot
    /// (`pooled_entry`) can build its own independent `Failsafe` (MIK-6735
    /// fix 1). The per-backend `Failsafe` this replaced is gone; every slot,
    /// including Shared, now owns one.
    failsafe_config: crate::config::FailsafeConfig,
    /// Cached tools
    tools_cache: CachedMetadata<Vec<Tool>>,
    /// Cached resources
    resources_cache: CachedMetadata<Vec<Resource>>,
    /// Cached resource templates
    resource_templates_cache: CachedMetadata<Vec<ResourceTemplate>>,
    /// Cached prompts
    prompts_cache: CachedMetadata<Vec<Prompt>>,
    /// Cache TTL
    cache_ttl: Duration,
    /// Last used timestamp
    last_used: AtomicU64,
    /// Concurrency limiter
    semaphore: Semaphore,
    /// Request counter
    request_count: AtomicU64,
}

#[cfg(test)]
mod pool_tests;
#[cfg(test)]
mod tests;
