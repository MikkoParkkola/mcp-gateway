// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Backend status/runtime-status report types and the [`BackendRegistry`]
//! that owns all configured backends by name.

use std::collections::HashMap;
use std::sync::Arc;

use dashmap::DashMap;
use tracing::warn;

use super::Backend;
use crate::runtime::{RuntimeDenyReason, RuntimeLicenseTier, RuntimeProviderKind};

/// Backend status information
#[derive(Debug, Clone, serde::Serialize)]
pub struct BackendStatus {
    /// Backend name
    pub name: String,
    /// Whether backend is running
    pub running: bool,
    /// Transport type
    pub transport: String,
    /// Number of cached tools
    pub tools_cached: usize,
    /// Circuit breaker state
    pub circuit_state: String,
    /// Total request count
    pub request_count: u64,
    /// Health-tracker liveness (flips false after consecutive failures, e.g.
    /// timeouts under load, *before* the circuit breaker trips Open). `/health`
    /// must consider this so it does not report healthy while a backend is
    /// silently timing out (see issue #5080 / MIK-5080).
    pub healthy: bool,
    /// Consecutive failures recorded by the health tracker.
    pub consecutive_failures: u64,
    /// 95th percentile latency in milliseconds, if any samples exist.
    pub latency_p95_ms: Option<u64>,
    /// Runtime profile lifecycle state for admin/operator surfaces.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<BackendRuntimeStatus>,
}

/// Runtime profile status information exposed through backend status.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct BackendRuntimeStatus {
    /// Runtime profile selected by this backend.
    pub profile: String,
    /// Provider selected by the compiled runtime plan.
    pub provider: RuntimeProviderKind,
    /// Policy id used for audit correlation.
    pub policy_id: String,
    /// License tier that owns this runtime provider capability.
    pub license_tier: RuntimeLicenseTier,
    /// Whether the runtime plan is ready, denied, or waiting for approval.
    pub state: BackendRuntimeState,
    /// Fail-closed denial reasons, when any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_reasons: Vec<RuntimeDenyReason>,
    /// Confirmation ids required before live start or provider apply.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub confirmation_ids: Vec<String>,
    /// Maximum restart attempts from the compiled policy.
    pub restart_max_attempts: u32,
    /// Restart backoff from the compiled policy.
    pub restart_backoff_secs: u64,
    /// Provider-specific health check instruction or command.
    pub health_check: String,
    /// Provider-specific restart command hint, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_command_hint: Option<String>,
    /// Rollback instruction for this runtime plan.
    pub rollback_step: String,
}

/// Compiled runtime plan state for a backend.
#[derive(Debug, Clone, Copy, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackendRuntimeState {
    /// Policy passed without pending human gates.
    Ready,
    /// Policy requires explicit human approval before execution.
    ConfirmationRequired,
    /// Policy denied execution and must fail closed.
    Denied,
}

/// Backend registry - manages all backends
pub struct BackendRegistry {
    /// Backends by name
    backends: DashMap<String, Arc<Backend>>,
}

impl BackendRegistry {
    /// Create a new registry
    #[must_use]
    pub fn new() -> Self {
        Self {
            backends: DashMap::new(),
        }
    }

    /// Register a backend
    pub fn register(&self, backend: Arc<Backend>) {
        self.backends.insert(backend.name.clone(), backend);
    }

    /// Get a backend by name
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Arc<Backend>> {
        self.backends.get(name).map(|b| Arc::clone(&*b))
    }

    /// Get all backends
    #[must_use]
    pub fn all(&self) -> Vec<Arc<Backend>> {
        self.backends.iter().map(|b| Arc::clone(&*b)).collect()
    }

    /// Get all backend statuses
    #[must_use]
    pub fn statuses(&self) -> HashMap<String, BackendStatus> {
        self.backends
            .iter()
            .map(|b| (b.name.clone(), b.status()))
            .collect()
    }

    /// Remove a backend by name (deregister without stopping).
    ///
    /// If the backend must be stopped before removal, call `backend.stop()`
    /// first.  Returns `true` when the backend was present and removed.
    pub fn remove(&self, name: &str) -> bool {
        self.backends.remove(name).is_some()
    }

    /// Stop all backends
    pub async fn stop_all(&self) {
        for backend in &self.backends {
            if let Err(e) = backend.stop().await {
                warn!(backend = %backend.name, error = %e, "Failed to stop backend");
            }
        }
    }
}

impl Default for BackendRegistry {
    fn default() -> Self {
        Self::new()
    }
}
