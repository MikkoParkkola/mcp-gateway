// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A capability backend's status, as `/status` and the UI report it.

/// Status information for a capability backend
#[derive(Debug, Clone, serde::Serialize)]
pub struct CapabilityBackendStatus {
    /// Backend name
    pub name: String,
    /// Number of loaded capabilities
    pub capabilities_count: usize,
    /// List of capability names
    pub capabilities: Vec<String>,
    /// Health-tracker liveness for outbound execution. Flips false
    /// after consecutive execution failures (e.g. upstream timeouts).
    pub healthy: bool,
    /// Consecutive execution failures recorded by the health tracker.
    pub consecutive_failures: u64,
    /// 95th percentile execution latency in milliseconds, if any samples exist.
    pub latency_p95_ms: Option<u64>,
    /// Whether the startup scan has loaded every directory.
    pub loaded: bool,
}
