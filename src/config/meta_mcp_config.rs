// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Surfaced-tool and Meta-MCP configuration (split from `mod.rs`).

use super::{
    Deserialize, Duration, Serialize, default_prompts_resources_fetch_timeout, humantime_serde,
};

// ── Meta-MCP ──────────────────────────────────────────────────────────────────

/// A single backend tool that is statically surfaced in `tools/list`.
///
/// Surfaced tools appear as first-class entries alongside meta-tools, giving
/// LLMs direct one-hop access to high-value tools without the full discovery
/// overhead.  The gateway proxies calls transparently to the configured backend.
///
/// # Example
///
/// ```yaml
/// meta_mcp:
///   surfaced_tools:
///     - server: my_backend
///       tool: my_important_tool
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SurfacedToolConfig {
    /// Name of the backend server that owns the tool.
    pub server: String,
    /// Exact tool name as reported by the backend's `tools/list`.
    pub tool: String,
}

/// Meta-MCP configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MetaMcpConfig {
    /// Enable Meta-MCP mode.
    pub enabled: bool,
    /// Tool cache TTL.
    #[serde(with = "humantime_serde")]
    pub cache_ttl: Duration,
    /// Per-backend bound on how long `prompts/list` and `resources/list`
    /// aggregation waits for a single backend before skipping it.
    ///
    /// The aggregate fetch runs all backends in parallel (see the meta-MCP
    /// handlers), so this bounds the whole request by the slowest backend
    /// rather than the sum of all backends. A backend that exceeds the bound —
    /// slow OR hung — is skipped for that response; its prompts/resources
    /// reappear once it recovers. Defaults to 10 seconds.
    #[serde(
        default = "default_prompts_resources_fetch_timeout",
        with = "humantime_serde"
    )]
    pub prompts_resources_fetch_timeout: Duration,
    /// Backends to warm-start on gateway startup.
    #[serde(default)]
    pub warm_start: Vec<String>,
    /// Tools to surface directly in `tools/list` alongside meta-tools.
    ///
    /// Each entry pins one backend tool so that LLMs can call it directly
    /// (one hop) instead of going through `gateway_invoke` (two hops).
    /// The gateway validates at startup that surfaced tool names do not
    /// collide with any meta-tool name.
    #[serde(default)]
    pub surfaced_tools: Vec<SurfacedToolConfig>,
    /// Canonical response-projection rollout mode (MIK-5877).
    ///
    /// `off` (default) — projection never runs, even for a capability that
    /// declares a spec (no contract change for live users). `on` — project
    /// whenever a spec is present. `experimental` — sticky per-session A/B
    /// split between projected (treatment) and raw (control).
    #[serde(default)]
    pub projection_mode: crate::projection::ProjectionMode,
    /// Meta-tools to expose in `tools/list` (GH issue 449).
    ///
    /// Empty — the default — exposes every meta-tool, so an existing
    /// deployment is unaffected. A non-empty list is an allow-list: only the
    /// named tools are listed, and a tool that is not listed is not callable
    /// either. Failing closed is deliberate; a meta-tool added in a later
    /// release stays hidden from operators who pin a list until they opt in.
    ///
    /// Unrecognised names are logged and dropped rather than aborting startup
    /// (same policy as `surfaced_tools`).
    ///
    /// The list is read once at startup, so an edit takes effect on restart
    /// rather than on `gateway_reload_config` (same as `surfaced_tools`).
    #[serde(default)]
    pub exposed_meta_tools: Vec<String>,
    /// List `gateway_get_stats` in `tools/list` (`NFR.PERF.4`).
    ///
    /// Off by default. The usage-stats collector is always attached, so its
    /// presence was never a gate; an HTTP operator reads the same numbers from
    /// `/metrics`, and a stdio client that wants the handler can still call it
    /// by name. The flag governs enumeration only — dispatch is unchanged.
    #[serde(default)]
    pub expose_stats_tool: bool,
}

impl Default for MetaMcpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_ttl: Duration::from_secs(300),
            prompts_resources_fetch_timeout: Duration::from_secs(10),
            warm_start: Vec::new(),
            surfaced_tools: Vec::new(),
            projection_mode: crate::projection::ProjectionMode::default(),
            exposed_meta_tools: Vec::new(),
            expose_stats_tool: false,
        }
    }
}
