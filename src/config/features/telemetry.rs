//! Telemetry configuration for privacy-preserving active-user heartbeat (MIK-6573).

use serde::{Deserialize, Serialize};

/// Telemetry configuration.
///
/// Controls whether the gateway sends a minimal heartbeat to the MIK-6565
/// shared collector on startup.  The heartbeat never includes an IP address,
/// honours every common opt-out, and is failure-open.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TelemetryConfig {
    /// Enable the privacy-preserving heartbeat (default: `true`).
    ///
    /// Set to `false` to suppress telemetry entirely.  Other opt-out
    /// mechanisms (`NO_TELEMETRY`, `DO_NOT_TRACK`, `MCP_GATEWAY_NO_TELEMETRY`,
    /// `CI`, debug/test builds) also suppress the heartbeat independently.
    pub enabled: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}
