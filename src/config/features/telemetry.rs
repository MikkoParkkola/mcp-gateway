//! Privacy-preserving active-user telemetry configuration.

/// Telemetry configuration — controls the daily heartbeat to the MIK-6565 collector.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct TelemetryConfig {
    /// Whether telemetry is enabled. Set to `false` to disable the heartbeat.
    pub enabled: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}
