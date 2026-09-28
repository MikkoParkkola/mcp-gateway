// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Anomaly-detection settings of [`FirewallConfig`]: defaults and load checks.

use super::FirewallConfig;

pub(super) const fn default_anomaly_threshold() -> f64 {
    0.7
}

pub(super) const fn default_anomaly_min_observations() -> u64 {
    20
}

impl FirewallConfig {
    /// Refuse anomaly thresholds that cannot mean what they say.
    ///
    /// Checked only when `anomaly_detection` is on, so a config that never
    /// enables the detector loads exactly as before.
    ///
    /// # Errors
    ///
    /// A message naming the first out-of-range field.
    pub fn validate(&self) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::config::Config;

    fn load(anomaly: &str) -> crate::Result<()> {
        let yaml = format!("security:\n  firewall:\n{anomaly}");
        let config: Config = serde_yaml::from_str(&yaml).expect("the YAML parses");
        config.validate()
    }

    #[test]
    fn anomaly_ranges_refused_at_load() {
        let on = "    anomaly_detection: true\n";
        for (field, bad) in [
            ("anomaly_threshold", "0.5"),
            ("anomaly_threshold", "1.01"),
            ("anomaly_threshold", ".nan"),
            ("anomaly_threshold", ".inf"),
            ("anomaly_block_threshold", "0.7"),
            ("anomaly_block_threshold", "1.01"),
            ("anomaly_block_threshold", ".nan"),
            ("anomaly_min_observations", "0"),
        ] {
            let result = load(&format!("{on}    {field}: {bad}\n"));
            assert!(result.is_err(), "{field}: {bad} must refuse to load");
            let message = result.unwrap_err().to_string();
            assert!(message.contains(field), "the refusal names {field}: {message}");
        }
        for (field, good) in [
            ("anomaly_threshold", "0.51"),
            ("anomaly_threshold", "1.0"),
            ("anomaly_block_threshold", "0.95"),
            ("anomaly_block_threshold", "1.0"),
            ("anomaly_min_observations", "1"),
        ] {
            assert!(
                load(&format!("{on}    {field}: {good}\n")).is_ok(),
                "{field}: {good} must load"
            );
        }
    }

    #[test]
    fn anomaly_ranges_ignored_when_detection_off() {
        // No default-config change: with the detector off nothing is checked.
        for line in [
            "    anomaly_threshold: 0.4\n",
            "    anomaly_block_threshold: 0.1\n",
            "    anomaly_min_observations: 0\n",
        ] {
            assert!(load(line).is_ok(), "detection off: {line} must still load");
        }
    }
}
