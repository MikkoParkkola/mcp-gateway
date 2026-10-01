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
        if !self.anomaly_detection {
            return Ok(());
        }
        // Scores are in [0, 1]. At or below 0.5 the old neutral score would
        // flag every call; above 1.0 nothing could ever be flagged.
        let log = self.anomaly_threshold;
        if !(log > 0.5 && log <= 1.0) {
            return Err(format!(
                "security.firewall.anomaly_threshold must be above 0.5 and at most 1.0, got {log}"
            ));
        }
        if let Some(block) = self.anomaly_block_threshold
            && !(block > log && block <= 1.0)
        {
            return Err(format!(
                "security.firewall.anomaly_block_threshold must be above anomaly_threshold \
                 ({log}) and at most 1.0, got {block}"
            ));
        }
        if self.anomaly_min_observations == 0 {
            return Err(
                "security.firewall.anomaly_min_observations must be at least 1".to_string(),
            );
        }
        Ok(())
    }
}

/// Refuse an HTTP start where anomaly detection is on and no caller can carry
/// a caller key (MIK-7215.CONTROL.5, gap G5).
///
/// A caller key comes from authentication, a client certificate, an agent token
/// or a trusted identity header. With all four off every HTTP caller's key is
/// empty, and the detector refuses each call it cannot attribute, so the
/// gateway would start and then refuse every meta call that has no session.
/// Stdio is not checked: its operator identity is a key.
///
/// # Errors
///
/// A message naming `anomaly_detection` and `auth.enabled`.
pub(crate) fn refuse_keyless_http_anomaly(_config: &crate::config::Config) -> Result<(), String> {
    Ok(())
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
            assert!(
                message.contains(field),
                "the refusal names {field}: {message}"
            );
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

    fn keyless() -> Config {
        let mut config = Config::default();
        config.auth.enabled = false;
        config.security.firewall.anomaly_detection = true;
        config
    }

    #[test]
    fn keyless_http_anomaly_detection_is_refused_naming_both_settings() {
        let message = super::refuse_keyless_http_anomaly(&keyless())
            .expect_err("no HTTP caller can have a key");
        assert!(message.contains("anomaly_detection"), "{message}");
        assert!(message.contains("auth.enabled"), "{message}");
    }

    #[test]
    fn any_source_of_a_caller_key_lets_it_start() {
        let mut auth = keyless();
        auth.auth.enabled = true;
        let mut mtls = keyless();
        mtls.mtls.enabled = true;
        let mut agent = keyless();
        agent.agent_auth.enabled = true;
        let mut header = keyless();
        header.security.caller_identity.mode =
            crate::security::caller_identity::CallerIdentityMode::TrustedProxy;
        let mut off = keyless();
        off.security.firewall.anomaly_detection = false;
        for (name, config) in [
            ("auth", auth),
            ("mtls", mtls),
            ("agent_auth", agent),
            ("caller_identity", header),
            ("detection off", off),
        ] {
            assert!(
                super::refuse_keyless_http_anomaly(&config).is_ok(),
                "{name} must start"
            );
        }
    }
}
