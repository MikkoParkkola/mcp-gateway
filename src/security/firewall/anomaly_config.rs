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
    /// Refuse rule globs, anomaly thresholds and relay settings that cannot
    /// mean what they say.
    ///
    /// Rule `match` globs are checked only when the firewall is on.
    /// Anomaly thresholds are checked only when `anomaly_detection` is on,
    /// relay settings only when `collusion.action` is not `off`, so a config
    /// that enables neither loads exactly as before.
    ///
    /// # Errors
    ///
    /// A message naming the first out-of-range field.
    pub fn validate(&self) -> Result<(), String> {
        // A `match` glob that does not parse would fail open at runtime, so it
        // is refused while the rules can run. The message names the rule's
        // path, not its text.
        if self.enabled
            && let Some(i) = self
                .rules
                .iter()
                .position(|rule| glob::Pattern::new(&rule.tool_match).is_err())
        {
            return Err(format!(
                "security.firewall.rules[{i}].match is not a valid glob"
            ));
        }
        if self.enabled {
            for (i, rule) in self.rules.iter().enumerate() {
                validate_rule_scope(i, rule)?;
                super::allowed_root::validate_rule(i, rule)?;
            }
        }
        // Relay detection is independent of anomaly detection: checked first.
        self.collusion.validate(self.enabled)?;
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

const KEYLESS_HTTP: &str = "security.firewall.anomaly_detection is on but auth.enabled is off, \
    and no client certificate, agent token or identity header can name a caller either: every \
    HTTP call without a session would be refused unscored. Turn auth.enabled on, or \
    anomaly_detection off";

/// Refuse an HTTP start where anomaly detection is on and no caller can carry
/// a caller key (MIK-7215.CONTROL.5, gap G5).
///
/// A caller key comes from authentication, a client certificate, an agent token
/// or a trusted identity header. With all four off every HTTP caller's key is
/// empty, and the detector refuses each call it cannot attribute, so the
/// gateway would start and then refuse every meta call that has no session.
/// Stdio is not checked: it serves the one local operator.
///
/// # Errors
///
/// A message naming `anomaly_detection` and `auth.enabled`.
pub(crate) fn refuse_keyless_http_anomaly(config: &crate::config::Config) -> Result<(), String> {
    let keyed = config.auth.enabled
        || config.mtls.enabled
        || config.agent_auth.enabled
        || config.security.caller_identity.mode
            != crate::security::caller_identity::CallerIdentityMode::Off;
    let firewall = &config.security.firewall;
    if firewall.enabled && firewall.anomaly_detection && !keyed {
        return Err(KEYLESS_HTTP.to_owned());
    }
    Ok(())
}

/// The scope keys of rule `i` (`servers`, `keys`, `except`): an absent key
/// means unscoped, so an empty list is refused rather than read as "nothing";
/// every glob must parse; an exception must set a field. Paths, never values.
fn validate_rule_scope(i: usize, rule: &super::FirewallRule) -> Result<(), String> {
    let path = format!("security.firewall.rules[{i}]");
    let invalid = |glob: &str| glob::Pattern::new(glob).is_err();
    for (key, empty) in [
        ("servers", rule.servers.as_ref().is_some_and(Vec::is_empty)),
        ("keys", rule.keys.as_ref().is_some_and(Vec::is_empty)),
        ("except", rule.except.as_ref().is_some_and(Vec::is_empty)),
    ] {
        if empty {
            return Err(format!(
                "{path}.{key} must not be empty; leave it out to apply to all"
            ));
        }
    }
    if let Some(j) = rule.servers.iter().flatten().position(|g| invalid(g)) {
        return Err(format!("{path}.servers[{j}] is not a valid glob"));
    }
    for (j, entry) in rule.except.iter().flatten().enumerate() {
        if entry.server.is_none() && entry.tool.is_none() && entry.key.is_none() {
            return Err(format!("{path}.except[{j}] sets no field"));
        }
        for (field, glob) in [("server", &entry.server), ("tool", &entry.tool)] {
            if glob.as_deref().is_some_and(invalid) {
                return Err(format!("{path}.except[{j}].{field} is not a valid glob"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::config::Config;

    fn load(anomaly: &str) -> crate::Result<()> {
        let yaml = format!("security:\n  firewall:\n{anomaly}");
        let config: Config = crate::yaml::from_str(&yaml).expect("the YAML parses");
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
        config.security.firewall.enabled = true;
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
        // A disabled firewall scores nothing, so its detector flag is dormant.
        let mut dormant = keyless();
        dormant.security.firewall.enabled = false;
        for (name, config) in [
            ("auth", auth),
            ("mtls", mtls),
            ("agent_auth", agent),
            ("caller_identity", header),
            ("detection off", off),
            ("firewall off", dormant),
        ] {
            assert!(
                super::refuse_keyless_http_anomaly(&config).is_ok(),
                "{name} must start"
            );
        }
    }
}
