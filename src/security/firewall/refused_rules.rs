// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rules the firewall-on load refuses, and the reload that would otherwise
//! slip them in. `security.firewall.enabled` and `auth.enabled` change only
//! on a restart, while a reload's rules join the running firewall at once: a
//! reload is judged against the firewall and the authentication that run.

use crate::config::Config;

use super::FirewallRule;

/// Whether the firewall runs: decided at startup, which builds it once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FirewallRuns {
    On,
    Off,
}

impl FirewallRuns {
    /// The state `running`, the config the gateway started with, put in place.
    pub(crate) fn of(running: &Config) -> Self {
        if running.security.firewall.enabled {
            Self::On
        } else {
            Self::Off
        }
    }
}

/// The API keys a rule's `keys` and exceptions' `key` can name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuleKeys<'a> {
    /// API-key authentication is on, with these keys.
    Configured(Vec<&'a str>),
    /// No caller carries a key: authentication is off, or has no API keys.
    AuthOff,
}

impl<'a> RuleKeys<'a> {
    /// What `config`'s own `auth` section offers.
    pub(crate) fn of(config: &'a Config) -> Self {
        let auth = &config.auth;
        if auth.enabled && !auth.api_keys.is_empty() {
            Self::Configured(auth.api_keys.iter().map(|key| key.name.as_str()).collect())
        } else {
            Self::AuthOff
        }
    }

    /// What a reload of `candidate` offers while `running` runs: keys reload
    /// live, but whether authentication is on is the running process's.
    fn running(running: &Config, candidate: &'a Config) -> Self {
        match Self::of(running) {
            Self::AuthOff => Self::AuthOff,
            Self::Configured(_) => Self::of(candidate),
        }
    }
}

/// Rule `i`'s `keys` entries and exceptions' `key` must name a configured API
/// key, and need API-key authentication to match anything: a rule that
/// matched no caller could leave a `block` unapplied.
pub(crate) fn key_problem(
    i: usize,
    rule: &FirewallRule,
    keys: &RuleKeys<'_>,
) -> Result<(), String> {
    let path = format!("security.firewall.rules[{i}]");
    let named = rule
        .keys
        .iter()
        .flatten()
        .enumerate()
        .map(|(j, k)| (format!("{path}.keys[{j}]"), k));
    let excepted = rule
        .except
        .iter()
        .flatten()
        .enumerate()
        .filter_map(|(j, e)| {
            e.key
                .as_ref()
                .map(|k| (format!("{path}.except[{j}].key"), k))
        });
    for (at, name) in named.chain(excepted) {
        match keys {
            RuleKeys::AuthOff => {
                return Err(format!(
                    "{at} needs API-key authentication (auth.enabled with auth.api_keys)"
                ));
            }
            RuleKeys::Configured(known) if !known.contains(&name.as_str()) => {
                return Err(format!("{at} names no configured API key"));
            }
            RuleKeys::Configured(_) => {}
        }
    }
    Ok(())
}

/// The remedy a refusal names when the firewall runs.
const FIX_OR_RESTART_OFF: &str =
    "; fix or remove the rule, or set security.firewall.enabled: false and restart the gateway";
/// The remedy when the running process has no API-key callers yet.
const KEYS_NEED_RESTART: &str =
    "; remove the keyed reference, or restart the gateway so auth.enabled takes effect";

/// A reload of `candidate` while `running` runs: refused when it carries a
/// rule the firewall-on load refuses, whatever `candidate` says about
/// `enabled`, and when it names a key the running process cannot match. The
/// order is the load's: key references, then `match` globs, then scopes and
/// folder rules.
pub(crate) fn refuse_while_running(running: &Config, candidate: &Config) -> Result<(), String> {
    if FirewallRuns::of(running) == FirewallRuns::Off {
        return Ok(());
    }
    let rules = &candidate.security.firewall.rules;
    let own = RuleKeys::of(candidate);
    let live = RuleKeys::running(running, candidate);
    for (i, rule) in rules.iter().enumerate() {
        key_problem(i, rule, &own).map_err(|e| e + FIX_OR_RESTART_OFF)?;
        key_problem(i, rule, &live).map_err(|e| e + KEYS_NEED_RESTART)?;
    }
    for (i, rule) in rules.iter().enumerate() {
        super::verdict::glob_problem(i, rule).map_err(|e| e + FIX_OR_RESTART_OFF)?;
    }
    for (i, rule) in rules.iter().enumerate() {
        super::verdict::scope_problem(i, rule).map_err(|e| e + FIX_OR_RESTART_OFF)?;
        super::allowed_root::validate_rule(i, rule).map_err(|e| e + FIX_OR_RESTART_OFF)?;
    }
    Ok(())
}
