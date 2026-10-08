// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Hidden config keys: INTERNAL and AUTO rows of `docs/design/surface-4.0.md`.
//!
//! A hidden key is still read and validated, so a value an operator set keeps
//! applying; it is only left out of the reference, `init` and the examples.
//! `doctor` names every hidden key a config file sets, so it stays findable.
//! `scripts/release/check_surface_inventory.py` fails when this table and the
//! inventory disagree.

use std::path::Path;

use figment::providers::{Format as _, Yaml};
use figment::value::{Dict, Value};

use super::CheckResult;

/// Hidden config keys in inventory form: `<name>` matches any map key and a
/// `[]` suffix steps into every list item.
pub(super) const HIDDEN_CONFIG_KEYS: &[&str] = &[
    "accounts.adapters[].clock_skew_seconds",
    "accounts.adapters[].max_lifetime_seconds",
    "accounts.limits",
    "accounts.limits.authority_bytes",
    "accounts.limits.journeys_created_per_minute",
    "accounts.limits.journeys_per_user",
    "accounts.limits.journeys_total",
    "accounts.limits.starts_per_minute_per_user",
    "accounts.limits.store_entries",
    "accounts.schema_version",
    "auth.client_circuit_breaker.failure_threshold",
    "auth.client_circuit_breaker.reset_timeout",
    "auth.client_circuit_breaker.success_threshold",
    "auth.dashboard_session",
    "auth.dashboard_session.absolute_timeout_secs",
    "auth.dashboard_session.idle_timeout_secs",
    "backends.<name>.a2a_agent_card_path",
    "backends.<name>.http_url",
    "backends.<name>.max_frame_bytes",
    "backends.<name>.oauth.token_refresh_buffer_secs",
    "backends.<name>.protocol_version",
    "backends.<name>.streamable_http",
    "backends.<name>.ws_url",
    "cache.default_ttl",
    "cache.max_entries",
    "capabilities.files.downloads_quota_bytes",
    "capabilities.name",
    "control_plane.export.max_batch",
    "control_plane.export.poll_interval_secs",
    "error_budget",
    "error_budget.capability",
    "error_budget.capability.cooldown",
    "error_budget.capability.min_samples",
    "error_budget.capability.threshold",
    "error_budget.capability.window_duration",
    "error_budget.capability.window_size",
    "error_budget.min_samples",
    "error_budget.threshold",
    "error_budget.window_duration",
    "error_budget.window_size",
    "events.dead_letter_max_bytes",
    "events.dead_letter_max_records",
    "events.default_ttl",
    "events.max_in_flight",
    "events.max_outbox",
    "events.max_outbox_per_subscription",
    "events.max_subscriptions",
    "events.max_subscriptions_per_principal",
    "events.max_ttl",
    "events.max_verified_tail",
    "events.max_verified_tail_per_principal",
    "events.min_ttl",
    "events.queue_depth",
    "events.rate_limit_per_subscription",
    "events.rate_limit_per_subscription.burst",
    "events.rate_limit_per_subscription.per_minute",
    "events.retry_base",
    "events.retry_max_attempts",
    "events.retry_window",
    "events.schedule",
    "events.schedule.max_timers",
    "events.schedule.max_timers_per_principal",
    "events.secret_rotation_grace",
    "events.seen_max_per_route",
    "events.suspend_min_attempts",
    "events.suspend_window",
    "events.verification_per_host_per_minute",
    "events.verified_tail_ttl",
    "events.watch",
    "events.watch.max_pollers",
    "events.watch.max_pollers_per_principal",
    "failsafe.circuit_breaker.failure_threshold",
    "failsafe.circuit_breaker.reset_timeout",
    "failsafe.circuit_breaker.success_threshold",
    "failsafe.health_check.interval",
    "failsafe.health_check.timeout",
    "failsafe.rate_limit.burst_size",
    "failsafe.rate_limit.requests_per_second",
    "failsafe.retry.initial_backoff",
    "failsafe.retry.max_attempts",
    "failsafe.retry.max_backoff",
    "failsafe.retry.multiplier",
    "key_server.cleanup_interval_secs",
    "key_server.max_oidc_token_age_secs",
    "key_server.max_tokens_per_identity",
    "key_server.oidc[].auto_discover",
    "key_server.token_ttl_secs",
    "meta_mcp.cache_ttl",
    "meta_mcp.projection_mode",
    "meta_mcp.prompts_resources_fetch_timeout",
    "security.firewall.anomaly_min_observations",
    "security.firewall.anomaly_threshold",
    "security.firewall.collusion.common_principals",
    "security.firewall.collusion.min_matches",
    "security.firewall.collusion.window_secs",
    "security.firewall.memory_poisoning.max_entry_size_bytes",
    "security.message_signing.replay_window",
    "server.max_body_size",
    "server.shutdown_timeout",
    "streaming.buffer_size",
    "streaming.keep_alive_interval",
    "streaming.session_reaper_interval",
    "streaming.session_ttl",
    "tasks.default_ttl_ms",
    "tasks.expiry_interval",
    "tasks.logical_budget_bytes",
    "tasks.max_per_principal",
    "tasks.max_record_bytes",
    "tasks.max_records",
    "tasks.max_workers",
    "tasks.poll_interval_ms",
    "webhooks.rate_limit",
];

/// Hidden keys that `config` sets, in table order. A key is left out when a
/// longer key under it is also set, so a section and its field are not both named.
pub(super) fn set_hidden_keys(config: &Dict) -> Vec<&'static str> {
    let set: Vec<&'static str> = HIDDEN_CONFIG_KEYS
        .iter()
        .copied()
        .filter(|key| is_set(config, &key.split('.').collect::<Vec<_>>()))
        .collect();
    set.iter()
        .copied()
        .filter(|key| {
            !set.iter().any(|other| {
                other
                    .strip_prefix(key)
                    .is_some_and(|tail| tail.starts_with('.'))
            })
        })
        .collect()
}

/// Whether `map` holds something at `path`. `<name>` matches any map key; a
/// segment ending in `[]` names a list whose every item is searched.
fn is_set(map: &Dict, path: &[&str]) -> bool {
    let Some((head, rest)) = path.split_first() else {
        return true;
    };
    let below = |child: &Value| {
        rest.is_empty() || matches!(child, Value::Dict(_, inner) if is_set(inner, rest))
    };
    if *head == "<name>" {
        return map.values().any(below);
    }
    if let Some(list_key) = head.strip_suffix("[]") {
        return match map.get(list_key) {
            Some(Value::Array(_, items)) => items.iter().any(below),
            _ => false,
        };
    }
    map.get(*head).is_some_and(below)
}

/// Read the config file for its key names, never its values.
///
/// `Config::load` has already read this path through the mode-checked reader.
/// This second read opens the way that reader does, so it reads the same file:
/// on Unix with `O_NONBLOCK | O_NOCTTY`, following a symlink (a Kubernetes
/// `ConfigMap` mount is one), and it refuses anything the opened handle does
/// not report as a regular file, so a FIFO is refused without blocking. Like
/// that reader, it sets no size limit on a config file. A regular file swapped
/// in since the first read can still be read; only its key names are
/// reported. Every error is dropped unformatted, because a parser message can
/// quote a line.
fn read_key_names(path: &Path) -> Option<Dict> {
    use std::io::Read as _;

    let mut file = open_nonblocking(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    file.read_to_string(&mut text).ok()?;
    // The loader's own reader: two equal keys keep the last, as the gateway does.
    Yaml::from_str::<Dict>(&text).ok()
}

#[cfg(unix)]
fn open_nonblocking(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(
            (rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOCTTY)
                .bits()
                .cast_signed(),
        )
        .open(path)
}

#[cfg(not(unix))]
fn open_nonblocking(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// The `doctor` row listing the advanced keys the config file at `path` sets.
///
/// A passing row, not a warning: a set value is applied, so nothing is wrong.
/// `None` when the file cannot be read or parsed (the configuration check
/// already reports that) or when it sets no such key.
pub(super) fn check_hidden_keys(path: &Path) -> Option<CheckResult> {
    let dict = read_key_names(path)?;
    let set = set_hidden_keys(&dict);
    if set.is_empty() {
        return None;
    }
    let named: Vec<String> = set
        .iter()
        .map(|key| {
            if URL_ALIASES.contains(key) && upgrade_rewrites(&dict, key) {
                format!("{key} (run mcp-gateway upgrade to rewrite it as url)")
            } else {
                (*key).to_string()
            }
        })
        .collect();
    Some(
        CheckResult::pass(
            "Advanced settings",
            format!(
                "{} sets {}. Each value is applied; these keys are not in the configuration reference.",
                path.display(),
                named.join(", ")
            ),
        )
        .with_category("config"),
    )
}

/// The older spellings of a backend's `url`, which `mcp-gateway upgrade` rewrites.
const URL_ALIASES: &[&str] = &["backends.<name>.http_url", "backends.<name>.ws_url"];

/// Whether some backend holds the alias `key` names as an address of its
/// scheme, the only kind `upgrade` rewrites. The value is tested, never shown.
fn upgrade_rewrites(dict: &Dict, key: &str) -> bool {
    let alias = key.rsplit('.').next().unwrap_or(key);
    let Some(Value::Dict(_, backends)) = dict.get("backends") else {
        return false;
    };
    backends.values().any(|backend| match backend {
        Value::Dict(_, fields) => matches!(
            fields.get(alias),
            Some(Value::String(_, address))
                if super::super::backend_url_keys::transport_key_for(address) == Some(alias)
        ),
        _ => false,
    })
}

#[cfg(test)]
#[path = "hidden_keys_tests.rs"]
mod tests;
