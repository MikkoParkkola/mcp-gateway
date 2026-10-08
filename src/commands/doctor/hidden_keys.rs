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
    "backends.<name>.max_frame_bytes",
    "backends.<name>.oauth.token_refresh_buffer_secs",
    "backends.<name>.protocol_version",
    "backends.<name>.streamable_http",
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

/// Hidden keys that `raw` sets, in table order.
pub(super) fn set_hidden_keys(raw: &serde_yaml::Value) -> Vec<&'static str> {
    HIDDEN_CONFIG_KEYS
        .iter()
        .copied()
        .filter(|key| is_set(raw, &key.split('.').collect::<Vec<_>>()))
        .collect()
}

/// Whether `value` holds something at `path`. `<name>` matches any map key; a
/// segment ending in `[]` names a list whose every item is searched.
fn is_set(value: &serde_yaml::Value, path: &[&str]) -> bool {
    let Some((head, rest)) = path.split_first() else {
        return true;
    };
    let Some(map) = value.as_mapping() else {
        return false;
    };
    if *head == "<name>" {
        return map.values().any(|child| is_set(child, rest));
    }
    if let Some(list_key) = head.strip_suffix("[]") {
        return map
            .get(list_key)
            .and_then(serde_yaml::Value::as_sequence)
            .is_some_and(|items| items.iter().any(|item| is_set(item, rest)));
    }
    map.get(*head).is_some_and(|child| is_set(child, rest))
}

/// The `doctor` row listing the hidden keys the config file at `path` sets.
///
/// `None` when the file cannot be read or parsed (the configuration check
/// already reports that) or when it sets no hidden key.
pub(super) fn check_hidden_keys(path: &Path) -> Option<CheckResult> {
    let text = std::fs::read_to_string(path).ok()?;
    let raw: serde_yaml::Value = serde_yaml::from_str(&text).ok()?;
    let set = set_hidden_keys(&raw);
    if set.is_empty() {
        return None;
    }
    Some(
        CheckResult::warn(
            "Hidden settings",
            format!("{} sets {}", path.display(), set.join(", ")),
        )
        .with_category("config")
        .with_hint("These keys are left out of the reference; each set value is still applied."),
    )
}

#[cfg(test)]
#[path = "hidden_keys_tests.rs"]
mod tests;
