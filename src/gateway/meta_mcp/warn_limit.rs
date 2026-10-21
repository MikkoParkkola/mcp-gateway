// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A bounded, windowed "warn once" limiter keyed by a pair of labels, shared
//! by the un-keyed admission warn ((backend, tool)) and the case-B lacked
//! principal warn ((backend, caller key), MIK-8382 UNIFY.1b).

/// One warn per key per window.
pub(super) const WARN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);
/// The most keys remembered; past it expired entries go first, then the
/// oldest live one, so a key can be warned again sooner at capacity.
pub(super) const WARN_CAP: usize = 1024;

pub(super) type WarnedAt = std::collections::HashMap<(String, String), std::time::Instant>;

/// Whether (first, second) is due a warn at `now`, recording it if so. `now`
/// is a parameter so the eviction order can be tested without sleeping.
pub(super) fn first_warn(
    warned: &mut WarnedAt,
    first: &str,
    second: &str,
    now: std::time::Instant,
) -> bool {
    let key = (first.to_owned(), second.to_owned());
    if warned
        .get(&key)
        .is_some_and(|last| now.duration_since(*last) < WARN_INTERVAL)
    {
        return false;
    }
    // Labels come from caller input: bound the map. Expired entries go
    // first; a map still full of live ones loses its oldest.
    if warned.len() >= WARN_CAP {
        warned.retain(|_, last| now.duration_since(*last) < WARN_INTERVAL);
    }
    if warned.len() >= WARN_CAP
        && let Some(oldest) = warned
            .iter()
            .min_by_key(|(_, last)| **last)
            .map(|(k, _)| k.clone())
    {
        warned.remove(&oldest);
    }
    warned.insert(key, now);
    true
}

/// Count one un-keyed admission in `mcp_unkeyed_calls_total` (ADR-012).
///
/// Each arm spells its labels as literals, so the metrics macro builds a
/// static key: no label `Vec` or `Key` is allocated per call (MIK-8014
/// PERF.13a). The name, label keys and values are the series' contract; the
/// rendered series are pinned by `admission::unkeyed_metric_tests`.
pub(super) fn count_unkeyed(is_modern: bool, read_only: bool) {
    match (is_modern, read_only) {
        (true, true) => telemetry_metrics::counter!("mcp_unkeyed_calls_total", "era" => "modern", "gateway_read_only" => "true").increment(1),
        (true, false) => telemetry_metrics::counter!("mcp_unkeyed_calls_total", "era" => "modern", "gateway_read_only" => "false").increment(1),
        (false, true) => telemetry_metrics::counter!("mcp_unkeyed_calls_total", "era" => "legacy", "gateway_read_only" => "true").increment(1),
        (false, false) => telemetry_metrics::counter!("mcp_unkeyed_calls_total", "era" => "legacy", "gateway_read_only" => "false").increment(1),
    }
}
