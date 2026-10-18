// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reading the ranking signals a catalogue entry carries, each with its
//! default when absent.

use serde_json::Value;

pub(super) fn parse_numeric_signal(value: &Value, keys: &[&str], default: f64) -> f64 {
    parse_optional_numeric_signal(value, keys).unwrap_or(default)
}

fn parse_optional_numeric_signal(value: &Value, keys: &[&str]) -> Option<f64> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_f64))
        .map(|score| score.clamp(0.0, 1.0))
}

pub(super) fn parse_safety_signal(value: &Value) -> f64 {
    if value
        .get("unsafe")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return 0.0;
    }
    if value
        .get("risk_level")
        .or_else(|| value.get("risk"))
        .and_then(Value::as_str)
        .is_some_and(|risk| matches!(risk, "high" | "critical" | "unsafe"))
    {
        return 0.0;
    }
    parse_numeric_signal(value, &["safety_score", "safety"], 1.0)
}

pub(super) fn parse_risk_signal(value: &Value) -> f64 {
    if let Some(level) = value
        .get("risk_level")
        .or_else(|| value.get("risk"))
        .and_then(Value::as_str)
    {
        return match level.to_ascii_lowercase().as_str() {
            "critical" | "high" | "unsafe" | "blocked" => 0.0,
            "medium" | "elevated" => 0.65,
            "low" => 0.9,
            _ => 1.0,
        };
    }
    if let Some(fit) =
        parse_optional_numeric_signal(value, &["risk_fit_score", "risk_fit", "risk_safety_score"])
    {
        return fit;
    }
    if let Some(score) = value.get("risk_score").and_then(Value::as_f64) {
        // `risk_score` is interpreted as risk severity, where higher means
        // riskier. `risk_fit` aliases above represent the inverse.
        return (1.0 - score).clamp(0.0, 1.0);
    }
    1.0
}

pub(super) fn parse_grant_signal(value: &Value) -> f64 {
    if value.get("authorized").and_then(Value::as_bool) == Some(false) {
        return 0.0;
    }
    if value
        .get("grant_status")
        .or_else(|| value.get("grant"))
        .and_then(Value::as_str)
        .is_some_and(|grant| matches!(grant, "denied" | "missing" | "unauthorized"))
    {
        return 0.0;
    }
    parse_numeric_signal(value, &["grant_score", "grant"], 1.0)
}

pub(super) fn parse_permission_fit_signal(value: &Value, grant_default: f64) -> f64 {
    if value.get("authorized").and_then(Value::as_bool) == Some(false) {
        return 0.0;
    }
    if value
        .get("permission_status")
        .or_else(|| value.get("grant_status"))
        .or_else(|| value.get("permission"))
        .or_else(|| value.get("grant"))
        .and_then(Value::as_str)
        .is_some_and(|grant| matches!(grant, "denied" | "missing" | "unauthorized"))
    {
        return 0.0;
    }
    parse_optional_numeric_signal(
        value,
        &[
            "permission_fit_score",
            "permission_fit",
            "permission_score",
            "grant_score",
            "grant",
        ],
    )
    .unwrap_or(grant_default)
}

pub(super) fn parse_policy_fit_signal(value: &Value) -> f64 {
    if value
        .get("policy_denied")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return 0.0;
    }
    if let Some(verdict) = value
        .get("policy_verdict")
        .or_else(|| value.get("policy_decision"))
        .or_else(|| value.get("policy"))
        .and_then(Value::as_str)
    {
        return match verdict.to_ascii_lowercase().as_str() {
            "deny" | "denied" | "block" | "blocked" | "quarantine" | "rejected" => 0.0,
            "warn" | "warning" | "advisory" | "review" => 0.65,
            _ => 1.0,
        };
    }
    parse_numeric_signal(
        value,
        &[
            "policy_fit_score",
            "policy_fit",
            "policy_score",
            "license_policy_fit",
        ],
        1.0,
    )
}

pub(super) fn parse_runtime_health_signal(value: &Value) -> f64 {
    if value
        .get("status")
        .or_else(|| value.get("runtime_status"))
        .and_then(Value::as_str)
        .is_some_and(|status| matches!(status, "disabled" | "unhealthy" | "down"))
    {
        return 0.0;
    }
    if value
        .get("health")
        .and_then(Value::as_str)
        .is_some_and(|health| matches!(health, "unhealthy" | "down"))
    {
        return 0.0;
    }
    parse_numeric_signal(value, &["runtime_health", "health_score"], 1.0)
}

pub(super) fn parse_success_rate_signal(value: &Value) -> f64 {
    if let Some(rate) = parse_optional_numeric_signal(
        value,
        &["success_rate", "success_score", "reliability_score"],
    ) {
        return rate;
    }
    if let Some(percent) = value.get("success_rate_percent").and_then(Value::as_f64) {
        return (percent / 100.0).clamp(0.0, 1.0);
    }
    let successes = value.get("success_count").and_then(Value::as_u64);
    let failures = value.get("failure_count").and_then(Value::as_u64);
    if let (Some(successes), Some(failures)) = (successes, failures) {
        let total = successes.saturating_add(failures);
        if total > 0 {
            #[allow(clippy::cast_precision_loss)]
            {
                return (successes as f64 / total as f64).clamp(0.0, 1.0);
            }
        }
    }
    1.0
}

pub(super) fn parse_cost_efficiency_signal(value: &Value) -> f64 {
    if let Some(score) = value.get("cost_efficiency").and_then(Value::as_f64) {
        return score.clamp(0.0, 1.0);
    }
    if let Some(category) = value
        .get("cost_category")
        .or_else(|| value.get("cost_tier"))
        .and_then(Value::as_str)
    {
        return match category {
            "free" => 1.0,
            "low" => 0.85,
            "medium" => 0.65,
            "high" => 0.35,
            _ => 0.75,
        };
    }
    if let Some(cost) = value.get("cost_usd").and_then(Value::as_f64) {
        return (1.0 / (1.0 + (cost * 100.0))).clamp(0.0, 1.0);
    }
    1.0
}

pub(super) fn parse_latency_signal(value: &Value) -> f64 {
    if let Some(score) = value.get("latency_score").and_then(Value::as_f64) {
        return score.clamp(0.0, 1.0);
    }
    if let Some(latency_ms) = value.get("latency_ms").and_then(Value::as_f64) {
        return (1.0 / (1.0 + (latency_ms / 1000.0))).clamp(0.0, 1.0);
    }
    1.0
}
