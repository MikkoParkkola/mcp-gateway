// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Enterprise Edition — Status condition helpers

use super::{StatusCondition, CONDITION_READY, CONDITION_DRIFT_DETECTED,
            CONDITION_POLICY_ACCEPTED, CONDITION_POLICY_VIOLATION};

/// Build a status.conditions patch for the Kubernetes API.
/// Returns a JSON-compatible structure with observedGeneration and conditions.
pub fn build_status_patch(
    observed_generation: i64,
    conditions: &[StatusCondition],
) -> serde_json::Value {
    let conditions_array: Vec<serde_json::Value> = conditions
        .iter()
        .map(|c| {
            serde_json::json!({
                "type": c.condition_type,
                "status": c.status,
                "reason": c.reason,
                "message": c.message,
                "lastTransitionTime": chrono::Utc::now().to_rfc3339(),
            })
        })
        .collect();

    serde_json::json!({
        "status": {
            "observedGeneration": observed_generation,
            "conditions": conditions_array,
        }
    })
}

/// Validate that a condition type is one of the known types.
pub fn is_valid_condition_type(condition_type: &str) -> bool {
    matches!(
        condition_type,
        CONDITION_READY | CONDITION_DRIFT_DETECTED | CONDITION_POLICY_ACCEPTED | CONDITION_POLICY_VIOLATION
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_status_patch_includes_observed_generation() {
        let conditions = vec![StatusCondition::ready("OK", "all good")];
        let patch = build_status_patch(42, &conditions);
        assert_eq!(patch["status"]["observedGeneration"], 42);
        assert_eq!(patch["status"]["conditions"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_valid_condition_types() {
        assert!(is_valid_condition_type(CONDITION_READY));
        assert!(is_valid_condition_type(CONDITION_DRIFT_DETECTED));
        assert!(is_valid_condition_type(CONDITION_POLICY_ACCEPTED));
        assert!(is_valid_condition_type(CONDITION_POLICY_VIOLATION));
        assert!(!is_valid_condition_type("Unknown"));
    }
}
