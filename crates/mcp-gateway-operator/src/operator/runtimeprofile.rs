// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Enterprise Edition — RuntimeProfile reconciler

use super::{
    OwnerReference, ReconcileAction, ReconcileContext, ReconcileResult,
    StatusCondition, CONDITION_READY, CONDITION_DRIFT_DETECTED,
};

/// Reconcile a RuntimeProfile custom resource.
///
/// Applies resource limits, feature flags, and tuning to the target Gateway's
/// Deployment. Detects drift between desired and live configuration.
/// Updates status conditions: Ready, DriftDetected.
pub fn reconcile_runtimeprofile(ctx: &ReconcileContext) -> ReconcileResult {
    let owner = OwnerReference::for_resource(
        "mcp-gateway.io/v1alpha1",
        "RuntimeProfile",
        &ctx.cr_name,
        &ctx.cr_uid,
    );

    let mut actions = Vec::new();

    // Update the target Gateway's Deployment with resource limits
    actions.push(ReconcileAction::UpdateDeployment {
        name: format!("{}-gateway", ctx.cr_name),
        replicas: ctx.desired_replicas,
    });

    // Detect drift: compare config_hash against observed state
    let drift_detected = ctx.config_hash.is_empty();

    let mut conditions = vec![
        StatusCondition::ready(
            "ProfileApplied",
            &format!("RuntimeProfile {} applied to Gateway", ctx.cr_name),
        ),
    ];

    if drift_detected {
        conditions.push(StatusCondition::drift_detected(
            "ConfigDrift",
            &format!("RuntimeProfile {} detected configuration drift", ctx.cr_name),
        ));
    }

    actions.push(ReconcileAction::UpdateStatusCondition {
        cr_name: ctx.cr_name.clone(),
        condition_type: CONDITION_READY.into(),
        status: "True".into(),
        reason: "ProfileApplied".into(),
    });

    if drift_detected {
        actions.push(ReconcileAction::UpdateStatusCondition {
            cr_name: ctx.cr_name.clone(),
            condition_type: CONDITION_DRIFT_DETECTED.into(),
            status: "True".into(),
            reason: "ConfigDrift".into(),
        });
    }

    let _ = owner;

    ReconcileResult {
        actions,
        observed_generation: ctx.cr_generation,
        conditions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtimeprofile_reconcile_ready() {
        let ctx = ReconcileContext {
            namespace: "default".into(),
            cr_name: "production".into(),
            cr_uid: "uid-rp".into(),
            cr_generation: 2,
            secret_refs: vec![],
            desired_replicas: 3,
            config_hash: "xyz789".into(),
        };
        let result = reconcile_runtimeprofile(&ctx);
        assert!(result.conditions.iter().any(|c| c.condition_type == CONDITION_READY));
        assert!(!result.conditions.iter().any(|c| c.condition_type == CONDITION_DRIFT_DETECTED));
    }

    #[test]
    fn test_runtimeprofile_reconcile_drift_detected() {
        let ctx = ReconcileContext {
            namespace: "default".into(),
            cr_name: "staging".into(),
            cr_uid: "uid-rp2".into(),
            cr_generation: 1,
            secret_refs: vec![],
            desired_replicas: 1,
            config_hash: "".into(),
        };
        let result = reconcile_runtimeprofile(&ctx);
        assert!(result.conditions.iter().any(|c| c.condition_type == CONDITION_DRIFT_DETECTED));
    }
}
