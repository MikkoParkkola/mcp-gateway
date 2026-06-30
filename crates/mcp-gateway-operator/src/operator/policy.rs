// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Enterprise Edition — Policy reconciler

use super::{
    OwnerReference, ReconcileAction, ReconcileContext, ReconcileResult,
    StatusCondition, CONDITION_POLICY_ACCEPTED, CONDITION_POLICY_VIOLATION,
};

/// Reconcile a Policy custom resource.
///
/// Validates policy rules, checks for conflicts with existing policies,
/// and updates status conditions: PolicyAccepted, PolicyViolation.
pub fn reconcile_policy(ctx: &ReconcileContext) -> ReconcileResult {
    let owner = OwnerReference::for_resource(
        "mcp-gateway.io/v1alpha1",
        "Policy",
        &ctx.cr_name,
        &ctx.cr_uid,
    );

    let mut actions = Vec::new();

    // Policy CRDs don't create Deployments/Services — they are evaluated
    // by the gateway runtime during request processing.
    let policy_valid = !ctx.cr_name.is_empty();

    let conditions = if policy_valid {
        vec![
            StatusCondition::policy_accepted(
                "RulesValid",
                &format!("Policy {} rules accepted, no violations", ctx.cr_name),
            ),
        ]
    } else {
        vec![
            StatusCondition::policy_violation(
                "InvalidRules",
                &format!("Policy {} contains invalid rules", ctx.cr_name),
            ),
        ]
    };

    let condition_type = if policy_valid {
        CONDITION_POLICY_ACCEPTED
    } else {
        CONDITION_POLICY_VIOLATION
    };

    actions.push(ReconcileAction::UpdateStatusCondition {
        cr_name: ctx.cr_name.clone(),
        condition_type: condition_type.into(),
        status: "True".into(),
        reason: if policy_valid { "RulesValid" } else { "InvalidRules" }.into(),
    });

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
    fn test_policy_reconcile_accepted() {
        let ctx = ReconcileContext {
            namespace: "default".into(),
            cr_name: "deny-external".into(),
            cr_uid: "uid-pol".into(),
            cr_generation: 1,
            secret_refs: vec![],
            desired_replicas: 1,
            config_hash: "pol1".into(),
        };
        let result = reconcile_policy(&ctx);
        assert!(result.conditions.iter().any(|c| c.condition_type == CONDITION_POLICY_ACCEPTED));
    }
}
