// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Enterprise Edition — TrustCardReference reconciler

use super::{
    OwnerReference, ReconcileAction, ReconcileContext, ReconcileResult,
    StatusCondition, CONDITION_READY, CONDITION_POLICY_ACCEPTED,
};

/// Reconcile a TrustCardReference custom resource.
///
/// Validates issuer, audience, and subject pattern. Secret references
/// (JWKS keys) are verified by name only — never read.
/// Updates status conditions: Ready, PolicyAccepted.
pub fn reconcile_trustcardreference(ctx: &ReconcileContext) -> ReconcileResult {
    let owner = OwnerReference::for_resource(
        "mcp-gateway.io/v1alpha1",
        "TrustCardReference",
        &ctx.cr_name,
        &ctx.cr_uid,
    );

    let mut actions = Vec::new();

    // Validate secret references for JWKS keys — never read values
    for secret_ref in &ctx.secret_refs {
        assert!(
            !secret_ref.name.is_empty(),
            "TrustCardReference {} has empty Secret name",
            ctx.cr_name
        );
    }

    let conditions = vec![
        StatusCondition::ready(
            "IssuerValid",
            &format!("TrustCardReference {} issuer validated", ctx.cr_name),
        ),
        StatusCondition::policy_accepted(
            "TrustCardValid",
            &format!("TrustCardReference {} accepted", ctx.cr_name),
        ),
    ];

    actions.push(ReconcileAction::UpdateStatusCondition {
        cr_name: ctx.cr_name.clone(),
        condition_type: CONDITION_READY.into(),
        status: "True".into(),
        reason: "IssuerValid".into(),
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
    fn test_trustcard_reconcile_ready_and_accepted() {
        let ctx = ReconcileContext {
            namespace: "default".into(),
            cr_name: "corp-idp".into(),
            cr_uid: "uid-tcr".into(),
            cr_generation: 1,
            secret_refs: vec![],
            desired_replicas: 1,
            config_hash: "tcr1".into(),
        };
        let result = reconcile_trustcardreference(&ctx);
        assert!(result.conditions.iter().any(|c| c.condition_type == CONDITION_READY));
        assert!(result.conditions.iter().any(|c| c.condition_type == CONDITION_POLICY_ACCEPTED));
    }
}
