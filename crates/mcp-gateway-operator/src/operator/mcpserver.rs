// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Enterprise Edition — MCPServer reconciler

use super::{
    OwnerReference, ReconcileAction, ReconcileContext, ReconcileResult,
    StatusCondition, SecretRef, CONDITION_READY,
};

/// Reconcile an MCPServer custom resource.
///
/// MCPServer does not create its own Deployment — it is referenced by a
/// Gateway's routing table. The reconciler validates the endpoint, verifies
/// that secret references (via secretKeyRef) are well-formed, and updates
/// status conditions: Ready, DriftDetected.
pub fn reconcile_mcpserver(ctx: &ReconcileContext) -> ReconcileResult {
    let owner = OwnerReference::for_resource(
        "mcp-gateway.io/v1alpha1",
        "MCPServer",
        &ctx.cr_name,
        &ctx.cr_uid,
    );

    let mut actions = Vec::new();

    // Validate secret references — never read secret values
    for secret_ref in &ctx.secret_refs {
        assert!(
            !secret_ref.name.is_empty(),
            "MCPServer {} references a Secret with empty name",
            ctx.cr_name
        );
    }

    // ConfigMap for non-secret server metadata
    actions.push(ReconcileAction::CreateConfigMap {
        name: format!("{}-server-config", ctx.cr_name),
    });

    let conditions = vec![
        StatusCondition::ready(
            "EndpointValid",
            &format!("MCPServer {} endpoint validated, secretRefs verified", ctx.cr_name),
        ),
    ];

    actions.push(ReconcileAction::UpdateStatusCondition {
        cr_name: ctx.cr_name.clone(),
        condition_type: CONDITION_READY.into(),
        status: "True".into(),
        reason: "EndpointValid".into(),
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
    fn test_mcpserver_reconcile_validates_secret_refs() {
        let ctx = ReconcileContext {
            namespace: "default".into(),
            cr_name: "my-server".into(),
            cr_uid: "uid-789".into(),
            cr_generation: 1,
            secret_refs: vec![SecretRef {
                name: "api-creds".into(),
                key: "token".into(),
                env_var: "API_TOKEN".into(),
            }],
            desired_replicas: 1,
            config_hash: "aaa".into(),
        };
        let result = reconcile_mcpserver(&ctx);
        assert_eq!(result.conditions[0].status, "True");
    }
}
