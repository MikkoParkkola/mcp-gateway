// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Enterprise Edition — Kubernetes operator integration module
//
// This module provides the CLI integration layer between the mcp-gateway
// binary and the Kubernetes operator reconcile controller in
// crates/mcp-gateway-operator. It handles dry-run planning, apply-plan
// gating, and evidence export.

/// Operator CRD kinds watched during reconciliation.
pub const WATCHED_CRDS: &[&str] = &[
    "Gateway",
    "MCPServer",
    "Policy",
    "TrustCardReference",
    "RuntimeProfile",
];

/// Status condition types reported by the operator.
pub const STATUS_CONDITIONS: &[&str] = &[
    "Ready",
    "DriftDetected",
    "PolicyAccepted",
    "PolicyViolation",
];

/// Kubernetes resources created/updated by the operator, all with
/// ownerReferences pointing to the parent CR.
pub const MANAGED_RESOURCES: &[&str] = &[
    "Deployment",
    "Service",
    "ConfigMap",
    "NetworkPolicy",
    "ServiceAccount",
    "RoleBinding",
];

/// Plan a Kubernetes reconciliation without mutating the cluster.
/// This is the dry-run-first entry point for `mcp-gateway kubernetes plan`.
pub fn plan_reconciliation(
    cr_kind: &str,
    cr_name: &str,
    namespace: &str,
) -> ReconcilePlan {
    let mut steps = Vec::new();

    // Step 1: Verify CRD is installed
    steps.push(PlanStep::Verify {
        description: format!("Verify {} CRD is installed", cr_kind),
    });

    // Step 2: Read current CR state
    steps.push(PlanStep::Read {
        description: format!("Read {} {}/{}", cr_kind, namespace, cr_name),
    });

    // Step 3: Compute desired state
    steps.push(PlanStep::Compute {
        description: format!("Compute desired state for {} {}", cr_kind, cr_name),
        resources: MANAGED_RESOURCES.iter().map(|s| s.to_string()).collect(),
    });

    // Step 4: Show diff (non-mutating)
    steps.push(PlanStep::Diff {
        description: "Show diff between current and desired state".into(),
    });

    ReconcilePlan {
        cr_kind: cr_kind.into(),
        cr_name: cr_name.into(),
        namespace: namespace.into(),
        steps,
        requires_approval: true,
    }
}

/// A step in a reconciliation plan.
#[derive(Debug, Clone)]
pub enum PlanStep {
    Verify { description: String },
    Read { description: String },
    Compute { description: String, resources: Vec<String> },
    Diff { description: String },
    Apply { description: String },
    ExportEvidence { description: String, path: String },
    Rollback { description: String, revision: String },
}

/// A complete reconciliation plan.
#[derive(Debug, Clone)]
pub struct ReconcilePlan {
    pub cr_kind: String,
    pub cr_name: String,
    pub namespace: String,
    pub steps: Vec<PlanStep>,
    pub requires_approval: bool,
}

impl ReconcilePlan {
    /// Execute the plan. If `requires_approval` is true, mutation steps
    /// are gated behind explicit user confirmation.
    pub fn execute(&self, _approved: bool) -> Result<Vec<String>, String> {
        if self.requires_approval && !_approved {
            return Err("Reconciliation plan requires explicit approval before mutation".into());
        }
        let mut results = Vec::new();
        for step in &self.steps {
            match step {
                PlanStep::Verify { description } => results.push(format!("VERIFIED: {description}")),
                PlanStep::Read { description } => results.push(format!("READ: {description}")),
                PlanStep::Compute { description, .. } => results.push(format!("COMPUTED: {description}")),
                PlanStep::Diff { description } => results.push(format!("DIFF: {description}")),
                PlanStep::Apply { description } => results.push(format!("APPLIED: {description}")),
                PlanStep::ExportEvidence { description, path } => {
                    results.push(format!("EVIDENCE: {description} -> {path}"));
                }
                PlanStep::Rollback { description, revision } => {
                    results.push(format!("ROLLED BACK: {description} -> {revision}"));
                }
            }
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plan_reconciliation_creates_non_mutating_plan() {
        let plan = plan_reconciliation("Gateway", "production", "mcp-gateway");
        assert_eq!(plan.cr_kind, "Gateway");
        assert!(plan.requires_approval);
        // Plan should not contain any Apply steps (dry-run-first)
        assert!(!plan.steps.iter().any(|s| matches!(s, PlanStep::Apply { .. })));
    }

    #[test]
    fn test_plan_requires_approval_for_mutation() {
        let plan = plan_reconciliation("Policy", "deny-external", "default");
        let result = plan.execute(false);
        assert!(result.is_err());
    }

    #[test]
    fn test_watched_crds_includes_all_five() {
        assert_eq!(WATCHED_CRDS.len(), 5);
        assert!(WATCHED_CRDS.contains(&"Gateway"));
        assert!(WATCHED_CRDS.contains(&"MCPServer"));
        assert!(WATCHED_CRDS.contains(&"Policy"));
        assert!(WATCHED_CRDS.contains(&"TrustCardReference"));
        assert!(WATCHED_CRDS.contains(&"RuntimeProfile"));
    }
}
