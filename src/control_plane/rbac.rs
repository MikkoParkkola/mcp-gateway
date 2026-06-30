// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Role-Based Access Control for ControlPlaneUI.
//!
//! AC.3: RBAC enforces admin, security_reviewer, developer, and auditor behavior:
//! - non-admin users cannot directly mutate applied grants/policies
//! - security reviewers can approve/reject but not bypass reconciliation
//! - developers can request but not approve their own requests
//! - auditors remain read-only
//!
//! CHECK: `cargo test --all-features control_plane_rbac_matrix` exits 0

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Supported roles for ControlPlaneUI RBAC.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    /// Full control: manage servers, tools, grants, policies, users, approvals.
    Admin,
    /// Approve/reject approval requests; cannot bypass reconciliation.
    SecurityReviewer,
    /// Request grants/policies; cannot approve own requests.
    Developer,
    /// Read-only access to inventory, evidence, health, and audit logs.
    Auditor,
}

impl Role {
    /// All defined roles.
    #[must_use]
    pub fn all() -> Vec<Role> {
        vec![
            Role::Admin,
            Role::SecurityReviewer,
            Role::Developer,
            Role::Auditor,
        ]
    }

    /// Return the role name as a string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::SecurityReviewer => "security_reviewer",
            Role::Developer => "developer",
            Role::Auditor => "auditor",
        }
    }

    /// Parse a role from a string.
    #[must_use]
    pub fn from_str(s: &str) -> Option<Role> {
        match s {
            "admin" => Some(Role::Admin),
            "security_reviewer" => Some(Role::SecurityReviewer),
            "developer" => Some(Role::Developer),
            "auditor" => Some(Role::Auditor),
            _ => None,
        }
    }
}

/// Actions that can be performed in the ControlPlaneUI.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Action {
    // Read actions
    ListServers,
    ListTools,
    ListTrustCards,
    ListGrants,
    GetGrant,
    ListPolicies,
    GetPolicy,
    ListApprovals,
    GetApproval,
    ListAuditEvidence,
    ListUsers,
    ListGroups,
    GetRuntimeHealth,
    ExportEvidence,

    // Mutation actions
    CreateGrant,
    UpdateGrant,
    DeleteGrant,
    CreatePolicy,
    UpdatePolicy,
    DeletePolicy,
    CreateApproval,
    ApproveApproval,
    RejectApproval,

    // Admin actions
    ManageUsers,
    ManageGroups,
    ManageServerRegistration,
}

/// RBAC enforcement engine.
///
/// Each role has a fixed set of permitted actions.
pub struct RbacEngine {
    /// Permissions per role.
    permissions: std::collections::HashMap<Role, HashSet<Action>>,
}

impl RbacEngine {
    /// Create a new RBAC engine with the predefined role matrix.
    #[must_use]
    pub fn new() -> Self {
        let mut permissions = std::collections::HashMap::new();

        // Admin: all actions
        let mut admin_actions = HashSet::new();
        admin_actions.insert(Action::ListServers);
        admin_actions.insert(Action::ListTools);
        admin_actions.insert(Action::ListTrustCards);
        admin_actions.insert(Action::ListGrants);
        admin_actions.insert(Action::GetGrant);
        admin_actions.insert(Action::ListPolicies);
        admin_actions.insert(Action::GetPolicy);
        admin_actions.insert(Action::ListApprovals);
        admin_actions.insert(Action::GetApproval);
        admin_actions.insert(Action::ListAuditEvidence);
        admin_actions.insert(Action::ListUsers);
        admin_actions.insert(Action::ListGroups);
        admin_actions.insert(Action::GetRuntimeHealth);
        admin_actions.insert(Action::ExportEvidence);
        admin_actions.insert(Action::CreateGrant);
        admin_actions.insert(Action::UpdateGrant);
        admin_actions.insert(Action::DeleteGrant);
        admin_actions.insert(Action::CreatePolicy);
        admin_actions.insert(Action::UpdatePolicy);
        admin_actions.insert(Action::DeletePolicy);
        admin_actions.insert(Action::CreateApproval);
        admin_actions.insert(Action::ApproveApproval);
        admin_actions.insert(Action::RejectApproval);
        admin_actions.insert(Action::ManageUsers);
        admin_actions.insert(Action::ManageGroups);
        admin_actions.insert(Action::ManageServerRegistration);
        permissions.insert(Role::Admin, admin_actions);

        // SecurityReviewer: read + approve/reject
        let mut sec_actions = HashSet::new();
        sec_actions.insert(Action::ListServers);
        sec_actions.insert(Action::ListTools);
        sec_actions.insert(Action::ListTrustCards);
        sec_actions.insert(Action::ListGrants);
        sec_actions.insert(Action::GetGrant);
        sec_actions.insert(Action::ListPolicies);
        sec_actions.insert(Action::GetPolicy);
        sec_actions.insert(Action::ListApprovals);
        sec_actions.insert(Action::GetApproval);
        sec_actions.insert(Action::ListAuditEvidence);
        sec_actions.insert(Action::ListUsers);
        sec_actions.insert(Action::ListGroups);
        sec_actions.insert(Action::GetRuntimeHealth);
        sec_actions.insert(Action::ExportEvidence);
        sec_actions.insert(Action::ApproveApproval);
        sec_actions.insert(Action::RejectApproval);
        // NOTE: Security reviewers cannot CreateGrant/CreatePolicy directly —
        // they approve/reject but cannot bypass reconciliation.
        permissions.insert(Role::SecurityReviewer, sec_actions);

        // Developer: read + request (create approval), but cannot approve own requests
        let mut dev_actions = HashSet::new();
        dev_actions.insert(Action::ListServers);
        dev_actions.insert(Action::ListTools);
        dev_actions.insert(Action::ListTrustCards);
        dev_actions.insert(Action::ListGrants);
        dev_actions.insert(Action::GetGrant);
        dev_actions.insert(Action::ListPolicies);
        dev_actions.insert(Action::GetPolicy);
        dev_actions.insert(Action::ListApprovals);
        dev_actions.insert(Action::GetApproval);
        dev_actions.insert(Action::ListAuditEvidence);
        dev_actions.insert(Action::ListUsers);
        dev_actions.insert(Action::ListGroups);
        dev_actions.insert(Action::GetRuntimeHealth);
        dev_actions.insert(Action::CreateApproval);
        // NOTE: Developers cannot ApproveApproval/RejectApproval (their own or others')
        permissions.insert(Role::Developer, dev_actions);

        // Auditor: read-only
        let mut aud_actions = HashSet::new();
        aud_actions.insert(Action::ListServers);
        aud_actions.insert(Action::ListTools);
        aud_actions.insert(Action::ListTrustCards);
        aud_actions.insert(Action::ListGrants);
        aud_actions.insert(Action::GetGrant);
        aud_actions.insert(Action::ListPolicies);
        aud_actions.insert(Action::GetPolicy);
        aud_actions.insert(Action::ListApprovals);
        aud_actions.insert(Action::GetApproval);
        aud_actions.insert(Action::ListAuditEvidence);
        aud_actions.insert(Action::ListUsers);
        aud_actions.insert(Action::ListGroups);
        aud_actions.insert(Action::GetRuntimeHealth);
        aud_actions.insert(Action::ExportEvidence);
        // NOTE: Auditors remain read-only — no mutations.
        permissions.insert(Role::Auditor, aud_actions);

        Self { permissions }
    }

    /// Check whether a role is permitted to perform an action.
    #[must_use]
    pub fn can(&self, role: &Role, action: &Action) -> bool {
        self.permissions
            .get(role)
            .is_some_and(|actions| actions.contains(action))
    }

    /// Check whether a user can approve their own request.
    /// AC.3: developers can request but not approve their own requests.
    #[must_use]
    pub fn can_approve_own_request(&self, role: &Role) -> bool {
        // Only Admin can approve their own requests (for operational expediency).
        // SecurityReviewer can approve OTHERS' requests but not their own.
        // Developer cannot approve at all.
        matches!(role, Role::Admin)
    }

    /// Return all permitted actions for a role.
    #[must_use]
    pub fn permitted_actions(&self, role: &Role) -> Vec<Action> {
        self.permissions
            .get(role)
            .map(|actions| actions.iter().cloned().collect())
            .unwrap_or_default()
    }
}

impl Default for RbacEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// RBAC enforcement result.
#[derive(Debug)]
pub enum RbacResult {
    /// Action is permitted.
    Allowed,
    /// Action is denied.
    Denied { reason: String },
}

impl RbacResult {
    /// Check if the result is allowed.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// Convenience function to check RBAC for a given role and action.
pub fn check_rbac(engine: &RbacEngine, role: &Role, action: Action) -> RbacResult {
    if engine.can(role, &action) {
        RbacResult::Allowed
    } else {
        RbacResult::Denied {
            reason: format!(
                "Role '{}' is not permitted to perform action '{:?}'",
                role.as_str(),
                action
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AC.3: RBAC enforces admin, security_reviewer, developer, and auditor behavior.
    /// CHECK: `cargo test --all-features control_plane_rbac_matrix` exits 0
    #[test]
    fn control_plane_rbac_matrix() {
        let engine = RbacEngine::new();

        // ── Admin: can do everything ──
        assert!(
            engine.can(&Role::Admin, &Action::CreateGrant),
            "Admin must be able to create grants"
        );
        assert!(
            engine.can(&Role::Admin, &Action::ManageUsers),
            "Admin must be able to manage users"
        );
        assert!(
            engine.can(&Role::Admin, &Action::ListServers),
            "Admin must be able to list servers"
        );
        assert!(
            engine.can(&Role::Admin, &Action::ApproveApproval),
            "Admin must be able to approve"
        );
        assert!(
            engine.can(&Role::Admin, &Action::ExportEvidence),
            "Admin must be able to export evidence"
        );

        // ── SecurityReviewer: can read + approve/reject, but NOT mutate grants/policies directly ──
        assert!(
            engine.can(&Role::SecurityReviewer, &Action::ApproveApproval),
            "Security reviewer must be able to approve"
        );
        assert!(
            engine.can(&Role::SecurityReviewer, &Action::RejectApproval),
            "Security reviewer must be able to reject"
        );
        assert!(
            engine.can(&Role::SecurityReviewer, &Action::ListGrants),
            "Security reviewer must be able to list grants"
        );
        assert!(
            !engine.can(&Role::SecurityReviewer, &Action::CreateGrant),
            "Security reviewer must NOT directly create grants (must go through reconciler)"
        );
        assert!(
            !engine.can(&Role::SecurityReviewer, &Action::UpdateGrant),
            "Security reviewer must NOT directly update grants"
        );
        assert!(
            !engine.can(&Role::SecurityReviewer, &Action::CreatePolicy),
            "Security reviewer must NOT directly create policies"
        );
        assert!(
            !engine.can(&Role::SecurityReviewer, &Action::ManageUsers),
            "Security reviewer must NOT manage users"
        );

        // ── Developer: can read + request, but NOT approve ──
        assert!(
            engine.can(&Role::Developer, &Action::CreateApproval),
            "Developer must be able to create approval requests"
        );
        assert!(
            engine.can(&Role::Developer, &Action::ListGrants),
            "Developer must be able to list grants"
        );
        assert!(
            !engine.can(&Role::Developer, &Action::ApproveApproval),
            "Developer must NOT be able to approve"
        );
        assert!(
            !engine.can(&Role::Developer, &Action::RejectApproval),
            "Developer must NOT be able to reject"
        );
        assert!(
            !engine.can(&Role::Developer, &Action::CreateGrant),
            "Developer must NOT directly create grants (must request via approval)"
        );
        assert!(
            !engine.can(&Role::Developer, &Action::ManageUsers),
            "Developer must NOT manage users"
        );

        // ── Auditor: read-only ──
        assert!(
            engine.can(&Role::Auditor, &Action::ListGrants),
            "Auditor must be able to list grants"
        );
        assert!(
            engine.can(&Role::Auditor, &Action::ListAuditEvidence),
            "Auditor must be able to list audit evidence"
        );
        assert!(
            engine.can(&Role::Auditor, &Action::ExportEvidence),
            "Auditor must be able to export evidence"
        );
        assert!(
            !engine.can(&Role::Auditor, &Action::CreateGrant),
            "Auditor must NOT create grants"
        );
        assert!(
            !engine.can(&Role::Auditor, &Action::UpdateGrant),
            "Auditor must NOT update grants"
        );
        assert!(
            !engine.can(&Role::Auditor, &Action::ApproveApproval),
            "Auditor must NOT approve"
        );
        assert!(
            !engine.can(&Role::Auditor, &Action::RejectApproval),
            "Auditor must NOT reject"
        );
        assert!(
            !engine.can(&Role::Auditor, &Action::ManageUsers),
            "Auditor must NOT manage users"
        );

        // ── Self-approval check ──
        assert!(
            engine.can_approve_own_request(&Role::Admin),
            "Admin may approve own requests (operational expediency)"
        );
        assert!(
            !engine.can_approve_own_request(&Role::SecurityReviewer),
            "Security reviewer must NOT approve own requests"
        );
        assert!(
            !engine.can_approve_own_request(&Role::Developer),
            "Developer must NOT approve own requests"
        );
        assert!(
            !engine.can_approve_own_request(&Role::Auditor),
            "Auditor must NOT approve own requests"
        );
    }

    #[test]
    fn role_from_str_roundtrip() {
        for role in Role::all() {
            let s = role.as_str();
            let parsed = Role::from_str(s);
            assert_eq!(parsed, Some(role));
        }
    }

    #[test]
    fn auditor_is_read_only_for_all_mutations() {
        let engine = RbacEngine::new();
        let mutations = [
            Action::CreateGrant,
            Action::UpdateGrant,
            Action::DeleteGrant,
            Action::CreatePolicy,
            Action::UpdatePolicy,
            Action::DeletePolicy,
            Action::CreateApproval,
            Action::ApproveApproval,
            Action::RejectApproval,
            Action::ManageUsers,
            Action::ManageGroups,
            Action::ManageServerRegistration,
        ];
        for action in &mutations {
            assert!(
                !engine.can(&Role::Auditor, action),
                "Auditor must not be able to perform mutation: {action:?}"
            );
        }
    }

    #[test]
    fn developer_cannot_approve_own() {
        let engine = RbacEngine::new();
        assert!(!engine.can_approve_own_request(&Role::Developer));
        // Also cannot approve at all
        assert!(!engine.can(&Role::Developer, &Action::ApproveApproval));
    }

    #[test]
    fn security_reviewer_cannot_bypass_reconciliation() {
        let engine = RbacEngine::new();
        // Security reviewer must go through approvals, not directly mutate
        assert!(!engine.can(&Role::SecurityReviewer, &Action::CreateGrant));
        assert!(!engine.can(&Role::SecurityReviewer, &Action::UpdateGrant));
        assert!(!engine.can(&Role::SecurityReviewer, &Action::DeleteGrant));
        assert!(!engine.can(&Role::SecurityReviewer, &Action::CreatePolicy));
        assert!(!engine.can(&Role::SecurityReviewer, &Action::UpdatePolicy));
        assert!(!engine.can(&Role::SecurityReviewer, &Action::DeletePolicy));
    }
}