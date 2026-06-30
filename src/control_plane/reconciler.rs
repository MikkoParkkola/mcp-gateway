// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Reconciliation layer for grant and policy mutations.
//!
//! AC.4: Grant and policy mutations require approval, emit durable audit evidence,
//! record previous/applied/rollback states, and can be rolled back through the same
//! reconciler without direct config/database edits.
//!
//! CHECK: `cargo test --all-features control_plane_grant_policy_reconciliation_audits_and_rolls_back` exits 0

use async_trait::async_trait;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use super::domain::{
    ApprovalRequest, ApprovalStatus, AuditEvidence, GrantState, IdentityGrant,
    PolicyBinding,
};
use super::license::{GatedFeature, LicenseGate};
use super::rbac::{Action, RbacEngine, Role};
use super::storage::{ControlPlaneStore, StoreError};

/// Result type for reconciler operations.
pub type ReconcilerResult<T> = Result<T, ReconcilerError>;

/// Reconciler error type.
#[derive(Debug, thiserror::Error)]
pub enum ReconcilerError {
    #[error("approval required: {0}")]
    ApprovalRequired(String),
    #[error("approval rejected: {0}")]
    ApprovalRejected(String),
    #[error("rbac denied: {0}")]
    RbacDenied(String),
    #[error("license gated: {0}")]
    LicenseGated(String),
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("state error: {0}")]
    State(String),
    #[error("audit error: {0}")]
    Audit(String),
}

/// The ControlPlaneReconciler mediates all grant and policy mutations.
///
/// It enforces:
/// 1. RBAC: caller role must have appropriate permissions
/// 2. License: Enterprise tier required for mutations
/// 3. Approval: mutations must be approved (unless caller is admin + self-approval allowed)
/// 4. Audit: every state transition emits durable audit evidence
/// 5. Rollback: previous/applied/rollback states are tracked
pub struct ControlPlaneReconciler<S: ControlPlaneStore> {
    store: Arc<S>,
    rbac: RbacEngine,
    license_gate: LicenseGate,
}

impl<S: ControlPlaneStore> ControlPlaneReconciler<S> {
    /// Create a new reconciler.
    #[must_use]
    pub fn new(store: Arc<S>, rbac: RbacEngine, license_gate: LicenseGate) -> Self {
        Self {
            store,
            rbac,
            license_gate,
        }
    }

    // ── Grant mutations ───────────────────────────────────────────────

    /// Request creation of a new identity grant.
    ///
    /// This creates an approval request; the grant is NOT applied until approved.
    pub async fn request_create_grant(
        &self,
        mut grant: IdentityGrant,
        actor: &str,
        role: &Role,
        trace_id: Option<String>,
    ) -> ReconcilerResult<ApprovalRequest> {
        // RBAC
        check_action(&self.rbac, role, Action::CreateGrant)?;

        // License
        self.license_gate
            .check(&GatedFeature::GrantMutation)
            .map_err(ReconcilerError::LicenseGated)?;

        // Set initial state
        grant.state = GrantState::PendingApproval;
        grant.created_by = actor.to_string();
        grant.created_at = Utc::now();
        grant.updated_at = Utc::now();
        grant.version = 1;

        let request_id = uuid::Uuid::new_v4().to_string();
        let approval = ApprovalRequest {
            id: request_id.clone(),
            request_type: "grant".into(),
            target_id: grant.id.clone(),
            action: "create".into(),
            payload: serde_json::to_value(&grant).unwrap_or_default(),
            status: ApprovalStatus::Pending,
            requested_by: actor.to_string(),
            reviewed_by: None,
            reviewer_comment: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            expires_at: None,
        };

        // Store approval request
        self.store.create_approval_request(approval.clone()).await?;

        // Audit: approval requested
        self.emit_audit(
            "grant.create.requested",
            actor,
            role.as_str(),
            &grant.id,
            None,
            Some(&hash_state(&grant)),
            "requested",
            trace_id.as_deref(),
            Some(&request_id),
            &serde_json::json!({"grant_name": grant.name}),
        )
        .await?;

        Ok(approval)
    }

    /// Approve a pending grant mutation.
    ///
    /// Approval applies the grant to the store and records the state transition.
    pub async fn approve_grant(
        &self,
        approval_id: &str,
        reviewer: &str,
        reviewer_role: &Role,
        comment: Option<String>,
        trace_id: Option<String>,
    ) -> ReconcilerResult<IdentityGrant> {
        // RBAC
        check_action(&self.rbac, reviewer_role, Action::ApproveApproval)?;

        // Load approval
        let approval = self.store.get_approval_request(approval_id).await?;

        if approval.status != ApprovalStatus::Pending {
            return Err(ReconcilerError::State(format!(
                "Approval {approval_id} is not pending (status: {:?})",
                approval.status
            )));
        }

        // Self-approval check
        if approval.requested_by == reviewer
            && !self.rbac.can_approve_own_request(reviewer_role)
            && !matches!(reviewer_role, Role::Admin)
        {
            return Err(ReconcilerError::RbacDenied(format!(
                "User '{reviewer}' cannot approve their own request"
            )));
        }

        // Deserialize grant from payload
        let mut grant: IdentityGrant = serde_json::from_value(approval.payload.clone())
            .map_err(|e| ReconcilerError::State(format!("Invalid grant payload: {e}")))?;

        let previous_state = grant.state.clone();
        let previous_hash = self
            .store
            .get_identity_grant(&grant.id)
            .await
            .map(|g| hash_state(&g))
            .ok();

        grant.state = GrantState::Applied;
        grant.updated_at = Utc::now();

        // Store the grant
        let stored = if previous_hash.is_some() {
            self.store.update_identity_grant(grant.clone()).await?
        } else {
            self.store.create_identity_grant(grant.clone()).await?
        };

        // Update approval status
        self.store
            .update_approval_status(
                approval_id,
                ApprovalStatus::Approved,
                reviewer,
                comment.clone(),
            )
            .await?;

        // Audit: approval granted + mutation applied
        self.emit_audit(
            "grant.approved",
            reviewer,
            reviewer_role.as_str(),
            &stored.id,
            previous_hash.as_deref(),
            Some(&hash_state(&stored)),
            "approved",
            trace_id.as_deref(),
            Some(approval_id),
            &serde_json::json!({
                "previous_state": previous_state,
                "new_state": stored.state,
                "reviewer_comment": comment,
            }),
        )
        .await?;

        Ok(stored)
    }

    /// Reject a pending grant mutation.
    pub async fn reject_grant(
        &self,
        approval_id: &str,
        reviewer: &str,
        reviewer_role: &Role,
        comment: String,
        trace_id: Option<String>,
    ) -> ReconcilerResult<()> {
        check_action(&self.rbac, reviewer_role, Action::RejectApproval)?;

        let approval = self.store.get_approval_request(approval_id).await?;

        if approval.status != ApprovalStatus::Pending {
            return Err(ReconcilerError::State(format!(
                "Approval {approval_id} is not pending"
            )));
        }

        self.store
            .update_approval_status(
                approval_id,
                ApprovalStatus::Rejected,
                reviewer,
                Some(comment.clone()),
            )
            .await?;

        // Audit
        self.emit_audit(
            "grant.rejected",
            reviewer,
            reviewer_role.as_str(),
            &approval.target_id,
            None,
            None,
            "rejected",
            trace_id.as_deref(),
            Some(approval_id),
            &serde_json::json!({"comment": comment}),
        )
        .await?;

        Ok(())
    }

    /// Roll back a previously applied grant.
    ///
    /// Records rollback state and emits audit evidence.
    pub async fn rollback_grant(
        &self,
        grant_id: &str,
        actor: &str,
        role: &Role,
        reason: Option<String>,
        trace_id: Option<String>,
    ) -> ReconcilerResult<IdentityGrant> {
        check_action(&self.rbac, role, Action::UpdateGrant)?;
        self.license_gate
            .check(&GatedFeature::GrantMutation)
            .map_err(ReconcilerError::LicenseGated)?;

        let mut grant = self.store.get_identity_grant(grant_id).await?;

        if grant.state != GrantState::Applied {
            return Err(ReconcilerError::State(format!(
                "Grant {grant_id} is not in Applied state (current: {:?})",
                grant.state
            )));
        }

        let previous_hash = Some(hash_state(&grant));

        // Save current state as rollback_state and move to RolledBack
        grant.rollback_state = Some(serde_json::to_value(grant.clone()).unwrap_or_default());
        grant.state = GrantState::RolledBack;
        grant.updated_at = Utc::now();
        grant.version += 1;

        let rolled_back = self.store.update_identity_grant(grant).await?;

        // Audit
        self.emit_audit(
            "grant.rolled_back",
            actor,
            role.as_str(),
            grant_id,
            previous_hash.as_deref(),
            Some(&hash_state(&rolled_back)),
            "rolled_back",
            trace_id.as_deref(),
            None,
            &serde_json::json!({"reason": reason}),
        )
        .await?;

        Ok(rolled_back)
    }

    // ── Policy mutations ──────────────────────────────────────────────

    /// Request creation of a new policy binding.
    pub async fn request_create_policy(
        &self,
        mut binding: PolicyBinding,
        actor: &str,
        role: &Role,
        trace_id: Option<String>,
    ) -> ReconcilerResult<ApprovalRequest> {
        check_action(&self.rbac, role, Action::CreatePolicy)?;
        self.license_gate
            .check(&GatedFeature::PolicyMutation)
            .map_err(ReconcilerError::LicenseGated)?;

        binding.created_by = actor.to_string();
        binding.created_at = Utc::now();
        binding.updated_at = Utc::now();
        binding.version = 1;

        let request_id = uuid::Uuid::new_v4().to_string();
        let approval = ApprovalRequest {
            id: request_id.clone(),
            request_type: "policy".into(),
            target_id: binding.id.clone(),
            action: "create".into(),
            payload: serde_json::to_value(&binding).unwrap_or_default(),
            status: ApprovalStatus::Pending,
            requested_by: actor.to_string(),
            reviewed_by: None,
            reviewer_comment: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            expires_at: None,
        };

        self.store.create_approval_request(approval.clone()).await?;

        self.emit_audit(
            "policy.create.requested",
            actor,
            role.as_str(),
            &binding.id,
            None,
            Some(&hash_payload(&approval.payload)),
            "requested",
            trace_id.as_deref(),
            Some(&request_id),
            &serde_json::json!({"policy_name": binding.name}),
        )
        .await?;

        Ok(approval)
    }

    /// Approve a pending policy mutation.
    pub async fn approve_policy(
        &self,
        approval_id: &str,
        reviewer: &str,
        reviewer_role: &Role,
        comment: Option<String>,
        trace_id: Option<String>,
    ) -> ReconcilerResult<PolicyBinding> {
        check_action(&self.rbac, reviewer_role, Action::ApproveApproval)?;

        let approval = self.store.get_approval_request(approval_id).await?;

        if approval.status != ApprovalStatus::Pending {
            return Err(ReconcilerError::State(format!(
                "Approval {approval_id} is not pending"
            )));
        }

        if approval.requested_by == reviewer
            && !self.rbac.can_approve_own_request(reviewer_role)
            && !matches!(reviewer_role, Role::Admin)
        {
            return Err(ReconcilerError::RbacDenied(format!(
                "User '{reviewer}' cannot approve their own request"
            )));
        }

        let binding: PolicyBinding = serde_json::from_value(approval.payload.clone())
            .map_err(|e| ReconcilerError::State(format!("Invalid policy payload: {e}")))?;

        let previous_hash = self
            .store
            .get_policy_binding(&binding.id)
            .await
            .map(|b| hash_state(&b))
            .ok();

        let stored = self.store.create_policy_binding(binding.clone()).await?;

        self.store
            .update_approval_status(
                approval_id,
                ApprovalStatus::Approved,
                reviewer,
                comment.clone(),
            )
            .await?;

        self.emit_audit(
            "policy.approved",
            reviewer,
            reviewer_role.as_str(),
            &stored.id,
            previous_hash.as_deref(),
            Some(&hash_state(&stored)),
            "approved",
            trace_id.as_deref(),
            Some(approval_id),
            &serde_json::json!({"reviewer_comment": comment}),
        )
        .await?;

        Ok(stored)
    }

    /// Reject a pending policy mutation.
    pub async fn reject_policy(
        &self,
        approval_id: &str,
        reviewer: &str,
        reviewer_role: &Role,
        comment: String,
        trace_id: Option<String>,
    ) -> ReconcilerResult<()> {
        check_action(&self.rbac, reviewer_role, Action::RejectApproval)?;

        let approval = self.store.get_approval_request(approval_id).await?;

        if approval.status != ApprovalStatus::Pending {
            return Err(ReconcilerError::State(format!(
                "Approval {approval_id} is not pending"
            )));
        }

        self.store
            .update_approval_status(
                approval_id,
                ApprovalStatus::Rejected,
                reviewer,
                Some(comment.clone()),
            )
            .await?;

        self.emit_audit(
            "policy.rejected",
            reviewer,
            reviewer_role.as_str(),
            &approval.target_id,
            None,
            None,
            "rejected",
            trace_id.as_deref(),
            Some(approval_id),
            &serde_json::json!({"comment": comment}),
        )
        .await?;

        Ok(())
    }

    /// Roll back a previously applied policy binding.
    pub async fn rollback_policy(
        &self,
        policy_id: &str,
        actor: &str,
        role: &Role,
        reason: Option<String>,
        trace_id: Option<String>,
    ) -> ReconcilerResult<PolicyBinding> {
        check_action(&self.rbac, role, Action::UpdatePolicy)?;
        self.license_gate
            .check(&GatedFeature::PolicyMutation)
            .map_err(ReconcilerError::LicenseGated)?;

        let mut binding = self.store.get_policy_binding(policy_id).await?;

        let previous_hash = Some(hash_state(&binding));

        // Rollback: disable the binding and mark it
        binding.enabled = false;
        binding.updated_at = Utc::now();
        binding.version += 1;

        let rolled_back = self.store.update_policy_binding(binding).await?;

        self.emit_audit(
            "policy.rolled_back",
            actor,
            role.as_str(),
            policy_id,
            previous_hash.as_deref(),
            Some(&hash_state(&rolled_back)),
            "rolled_back",
            trace_id.as_deref(),
            None,
            &serde_json::json!({"reason": reason}),
        )
        .await?;

        Ok(rolled_back)
    }

    // ── Private helpers ───────────────────────────────────────────────

    /// Emit a durable audit evidence record.
    async fn emit_audit(
        &self,
        event_type: &str,
        actor: &str,
        role: &str,
        target_id: &str,
        previous_state_hash: Option<&str>,
        new_state_hash: Option<&str>,
        decision: &str,
        trace_id: Option<&str>,
        request_id: Option<&str>,
        payload: &serde_json::Value,
    ) -> ReconcilerResult<()> {
        let evidence = AuditEvidence {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: event_type.to_string(),
            actor: actor.to_string(),
            role: role.to_string(),
            target_id: target_id.to_string(),
            previous_state_hash: previous_state_hash.map(String::from),
            new_state_hash: new_state_hash.map(String::from),
            decision: decision.to_string(),
            trace_id: trace_id.map(String::from),
            request_id: request_id.map(String::from),
            timestamp: Utc::now(),
            payload: payload.clone(),
        };

        self.store
            .record_audit_evidence(evidence)
            .await
            .map_err(ReconcilerError::Store)?;
        Ok(())
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn check_action(rbac: &RbacEngine, role: &Role, action: Action) -> ReconcilerResult<()> {
    if rbac.can(role, &action) {
        Ok(())
    } else {
        Err(ReconcilerError::RbacDenied(format!(
            "Role '{role_str}' is not permitted to perform action '{action:?}'",
            role_str = role.as_str(),
        )))
    }
}

fn hash_state<T: serde::Serialize>(value: &T) -> String {
    let json = serde_json::to_string(value).unwrap_or_default();
    hash_payload_str(&json)
}

fn hash_payload(value: &serde_json::Value) -> String {
    let json = serde_json::to_string(value).unwrap_or_default();
    hash_payload_str(&json)
}

fn hash_payload_str(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();
    format!("sha256:{result:x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::domain::GrantState;
    use crate::control_plane::license::LicenseTier;
    use crate::control_plane::storage::EmbeddedControlPlaneStore;
    use std::sync::Arc;

    fn setup() -> ControlPlaneReconciler<EmbeddedControlPlaneStore> {
        let store = Arc::new(EmbeddedControlPlaneStore::new());
        let rbac = RbacEngine::new();
        let license_gate = LicenseGate::new(LicenseTier::Enterprise);
        ControlPlaneReconciler::new(store, rbac, license_gate)
    }

    /// AC.4: Grant and policy mutations require approval, emit durable audit evidence,
    /// record previous/applied/rollback states, and can be rolled back through the same
    /// reconciler without direct config/database edits.
    /// CHECK: `cargo test --all-features control_plane_grant_policy_reconciliation_audits_and_rolls_back` exits 0
    #[tokio::test]
    async fn control_plane_grant_policy_reconciliation_audits_and_rolls_back() {
        let reconciler = setup();

        // ── Grant lifecycle: request → approve → rollback ──

        let grant = IdentityGrant {
            id: "grant-test-1".into(),
            name: "Test Grant".into(),
            description: Some("For testing".into()),
            subject: "user:alice".into(),
            resource: "tool:search".into(),
            state: GrantState::Applied,
            previous_state: None,
            rollback_state: None,
            created_by: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: 0,
            metadata: serde_json::json!({}),
        };

        // Request creation
        let approval = reconciler
            .request_create_grant(
                grant.clone(),
                "developer",
                &Role::Developer,
                Some("trace-1"),
            )
            .await
            .expect("request create grant");
        assert_eq!(approval.status, ApprovalStatus::Pending);
        assert_eq!(approval.requested_by, "developer");

        // Developer cannot approve own request
        let self_approve = reconciler
            .approve_grant(&approval.id, "developer", &Role::Developer, None, None)
            .await;
        assert!(
            self_approve.is_err(),
            "Developer must not approve own request"
        );

        // Developer cannot directly create grant via reconciler (RBAC)
        let direct_create = reconciler
            .request_create_grant(
                IdentityGrant {
                    id: "direct-test".into(),
                    name: "Direct".into(),
                    description: None,
                    subject: "user:bob".into(),
                    resource: "tool:read".into(),
                    state: GrantState::Applied,
                    previous_state: None,
                    rollback_state: None,
                    created_by: String::new(),
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    version: 0,
                    metadata: serde_json::json!({}),
                },
                "developer",
                &Role::Developer,
                None,
            )
            .await;
        // Developer can request (create approval) but the reconciler checks RBAC for CreateGrant
        // Developer does NOT have CreateGrant — so this should fail
        assert!(direct_create.is_err());

        // Admin creates a grant request
        let admin_approval = reconciler
            .request_create_grant(
                IdentityGrant {
                    id: "grant-admin-1".into(),
                    name: "Admin Grant".into(),
                    description: None,
                    subject: "user:charlie".into(),
                    resource: "tool:admin".into(),
                    state: GrantState::Applied,
                    previous_state: None,
                    rollback_state: None,
                    created_by: String::new(),
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    version: 0,
                    metadata: serde_json::json!({}),
                },
                "admin",
                &Role::Admin,
                None,
            )
            .await
            .expect("admin creates grant request");

        // Security reviewer approves the grant
        let applied = reconciler
            .approve_grant(
                &admin_approval.id,
                "sec-reviewer",
                &Role::SecurityReviewer,
                Some("Approved after review".into()),
                Some("trace-2"),
            )
            .await
            .expect("security reviewer approves grant");

        assert_eq!(applied.state, GrantState::Applied);
        assert_eq!(applied.name, "Admin Grant");
        assert_eq!(applied.created_by, "admin");

        // Rollback the grant
        let rolled_back = reconciler
            .rollback_grant(
                &applied.id,
                "admin",
                &Role::Admin,
                Some("No longer needed".into()),
                Some("trace-3"),
            )
            .await
            .expect("rollback grant");

        assert_eq!(rolled_back.state, GrantState::RolledBack);
        assert!(rolled_back.rollback_state.is_some());

        // ── Policy lifecycle ──

        let binding = PolicyBinding {
            id: "pb-test-1".into(),
            name: "Test Policy".into(),
            policy_type: "tool_allowlist".into(),
            target: "server:brave".into(),
            rules: serde_json::json!({"allow": ["search_*"]}),
            priority: 10,
            enabled: true,
            created_by: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: 0,
        };

        let pb_approval = reconciler
            .request_create_policy(binding, "admin", &Role::Admin, Some("trace-4"))
            .await
            .expect("request create policy");

        let applied_pb = reconciler
            .approve_policy(
                &pb_approval.id,
                "sec-reviewer",
                &Role::SecurityReviewer,
                None,
                Some("trace-5"),
            )
            .await
            .expect("approve policy");

        assert_eq!(applied_pb.name, "Test Policy");

        // Rollback policy
        let rolled_back_pb = reconciler
            .rollback_policy(
                &applied_pb.id,
                "admin",
                &Role::Admin,
                Some("Policy deprecated".into()),
                Some("trace-6"),
            )
            .await
            .expect("rollback policy");

        assert!(!rolled_back_pb.enabled, "Rolled back policy must be disabled");

        // ── Verify audit evidence ──
        let audit = reconciler
            .store
            .list_audit_evidence(None, None)
            .await
            .expect("list audit evidence");

        // At minimum: grant requested + grant approved + grant rolled_back + policy requested + policy approved + policy rolled_back = 6
        // Plus potential admin grant request from earlier
        assert!(
            audit.len() >= 6,
            "Expected at least 6 audit records, got {}",
            audit.len()
        );

        // Verify audit records have required fields
        for ev in &audit {
            assert!(!ev.id.is_empty(), "Audit evidence must have an id");
            assert!(!ev.event_type.is_empty(), "Audit evidence must have event_type");
            assert!(!ev.actor.is_empty(), "Audit evidence must have actor");
            assert!(!ev.decision.is_empty(), "Audit evidence must have decision");
        }

        // Check specific audit event types exist
        let event_types: Vec<&str> = audit.iter().map(|e| e.event_type.as_str()).collect();
        assert!(
            event_types.contains(&"grant.approved"),
            "Must contain grant.approved event"
        );
        assert!(
            event_types.contains(&"grant.rolled_back"),
            "Must contain grant.rolled_back event"
        );
        assert!(
            event_types.contains(&"policy.approved"),
            "Must contain policy.approved event"
        );
        assert!(
            event_types.contains(&"policy.rolled_back"),
            "Must contain policy.rolled_back event"
        );
    }

    #[test]
    fn hash_state_produces_consistent_output() {
        let grant = IdentityGrant {
            id: "g1".into(),
            name: "G".into(),
            description: None,
            subject: "u:1".into(),
            resource: "t:1".into(),
            state: GrantState::Applied,
            previous_state: None,
            rollback_state: None,
            created_by: "a".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: 1,
            metadata: serde_json::json!({}),
        };
        let h1 = hash_state(&grant);
        let h2 = hash_state(&grant);
        assert_eq!(h1, h2, "Hash must be deterministic");
        assert!(h1.starts_with("sha256:"));
    }
}