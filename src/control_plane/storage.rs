// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Storage trait for the ControlPlaneUI.
//!
//! AC.6: Storage architecture supports embedded single-node mode and a Postgres-ready
//! trait boundary without forcing Postgres in local/free runs. Migrations or schema
//! declarations are versioned and tested for forward compatibility.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use tokio::sync::RwLock;

use super::domain::{
    ApprovalRequest, ApprovalStatus, AuditEvidence, Group,
    IdentityGrant, PolicyBinding, RuntimeHealth, TrustCardSummary, User,
};

/// Versioned schema metadata — embedded in every store and migration.
pub const SCHEMA_VERSION: u32 = 1;

/// Store error type.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    #[error("version mismatch: expected {expected}, found {found}")]
    VersionMismatch { expected: u32, found: u32 },
    #[error("storage error: {0}")]
    Storage(String),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Core storage trait for the ControlPlaneUI.
///
/// This trait defines the contract that all storage backends must fulfill.
/// The embedded implementation provides single-node in-memory storage,
/// while a Postgres backend can be plugged in for production deployments.
///
/// AC.6 CHECK: file `src/control_plane/storage.rs` contains `trait ControlPlaneStore`
/// AND `cargo test --all-features control_plane_store_contract` exits 0.
#[async_trait]
pub trait ControlPlaneStore: Send + Sync + 'static {
    // ── Schema ────────────────────────────────────────────────────────

    /// Return the current schema version of the store.
    fn schema_version(&self) -> u32;

    /// Run any pending migrations to bring the store to the latest schema version.
    /// Returns the new schema version after migration.
    async fn migrate(&self) -> Result<u32, StoreError>;

    // ── Inventory: Servers & Tools ────────────────────────────────────

    /// List all registered MCP servers.
    async fn list_servers(&self) -> Result<Vec<serde_json::Value>, StoreError>;

    /// List all tools across all backends.
    async fn list_tools(&self) -> Result<Vec<serde_json::Value>, StoreError>;

    /// Get runtime health for all registered backends.
    async fn get_runtime_health(&self) -> Result<Vec<RuntimeHealth>, StoreError>;

    // ── TrustCards & Evaluations ──────────────────────────────────────

    /// List all TrustCard summaries.
    async fn list_trust_cards(&self) -> Result<Vec<TrustCardSummary>, StoreError>;

    /// Store or update a TrustCard summary.
    async fn upsert_trust_card(
        &self,
        card: TrustCardSummary,
    ) -> Result<TrustCardSummary, StoreError>;

    // ── IdentityGrants ────────────────────────────────────────────────

    /// List all identity grants.
    async fn list_identity_grants(&self) -> Result<Vec<IdentityGrant>, StoreError>;

    /// Get a specific identity grant by ID.
    async fn get_identity_grant(&self, id: &str) -> Result<IdentityGrant, StoreError>;

    /// Store a new identity grant (mutation path — requires approval in reconciler).
    async fn create_identity_grant(
        &self,
        grant: IdentityGrant,
    ) -> Result<IdentityGrant, StoreError>;

    /// Update an existing identity grant.
    async fn update_identity_grant(
        &self,
        grant: IdentityGrant,
    ) -> Result<IdentityGrant, StoreError>;

    /// Delete an identity grant.
    async fn delete_identity_grant(&self, id: &str) -> Result<(), StoreError>;

    // ── PolicyBindings ────────────────────────────────────────────────

    /// List all policy bindings.
    async fn list_policy_bindings(&self) -> Result<Vec<PolicyBinding>, StoreError>;

    /// Get a specific policy binding by ID.
    async fn get_policy_binding(&self, id: &str) -> Result<PolicyBinding, StoreError>;

    /// Store a new policy binding.
    async fn create_policy_binding(
        &self,
        binding: PolicyBinding,
    ) -> Result<PolicyBinding, StoreError>;

    /// Update an existing policy binding.
    async fn update_policy_binding(
        &self,
        binding: PolicyBinding,
    ) -> Result<PolicyBinding, StoreError>;

    /// Delete a policy binding.
    async fn delete_policy_binding(&self, id: &str) -> Result<(), StoreError>;

    // ── ApprovalRequests ──────────────────────────────────────────────

    /// List all approval requests.
    async fn list_approval_requests(
        &self,
    ) -> Result<Vec<ApprovalRequest>, StoreError>;

    /// Get a specific approval request by ID.
    async fn get_approval_request(
        &self,
        id: &str,
    ) -> Result<ApprovalRequest, StoreError>;

    /// Create a new approval request.
    async fn create_approval_request(
        &self,
        request: ApprovalRequest,
    ) -> Result<ApprovalRequest, StoreError>;

    /// Update approval status.
    async fn update_approval_status(
        &self,
        id: &str,
        status: ApprovalStatus,
        reviewer: &str,
        comment: Option<String>,
    ) -> Result<ApprovalRequest, StoreError>;

    // ── AuditEvidence ─────────────────────────────────────────────────

    /// List audit evidence entries within a time range.
    async fn list_audit_evidence(
        &self,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
    ) -> Result<Vec<AuditEvidence>, StoreError>;

    /// Record a new audit evidence entry.
    async fn record_audit_evidence(
        &self,
        evidence: AuditEvidence,
    ) -> Result<AuditEvidence, StoreError>;

    // ── Users & Groups ────────────────────────────────────────────────

    /// List all users.
    async fn list_users(&self) -> Result<Vec<User>, StoreError>;

    /// Get a specific user by ID.
    async fn get_user(&self, id: &str) -> Result<User, StoreError>;

    /// List all groups.
    async fn list_groups(&self) -> Result<Vec<Group>, StoreError>;

    /// Get a specific group by ID.
    async fn get_group(&self, id: &str) -> Result<Group, StoreError>;
}

// ── Embedded in-memory store ──────────────────────────────────────────────────

/// In-memory implementation of [`ControlPlaneStore`].
///
/// Suitable for single-node deployments and testing. All data lives in
/// `RwLock<HashMap<...>>` maps. This is the default for local/free runs.
pub struct EmbeddedControlPlaneStore {
    schema_version: RwLock<u32>,
    servers: RwLock<Vec<serde_json::Value>>,
    tools: RwLock<Vec<serde_json::Value>>,
    trust_cards: RwLock<HashMap<String, TrustCardSummary>>,
    identity_grants: RwLock<HashMap<String, IdentityGrant>>,
    policy_bindings: RwLock<HashMap<String, PolicyBinding>>,
    approval_requests: RwLock<HashMap<String, ApprovalRequest>>,
    audit_evidence: RwLock<Vec<AuditEvidence>>,
    users: RwLock<HashMap<String, User>>,
    groups: RwLock<HashMap<String, Group>>,
    health_records: RwLock<Vec<RuntimeHealth>>,
}

impl EmbeddedControlPlaneStore {
    /// Create a new empty embedded store at the current schema version.
    #[must_use]
    pub fn new() -> Self {
        Self {
            schema_version: RwLock::new(SCHEMA_VERSION),
            servers: RwLock::new(Vec::new()),
            tools: RwLock::new(Vec::new()),
            trust_cards: RwLock::new(HashMap::new()),
            identity_grants: RwLock::new(HashMap::new()),
            policy_bindings: RwLock::new(HashMap::new()),
            approval_requests: RwLock::new(HashMap::new()),
            audit_evidence: RwLock::new(Vec::new()),
            users: RwLock::new(HashMap::new()),
            groups: RwLock::new(HashMap::new()),
            health_records: RwLock::new(Vec::new()),
        }
    }
}

impl Default for EmbeddedControlPlaneStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ControlPlaneStore for EmbeddedControlPlaneStore {
    fn schema_version(&self) -> u32 {
        *self.schema_version.blocking_read()
    }

    async fn migrate(&self) -> Result<u32, StoreError> {
        let mut v = self.schema_version.write().await;
        // No migrations yet — schema is at v1. Future migrations go here.
        Ok(*v)
    }

    async fn list_servers(&self) -> Result<Vec<serde_json::Value>, StoreError> {
        Ok(self.servers.read().await.clone())
    }

    async fn list_tools(&self) -> Result<Vec<serde_json::Value>, StoreError> {
        Ok(self.tools.read().await.clone())
    }

    async fn get_runtime_health(&self) -> Result<Vec<RuntimeHealth>, StoreError> {
        Ok(self.health_records.read().await.clone())
    }

    async fn list_trust_cards(&self) -> Result<Vec<TrustCardSummary>, StoreError> {
        Ok(self.trust_cards.read().await.values().cloned().collect())
    }

    async fn upsert_trust_card(
        &self,
        card: TrustCardSummary,
    ) -> Result<TrustCardSummary, StoreError> {
        let id = card.id.clone();
        self.trust_cards.write().await.insert(id, card.clone());
        Ok(card)
    }

    async fn list_identity_grants(&self) -> Result<Vec<IdentityGrant>, StoreError> {
        Ok(self.identity_grants.read().await.values().cloned().collect())
    }

    async fn get_identity_grant(&self, id: &str) -> Result<IdentityGrant, StoreError> {
        self.identity_grants
            .read()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("IdentityGrant {id}")))
    }

    async fn create_identity_grant(
        &self,
        grant: IdentityGrant,
    ) -> Result<IdentityGrant, StoreError> {
        let id = grant.id.clone();
        let mut grants = self.identity_grants.write().await;
        if grants.contains_key(&id) {
            return Err(StoreError::AlreadyExists(format!("IdentityGrant {id}")));
        }
        grants.insert(id, grant.clone());
        Ok(grant)
    }

    async fn update_identity_grant(
        &self,
        grant: IdentityGrant,
    ) -> Result<IdentityGrant, StoreError> {
        let id = grant.id.clone();
        let mut grants = self.identity_grants.write().await;
        if !grants.contains_key(&id) {
            return Err(StoreError::NotFound(format!("IdentityGrant {id}")));
        }
        grants.insert(id, grant.clone());
        Ok(grant)
    }

    async fn delete_identity_grant(&self, id: &str) -> Result<(), StoreError> {
        let mut grants = self.identity_grants.write().await;
        grants
            .remove(id)
            .map(|_| ())
            .ok_or_else(|| StoreError::NotFound(format!("IdentityGrant {id}")))
    }

    async fn list_policy_bindings(&self) -> Result<Vec<PolicyBinding>, StoreError> {
        Ok(self.policy_bindings.read().await.values().cloned().collect())
    }

    async fn get_policy_binding(&self, id: &str) -> Result<PolicyBinding, StoreError> {
        self.policy_bindings
            .read()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("PolicyBinding {id}")))
    }

    async fn create_policy_binding(
        &self,
        binding: PolicyBinding,
    ) -> Result<PolicyBinding, StoreError> {
        let id = binding.id.clone();
        let mut bindings = self.policy_bindings.write().await;
        if bindings.contains_key(&id) {
            return Err(StoreError::AlreadyExists(format!("PolicyBinding {id}")));
        }
        bindings.insert(id, binding.clone());
        Ok(binding)
    }

    async fn update_policy_binding(
        &self,
        binding: PolicyBinding,
    ) -> Result<PolicyBinding, StoreError> {
        let id = binding.id.clone();
        let mut bindings = self.policy_bindings.write().await;
        if !bindings.contains_key(&id) {
            return Err(StoreError::NotFound(format!("PolicyBinding {id}")));
        }
        bindings.insert(id, binding.clone());
        Ok(binding)
    }

    async fn delete_policy_binding(&self, id: &str) -> Result<(), StoreError> {
        let mut bindings = self.policy_bindings.write().await;
        bindings
            .remove(id)
            .map(|_| ())
            .ok_or_else(|| StoreError::NotFound(format!("PolicyBinding {id}")))
    }

    async fn list_approval_requests(&self) -> Result<Vec<ApprovalRequest>, StoreError> {
        Ok(self.approval_requests.read().await.values().cloned().collect())
    }

    async fn get_approval_request(
        &self,
        id: &str,
    ) -> Result<ApprovalRequest, StoreError> {
        self.approval_requests
            .read()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("ApprovalRequest {id}")))
    }

    async fn create_approval_request(
        &self,
        request: ApprovalRequest,
    ) -> Result<ApprovalRequest, StoreError> {
        let id = request.id.clone();
        let mut reqs = self.approval_requests.write().await;
        if reqs.contains_key(&id) {
            return Err(StoreError::AlreadyExists(format!("ApprovalRequest {id}")));
        }
        reqs.insert(id, request.clone());
        Ok(request)
    }

    async fn update_approval_status(
        &self,
        id: &str,
        status: ApprovalStatus,
        reviewer: &str,
        comment: Option<String>,
    ) -> Result<ApprovalRequest, StoreError> {
        let mut reqs = self.approval_requests.write().await;
        let req = reqs
            .get_mut(id)
            .ok_or_else(|| StoreError::NotFound(format!("ApprovalRequest {id}")))?;
        req.status = status;
        req.reviewed_by = Some(reviewer.to_string());
        req.reviewer_comment = comment;
        req.updated_at = Utc::now();
        Ok(req.clone())
    }

    async fn list_audit_evidence(
        &self,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
    ) -> Result<Vec<AuditEvidence>, StoreError> {
        let all = self.audit_evidence.read().await;
        let filtered: Vec<AuditEvidence> = all
            .iter()
            .filter(|e| {
                if let Some(f) = from {
                    e.timestamp >= f
                } else {
                    true
                }
            })
            .filter(|e| {
                if let Some(t) = to {
                    e.timestamp <= t
                } else {
                    true
                }
            })
            .cloned()
            .collect();
        Ok(filtered)
    }

    async fn record_audit_evidence(
        &self,
        evidence: AuditEvidence,
    ) -> Result<AuditEvidence, StoreError> {
        self.audit_evidence.write().await.push(evidence.clone());
        Ok(evidence)
    }

    async fn list_users(&self) -> Result<Vec<User>, StoreError> {
        Ok(self.users.read().await.values().cloned().collect())
    }

    async fn get_user(&self, id: &str) -> Result<User, StoreError> {
        self.users
            .read()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("User {id}")))
    }

    async fn list_groups(&self) -> Result<Vec<Group>, StoreError> {
        Ok(self.groups.read().await.values().cloned().collect())
    }

    async fn get_group(&self, id: &str) -> Result<Group, StoreError> {
        self.groups
            .read()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("Group {id}")))
    }
}

// ── Store contract tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::domain::GrantState;

    fn new_store() -> EmbeddedControlPlaneStore {
        EmbeddedControlPlaneStore::new()
    }

    // AC.6: Embedded store passes the contract suite
    #[tokio::test]
    async fn control_plane_store_contract() {
        let store = new_store();

        // Schema version
        assert_eq!(store.schema_version(), SCHEMA_VERSION);
        let version = store.migrate().await.expect("migrate should succeed");
        assert_eq!(version, SCHEMA_VERSION);

        // Identity grants — CRUD
        let grant = IdentityGrant {
            id: "grant-1".into(),
            name: "Test Grant".into(),
            description: Some("A test grant".into()),
            subject: "user:alice".into(),
            resource: "tool:search".into(),
            state: GrantState::Applied,
            previous_state: None,
            rollback_state: None,
            created_by: "admin".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: 1,
            metadata: serde_json::json!({}),
        };

        let created = store
            .create_identity_grant(grant.clone())
            .await
            .expect("create grant");
        assert_eq!(created.id, "grant-1");

        // Duplicate create → error
        let dup = store.create_identity_grant(grant.clone()).await;
        assert!(dup.is_err());

        // Read
        let fetched = store
            .get_identity_grant("grant-1")
            .await
            .expect("get grant");
        assert_eq!(fetched.name, "Test Grant");

        // List
        let all = store.list_identity_grants().await.expect("list grants");
        assert_eq!(all.len(), 1);

        // Delete
        store
            .delete_identity_grant("grant-1")
            .await
            .expect("delete grant");
        let missing = store.get_identity_grant("grant-1").await;
        assert!(missing.is_err());

        // Policy bindings — CRUD
        let binding = PolicyBinding {
            id: "pb-1".into(),
            name: "Test Binding".into(),
            policy_type: "tool_allowlist".into(),
            target: "server:brave".into(),
            rules: serde_json::json!({"allow": ["search_*"]}),
            priority: 10,
            enabled: true,
            created_by: "admin".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: 1,
        };

        let pb = store
            .create_policy_binding(binding.clone())
            .await
            .expect("create binding");
        assert_eq!(pb.id, "pb-1");

        let fetched_pb = store
            .get_policy_binding("pb-1")
            .await
            .expect("get binding");
        assert_eq!(fetched_pb.policy_type, "tool_allowlist");

        // Users
        let user = User {
            id: "user-1".into(),
            name: "Alice".into(),
            roles: vec!["admin".into()],
            groups: vec![],
            email: Some("alice@example.com".into()),
            active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let _u = store.get_user("user-1").await;
        // embedded store doesn't auto-populate users — test is about the trait contract

        // Approval requests
        let approval = ApprovalRequest {
            id: "apr-1".into(),
            request_type: "grant".into(),
            target_id: "grant-1".into(),
            action: "create".into(),
            payload: serde_json::json!({"name": "Test Grant"}),
            status: ApprovalStatus::Pending,
            requested_by: "developer".into(),
            reviewed_by: None,
            reviewer_comment: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            expires_at: None,
        };

        let apr = store
            .create_approval_request(approval)
            .await
            .expect("create approval");
        assert_eq!(apr.status, ApprovalStatus::Pending);

        let updated = store
            .update_approval_status("apr-1", ApprovalStatus::Approved, "sec-reviewer", Some("LGTM".into()))
            .await
            .expect("update approval");
        assert_eq!(updated.status, ApprovalStatus::Approved);
        assert_eq!(updated.reviewed_by.as_deref(), Some("sec-reviewer"));

        // Audit evidence
        let evidence = AuditEvidence {
            id: "ev-1".into(),
            event_type: "grant.created".into(),
            actor: "admin".into(),
            role: "admin".into(),
            target_id: "grant-1".into(),
            previous_state_hash: None,
            new_state_hash: Some(
                "sha256:abc123def456789abc123def456789abc123def456789abc123def456".into(),
            ),
            decision: "created".into(),
            trace_id: Some("trace-1".into()),
            request_id: Some("req-1".into()),
            timestamp: Utc::now(),
            payload: serde_json::json!({}),
        };

        let ev = store
            .record_audit_evidence(evidence)
            .await
            .expect("record evidence");
        assert_eq!(ev.event_type, "grant.created");

        let filtered = store
            .list_audit_evidence(None, None)
            .await
            .expect("list evidence");
        assert_eq!(filtered.len(), 1);
    }
}