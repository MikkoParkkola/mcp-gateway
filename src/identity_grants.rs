// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Identity-scoped capability grants for personal MCP tools.
//!
//! This module is the MIK-6553 grant contract. It models who may use a
//! capability, which agent may act for that subject, how long the permission is
//! live, and why each decision was made. Gateway dispatch uses this contract
//! to fail closed for explicitly personal capabilities while existing shared
//! and public tools keep their backward-compatible behavior.

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Stable local grant-file schema version.
pub const IDENTITY_GRANTS_FILE_SCHEMA_VERSION: &str = "identity_grants.v1";

/// Default recommendation lease duration for local grants.
pub const DEFAULT_GRANT_LEASE_SECONDS: i64 = 60 * 60;

/// Maximum recommendation lease duration for local grants.
pub const MAX_GRANT_LEASE_SECONDS: i64 = 24 * 60 * 60;

/// Stable subject identity used by grant evaluation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GrantSubject {
    /// Identity authority, such as an issuer URL or local authority name.
    pub authority: String,
    /// Stable subject identifier inside the authority namespace.
    pub subject: String,
    /// Optional operator-facing label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl GrantSubject {
    /// Create a new grant subject.
    #[must_use]
    pub fn new(
        authority: impl Into<String>,
        subject: impl Into<String>,
        label: Option<String>,
    ) -> Self {
        Self {
            authority: authority.into(),
            subject: subject.into(),
            label,
        }
    }
}

/// Agent binding for a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantAgent {
    /// Grant applies to any agent acting for the subject.
    Any,
    /// Grant applies only to this exact agent identifier.
    Exact(String),
}

impl GrantAgent {
    fn matches(&self, agent_id: Option<&str>) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(expected) => agent_id.is_some_and(|actual| actual == expected),
        }
    }
}

/// Capability exposure class.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityExposure {
    /// No caller identity is required. This preserves public-tool behavior.
    Public,
    /// Shared team or gateway capability.
    #[default]
    Shared,
    /// Personal capability. Caller identity, matching ownership, and a live grant are required.
    Personal,
}

impl CapabilityExposure {
    /// Whether this is the backward-compatible default exposure.
    #[must_use]
    pub const fn is_shared(&self) -> bool {
        matches!(self, Self::Shared)
    }
}

/// Action scope granted for a capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantScope {
    /// Read-only operations.
    Read,
    /// Mutating operations.
    Write,
    /// Tool execution.
    Execute,
    /// Any operation.
    Any,
}

impl GrantScope {
    fn grants(&self, requested: &Self) -> bool {
        matches!(self, Self::Any) || self == requested
    }
}

/// One durable grant row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityGrant {
    /// Stable grant identifier.
    pub grant_id: String,
    /// Subject that owns the grant.
    pub subject: GrantSubject,
    /// Agent binding.
    pub agent: GrantAgent,
    /// Capability identifier, usually the gateway capability id.
    pub capability: String,
    /// Optional concrete tool name under the capability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Granted action scope.
    pub scope: GrantScope,
    /// Optional owner that must match the caller for personal tools.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<GrantSubject>,
    /// Optional expiry timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Optional revocation timestamp. Any value means the grant is denied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    /// Provenance for why the grant exists.
    pub provenance: String,
    /// Operator-visible reason.
    pub reason: String,
}

/// Local JSON/YAML grant file loaded by free/core deployments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityGrantFile {
    /// Grant-file schema version.
    #[serde(default = "default_identity_grants_file_schema_version")]
    pub schema_version: String,
    /// Durable local grant rows.
    #[serde(default)]
    pub grants: Vec<IdentityGrant>,
}

impl IdentityGrantFile {
    /// Build a grant file from rows.
    #[must_use]
    pub fn new(grants: Vec<IdentityGrant>) -> Self {
        Self {
            schema_version: IDENTITY_GRANTS_FILE_SCHEMA_VERSION.to_string(),
            grants,
        }
    }
}

fn default_identity_grants_file_schema_version() -> String {
    IDENTITY_GRANTS_FILE_SCHEMA_VERSION.to_string()
}

/// Read a local identity-grants file as persisted rows.
///
/// # Errors
///
/// Returns an error if the file cannot be read, parsed, or uses an unsupported
/// schema version.
pub async fn read_identity_grants_file(path: &Path) -> Result<IdentityGrantFile, String> {
    let content = tokio::fs::read_to_string(path).await.map_err(|e| {
        format!(
            "failed to read identity grants file {}: {e}",
            path.display()
        )
    })?;
    let file = serde_json::from_str::<IdentityGrantFile>(&content)
        .or_else(|_| serde_yaml::from_str::<IdentityGrantFile>(&content))
        .map_err(|e| {
            format!(
                "failed to parse identity grants file {}: {e}",
                path.display()
            )
        })?;

    if file.schema_version != IDENTITY_GRANTS_FILE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported identity grants schema version '{}' in {}; expected '{}'",
            file.schema_version,
            path.display(),
            IDENTITY_GRANTS_FILE_SCHEMA_VERSION
        ));
    }

    Ok(file)
}

/// Load local identity grants from a JSON or YAML file.
///
/// # Errors
///
/// Returns an error if the file cannot be read, parsed, or uses an unsupported
/// schema version.
pub async fn load_identity_grants_file(path: &Path) -> Result<LocalIdentityGrantStore, String> {
    let file = read_identity_grants_file(path).await?;
    Ok(LocalIdentityGrantStore::from_grants(file.grants))
}

impl IdentityGrant {
    fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|expires_at| expires_at > now)
    }

    fn covers(
        &self,
        identity: &GrantSubject,
        agent_id: Option<&str>,
        capability: &str,
        tool: Option<&str>,
        scope: &GrantScope,
        now: DateTime<Utc>,
    ) -> bool {
        self.is_active_at(now)
            && &self.subject == identity
            && self.agent.matches(agent_id)
            && self.capability == capability
            && self
                .tool
                .as_deref()
                .is_none_or(|expected| Some(expected) == tool)
            && self.scope.grants(scope)
    }
}

/// Grant evaluation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityGrantRequest {
    /// Caller identity, when the transport authenticated one.
    pub identity: Option<GrantSubject>,
    /// Calling agent id, when available.
    pub agent_id: Option<String>,
    /// Capability identifier.
    pub capability: String,
    /// Optional concrete tool name.
    pub tool: Option<String>,
    /// Requested action scope.
    pub scope: GrantScope,
    /// Capability exposure class.
    pub exposure: CapabilityExposure,
    /// Owner for personal tools.
    pub owner: Option<GrantSubject>,
    /// Evaluation timestamp.
    pub now: DateTime<Utc>,
}

/// Result of evaluating a grant request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityGrantEvaluation {
    /// Whether dispatch is allowed by this grant decision.
    pub allowed: bool,
    /// Stable reason code.
    pub reason: IdentityGrantDecisionReason,
    /// Matching grant id when one was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    /// Audit event for durable logs.
    pub audit: IdentityGrantAuditEvent,
}

/// Stable reason code for grant decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityGrantDecisionReason {
    /// Public capability is allowed without a personal grant.
    PublicCapability,
    /// Shared capability is allowed by backward-compatible behavior.
    SharedCapability,
    /// Personal capability request has no authenticated subject.
    MissingIdentity,
    /// Personal capability request has no ownership evidence.
    MissingOwner,
    /// Personal capability belongs to a different subject.
    OwnerMismatch,
    /// No live matching grant was found.
    MissingGrant,
    /// A live matching grant allowed the request.
    GrantMatched,
}

/// Data class used when recommending least-privilege grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantDataClass {
    /// Public data.
    Public,
    /// Internal project or team data.
    Internal,
    /// Personal user data.
    Personal,
    /// Sensitive business, regulated, or private data.
    Sensitive,
}

/// Tool risk used when recommending least-privilege grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantToolRisk {
    /// Low-risk read or lookup workflow.
    Low,
    /// Medium-risk workflow that may need review.
    Medium,
    /// High-risk workflow that must be confirmed.
    High,
    /// Destructive workflow that must be confirmed.
    Destructive,
}

/// Request for a grant recommendation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRecommendationRequest {
    /// Caller identity, when the transport authenticated one.
    pub identity: Option<GrantSubject>,
    /// Calling agent id, when available.
    pub agent_id: Option<String>,
    /// Capability identifier.
    pub capability: String,
    /// Optional concrete tool name.
    pub tool: Option<String>,
    /// Requested action scope.
    pub scope: GrantScope,
    /// Capability exposure class.
    pub exposure: CapabilityExposure,
    /// Owner for personal tools.
    pub owner: Option<GrantSubject>,
    /// Data class touched by the requested workflow.
    pub data_class: GrantDataClass,
    /// Tool risk for the requested workflow.
    pub tool_risk: GrantToolRisk,
    /// Requested lease duration in seconds.
    pub requested_lease_seconds: Option<i64>,
    /// Human-readable reason for the request.
    pub reason: String,
    /// Recommendation timestamp.
    pub now: DateTime<Utc>,
}

/// Recommendation outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantRecommendationDecision {
    /// Public or shared capability can proceed under existing compatibility behavior.
    AllowPublicOrShared,
    /// An existing live grant already covers this request.
    UseExistingGrant,
    /// A short least-privilege lease can be proposed for human approval.
    RecommendLease,
    /// Human confirmation is required before a lease can be used.
    RequireConfirmation,
    /// Delegated administrator review is required.
    RequestAdmin,
    /// The request cannot be recommended.
    Deny,
}

/// Stable reason code for grant recommendations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantRecommendationReason {
    /// Public or shared capability does not need a personal grant.
    PublicOrSharedCapability,
    /// A live grant already covers the request.
    ExistingGrant,
    /// No caller identity was present.
    MissingIdentity,
    /// No owner evidence was present.
    MissingOwner,
    /// The request crosses user boundaries.
    CrossUserAccess,
    /// Tool risk requires explicit confirmation.
    HighRiskTool,
    /// Scope or data class requires explicit confirmation.
    SensitiveOrBroadScope,
    /// A short least-privilege lease is recommended.
    LeastPrivilegeLease,
}

/// Time-bound lease proposal emitted by the recommendation engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantLeaseProposal {
    /// Subject that would own the grant.
    pub subject: GrantSubject,
    /// Agent binding for the proposed grant.
    pub agent: GrantAgent,
    /// Capability identifier.
    pub capability: String,
    /// Optional concrete tool name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Proposed action scope.
    pub scope: GrantScope,
    /// Optional owner subject for personal capabilities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<GrantSubject>,
    /// Proposed expiry timestamp.
    pub expires_at: DateTime<Utc>,
    /// Human-readable reason.
    pub reason: String,
    /// Provenance for the recommendation.
    pub provenance: String,
}

/// Result of generating a grant recommendation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRecommendation {
    /// Recommendation decision.
    pub decision: GrantRecommendationDecision,
    /// Stable reason code.
    pub reason: GrantRecommendationReason,
    /// Operator-facing explanation.
    pub explanation: String,
    /// True when a human must approve before dispatch or grant creation.
    pub confirmation_required: bool,
    /// Proposed short lease, when one is safe to present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease: Option<GrantLeaseProposal>,
    /// Revoke or rollback guidance.
    pub revoke_path: String,
    /// Audit event for recommendation logs.
    pub audit: GrantRecommendationAuditEvent,
}

/// Audit event emitted for each recommendation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRecommendationAuditEvent {
    /// Event name.
    pub event: String,
    /// Recommendation timestamp.
    pub timestamp: DateTime<Utc>,
    /// Recommendation decision.
    pub decision: GrantRecommendationDecision,
    /// Stable reason code.
    pub reason: GrantRecommendationReason,
    /// Caller subject, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<GrantSubject>,
    /// Agent id, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Capability identifier.
    pub capability: String,
    /// Optional concrete tool name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Requested scope.
    pub scope: GrantScope,
    /// Capability exposure class.
    pub exposure: CapabilityExposure,
    /// Whether human confirmation is required.
    pub confirmation_required: bool,
    /// Proposed lease expiry, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_expires_at: Option<DateTime<Utc>>,
}

/// Audit event emitted for every grant evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityGrantAuditEvent {
    /// Event name.
    pub event: String,
    /// Evaluation timestamp.
    pub timestamp: DateTime<Utc>,
    /// Whether the request was allowed.
    pub allowed: bool,
    /// Stable reason code.
    pub reason: IdentityGrantDecisionReason,
    /// Caller subject, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<GrantSubject>,
    /// Agent id, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Capability identifier.
    pub capability: String,
    /// Optional concrete tool name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Requested scope.
    pub scope: GrantScope,
    /// Matching grant id, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
}

/// Local in-memory implementation of the grant store contract.
#[derive(Debug, Default, Clone)]
pub struct LocalIdentityGrantStore {
    grants: BTreeMap<String, IdentityGrant>,
}

impl LocalIdentityGrantStore {
    /// Create an empty local grant store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a local store from persisted grant rows.
    #[must_use]
    pub fn from_grants(grants: impl IntoIterator<Item = IdentityGrant>) -> Self {
        let mut store = Self::new();
        for grant in grants {
            store.upsert(grant);
        }
        store
    }

    /// Number of grant rows in the store.
    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// Whether the store contains no grant rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// Iterate over all grant rows, ordered by grant id.
    pub fn values(&self) -> impl Iterator<Item = &IdentityGrant> {
        self.grants.values()
    }

    /// Insert or replace a grant.
    pub fn upsert(&mut self, grant: IdentityGrant) {
        self.grants.insert(grant.grant_id.clone(), grant);
    }

    /// Revoke an existing grant. Returns true when a grant was found.
    pub fn revoke(&mut self, grant_id: &str, revoked_at: DateTime<Utc>) -> bool {
        let Some(grant) = self.grants.get_mut(grant_id) else {
            return false;
        };
        grant.revoked_at = Some(revoked_at);
        true
    }

    /// Evaluate one request against the local grant set.
    #[must_use]
    pub fn evaluate(&self, request: &IdentityGrantRequest) -> IdentityGrantEvaluation {
        match request.exposure {
            CapabilityExposure::Public => {
                return Self::outcome(
                    request,
                    true,
                    IdentityGrantDecisionReason::PublicCapability,
                    None,
                );
            }
            CapabilityExposure::Shared => {
                return Self::outcome(
                    request,
                    true,
                    IdentityGrantDecisionReason::SharedCapability,
                    None,
                );
            }
            CapabilityExposure::Personal => {}
        }

        let Some(identity) = request.identity.as_ref() else {
            return Self::outcome(
                request,
                false,
                IdentityGrantDecisionReason::MissingIdentity,
                None,
            );
        };

        let Some(owner) = request.owner.as_ref() else {
            return Self::outcome(
                request,
                false,
                IdentityGrantDecisionReason::MissingOwner,
                None,
            );
        };

        if owner != identity {
            return Self::outcome(
                request,
                false,
                IdentityGrantDecisionReason::OwnerMismatch,
                None,
            );
        }

        let matching_grant = self.grants.values().find(|grant| {
            grant.covers(
                identity,
                request.agent_id.as_deref(),
                &request.capability,
                request.tool.as_deref(),
                &request.scope,
                request.now,
            ) && grant
                .owner
                .as_ref()
                .is_none_or(|grant_owner| grant_owner == owner)
        });

        if let Some(grant) = matching_grant {
            return Self::outcome(
                request,
                true,
                IdentityGrantDecisionReason::GrantMatched,
                Some(grant.grant_id.clone()),
            );
        }

        Self::outcome(
            request,
            false,
            IdentityGrantDecisionReason::MissingGrant,
            None,
        )
    }

    /// Recommend the least-privilege grant action for one local workflow.
    #[must_use]
    pub fn recommend(&self, request: &GrantRecommendationRequest) -> GrantRecommendation {
        if matches!(
            request.exposure,
            CapabilityExposure::Public | CapabilityExposure::Shared
        ) {
            return Self::recommendation(
                request,
                GrantRecommendationDecision::AllowPublicOrShared,
                GrantRecommendationReason::PublicOrSharedCapability,
                "Public or shared capability does not need a personal grant.".to_string(),
                false,
                None,
            );
        }

        let evaluation = self.evaluate(&IdentityGrantRequest {
            identity: request.identity.clone(),
            agent_id: request.agent_id.clone(),
            capability: request.capability.clone(),
            tool: request.tool.clone(),
            scope: request.scope.clone(),
            exposure: request.exposure,
            owner: request.owner.clone(),
            now: request.now,
        });

        if evaluation.allowed {
            return Self::recommendation(
                request,
                GrantRecommendationDecision::UseExistingGrant,
                GrantRecommendationReason::ExistingGrant,
                "A live grant already covers this request.".to_string(),
                false,
                None,
            );
        }

        let Some(identity) = request.identity.as_ref() else {
            return Self::recommendation(
                request,
                GrantRecommendationDecision::Deny,
                GrantRecommendationReason::MissingIdentity,
                "Cannot recommend a personal grant without caller identity.".to_string(),
                false,
                None,
            );
        };

        let Some(owner) = request.owner.as_ref() else {
            return Self::recommendation(
                request,
                GrantRecommendationDecision::Deny,
                GrantRecommendationReason::MissingOwner,
                "Cannot recommend a personal grant without owner evidence.".to_string(),
                false,
                None,
            );
        };

        if owner != identity {
            return Self::recommendation(
                request,
                GrantRecommendationDecision::RequestAdmin,
                GrantRecommendationReason::CrossUserAccess,
                "Cross-user personal access requires delegated administrator review.".to_string(),
                true,
                None,
            );
        }

        let lease = Some(build_lease_proposal(request, identity, owner));
        if matches!(
            request.tool_risk,
            GrantToolRisk::High | GrantToolRisk::Destructive
        ) {
            return Self::recommendation(
                request,
                GrantRecommendationDecision::RequireConfirmation,
                GrantRecommendationReason::HighRiskTool,
                "Tool risk requires explicit confirmation before a lease is used.".to_string(),
                true,
                lease,
            );
        }

        if matches!(
            request.data_class,
            GrantDataClass::Personal | GrantDataClass::Sensitive
        ) || matches!(request.scope, GrantScope::Write | GrantScope::Any)
        {
            return Self::recommendation(
                request,
                GrantRecommendationDecision::RequireConfirmation,
                GrantRecommendationReason::SensitiveOrBroadScope,
                "Scope or data class requires explicit confirmation before a lease is used."
                    .to_string(),
                true,
                lease,
            );
        }

        Self::recommendation(
            request,
            GrantRecommendationDecision::RecommendLease,
            GrantRecommendationReason::LeastPrivilegeLease,
            "Recommend a short least-privilege lease for this local workflow.".to_string(),
            true,
            lease,
        )
    }

    fn outcome(
        request: &IdentityGrantRequest,
        allowed: bool,
        reason: IdentityGrantDecisionReason,
        grant_id: Option<String>,
    ) -> IdentityGrantEvaluation {
        IdentityGrantEvaluation {
            allowed,
            reason: reason.clone(),
            grant_id: grant_id.clone(),
            audit: IdentityGrantAuditEvent {
                event: "identity_grant.evaluated".to_string(),
                timestamp: request.now,
                allowed,
                reason,
                subject: request.identity.clone(),
                agent_id: request.agent_id.clone(),
                capability: request.capability.clone(),
                tool: request.tool.clone(),
                scope: request.scope.clone(),
                grant_id,
            },
        }
    }

    fn recommendation(
        request: &GrantRecommendationRequest,
        decision: GrantRecommendationDecision,
        reason: GrantRecommendationReason,
        explanation: String,
        confirmation_required: bool,
        lease: Option<GrantLeaseProposal>,
    ) -> GrantRecommendation {
        let lease_expires_at = lease.as_ref().map(|proposal| proposal.expires_at);
        GrantRecommendation {
            decision: decision.clone(),
            reason: reason.clone(),
            explanation,
            confirmation_required,
            lease,
            revoke_path: "Revoke the issued grant id or let the proposed lease expire.".to_string(),
            audit: GrantRecommendationAuditEvent {
                event: "identity_grant.recommended".to_string(),
                timestamp: request.now,
                decision,
                reason,
                subject: request.identity.clone(),
                agent_id: request.agent_id.clone(),
                capability: request.capability.clone(),
                tool: request.tool.clone(),
                scope: request.scope.clone(),
                exposure: request.exposure,
                confirmation_required,
                lease_expires_at,
            },
        }
    }
}

fn build_lease_proposal(
    request: &GrantRecommendationRequest,
    identity: &GrantSubject,
    owner: &GrantSubject,
) -> GrantLeaseProposal {
    let lease_seconds = request
        .requested_lease_seconds
        .unwrap_or(DEFAULT_GRANT_LEASE_SECONDS)
        .clamp(60, MAX_GRANT_LEASE_SECONDS);

    GrantLeaseProposal {
        subject: identity.clone(),
        agent: request
            .agent_id
            .as_ref()
            .map_or(GrantAgent::Any, |agent_id| {
                GrantAgent::Exact(agent_id.clone())
            }),
        capability: request.capability.clone(),
        tool: request.tool.clone(),
        scope: request.scope.clone(),
        owner: Some(owner.clone()),
        expires_at: request.now + Duration::seconds(lease_seconds),
        reason: request.reason.clone(),
        provenance: "identity_grant.recommendation".to_string(),
    }
}

#[cfg(test)]
#[path = "identity_grants_tests.rs"]
mod tests;
