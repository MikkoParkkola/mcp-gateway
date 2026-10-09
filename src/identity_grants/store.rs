// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::{
    CapabilityExposure, DEFAULT_GRANT_LEASE_SECONDS, DateTime, Duration, GrantAgent, GrantAgentKey,
    GrantDataClass, GrantLeaseProposal, GrantRecommendation, GrantRecommendationAuditEvent,
    GrantRecommendationDecision, GrantRecommendationReason, GrantRecommendationRequest, GrantScope,
    GrantSubject, GrantToolRisk, IdentityGrant, IdentityGrantAuditEvent,
    IdentityGrantDecisionReason, IdentityGrantEvaluation, IdentityGrantRequest,
    LocalIdentityGrantStore, MAX_GRANT_LEASE_SECONDS, OwnedProvenAgentId, Utc,
};

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
                request.agent_id.as_ref(),
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
        ) || matches!(request.scope, GrantScope::Any)
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
                agent_id: request.agent_id.as_ref().map(OwnedProvenAgentId::qualified),
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
                agent_id: request.agent_id.as_ref().map(OwnedProvenAgentId::qualified),
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
        agent: request.agent_id.as_ref().map_or(GrantAgent::Any, |agent| {
            GrantAgent::Exact(GrantAgentKey {
                source: agent.proof(),
                id: agent.as_str().to_string(),
            })
        }),
        capability: request.capability.clone(),
        tool: request.tool.clone(),
        scope: request.scope.clone(),
        owner: Some(owner.clone()),
        // Clamped to MAX_GRANT_LEASE_SECONDS above, so always in range.
        expires_at: request.now
            + Duration::try_seconds(lease_seconds).unwrap_or(crate::duration_bound::delta!(
                seconds,
                MAX_GRANT_LEASE_SECONDS
            )),
        reason: request.reason.clone(),
        provenance: "identity_grant.recommendation".to_string(),
    }
}
