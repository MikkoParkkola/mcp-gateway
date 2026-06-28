use chrono::{Duration, TimeZone};

use super::*;

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 28, 12, 0, 0).unwrap()
}

fn alice() -> GrantSubject {
    GrantSubject::new("local", "alice-sub", Some("alice".to_string()))
}

fn bob() -> GrantSubject {
    GrantSubject::new("local", "bob-sub", Some("bob".to_string()))
}

fn personal_request(identity: Option<GrantSubject>) -> IdentityGrantRequest {
    IdentityGrantRequest {
        identity,
        agent_id: Some("agent-a".to_string()),
        capability: "mail.send".to_string(),
        tool: Some("send_message".to_string()),
        scope: GrantScope::Execute,
        exposure: CapabilityExposure::Personal,
        owner: Some(alice()),
        now: now(),
    }
}

fn recommendation_request(identity: Option<GrantSubject>) -> GrantRecommendationRequest {
    GrantRecommendationRequest {
        identity,
        agent_id: Some("agent-a".to_string()),
        capability: "mail.read".to_string(),
        tool: Some("list_messages".to_string()),
        scope: GrantScope::Read,
        exposure: CapabilityExposure::Personal,
        owner: Some(alice()),
        data_class: GrantDataClass::Internal,
        tool_risk: GrantToolRisk::Low,
        requested_lease_seconds: None,
        reason: "read the current inbox summary".to_string(),
        now: now(),
    }
}

fn grant() -> IdentityGrant {
    IdentityGrant {
        grant_id: "grant-1".to_string(),
        subject: alice(),
        agent: GrantAgent::Exact("agent-a".to_string()),
        capability: "mail.send".to_string(),
        tool: Some("send_message".to_string()),
        scope: GrantScope::Execute,
        owner: Some(alice()),
        expires_at: Some(now() + Duration::hours(1)),
        revoked_at: None,
        provenance: "linear://MIK-6553".to_string(),
        reason: "operator-approved test grant".to_string(),
    }
}

#[test]
fn personal_capability_fails_closed_without_identity() {
    let store = LocalIdentityGrantStore::new();

    let evaluation = store.evaluate(&personal_request(None));

    assert!(!evaluation.allowed);
    assert_eq!(
        evaluation.reason,
        IdentityGrantDecisionReason::MissingIdentity
    );
    assert_eq!(evaluation.audit.event, "identity_grant.evaluated");
}

#[test]
fn personal_capability_requires_own_resource() {
    let mut store = LocalIdentityGrantStore::new();
    store.upsert(grant());

    let mut request = personal_request(Some(bob()));
    request.owner = Some(alice());

    let evaluation = store.evaluate(&request);

    assert!(!evaluation.allowed);
    assert_eq!(
        evaluation.reason,
        IdentityGrantDecisionReason::OwnerMismatch
    );
}

#[test]
fn personal_capability_requires_matching_live_grant() {
    let mut store = LocalIdentityGrantStore::new();
    let mut expired = grant();
    expired.expires_at = Some(now() - Duration::minutes(1));
    store.upsert(expired);

    let evaluation = store.evaluate(&personal_request(Some(alice())));

    assert!(!evaluation.allowed);
    assert_eq!(evaluation.reason, IdentityGrantDecisionReason::MissingGrant);
}

#[test]
fn matching_grant_allows_personal_capability_and_records_audit() {
    let mut store = LocalIdentityGrantStore::new();
    store.upsert(grant());

    let evaluation = store.evaluate(&personal_request(Some(alice())));

    assert!(evaluation.allowed);
    assert_eq!(evaluation.reason, IdentityGrantDecisionReason::GrantMatched);
    assert_eq!(evaluation.grant_id.as_deref(), Some("grant-1"));
    assert_eq!(evaluation.audit.grant_id.as_deref(), Some("grant-1"));
    assert_eq!(evaluation.audit.subject, Some(alice()));
}

#[test]
fn revoked_grant_is_not_accepted() {
    let mut store = LocalIdentityGrantStore::new();
    store.upsert(grant());
    assert!(store.revoke("grant-1", now()));

    let evaluation = store.evaluate(&personal_request(Some(alice())));

    assert!(!evaluation.allowed);
    assert_eq!(evaluation.reason, IdentityGrantDecisionReason::MissingGrant);
}

#[test]
fn public_and_shared_capabilities_preserve_backward_compatibility() {
    let store = LocalIdentityGrantStore::new();

    for exposure in [CapabilityExposure::Public, CapabilityExposure::Shared] {
        let mut request = personal_request(None);
        request.exposure = exposure;
        request.owner = None;

        let evaluation = store.evaluate(&request);

        assert!(evaluation.allowed);
    }
}

#[test]
fn recommendation_allows_public_and_shared_without_personal_grant() {
    let store = LocalIdentityGrantStore::new();

    for exposure in [CapabilityExposure::Public, CapabilityExposure::Shared] {
        let mut request = recommendation_request(None);
        request.exposure = exposure;
        request.owner = None;

        let recommendation = store.recommend(&request);

        assert_eq!(
            recommendation.decision,
            GrantRecommendationDecision::AllowPublicOrShared
        );
        assert_eq!(
            recommendation.reason,
            GrantRecommendationReason::PublicOrSharedCapability
        );
        assert!(!recommendation.confirmation_required);
        assert!(recommendation.lease.is_none());
    }
}

#[test]
fn recommendation_reuses_existing_live_grant_without_new_prompt() {
    let mut store = LocalIdentityGrantStore::new();
    let mut existing = grant();
    existing.capability = "mail.read".to_string();
    existing.tool = Some("list_messages".to_string());
    existing.scope = GrantScope::Read;
    store.upsert(existing);

    let recommendation = store.recommend(&recommendation_request(Some(alice())));

    assert_eq!(
        recommendation.decision,
        GrantRecommendationDecision::UseExistingGrant
    );
    assert_eq!(
        recommendation.reason,
        GrantRecommendationReason::ExistingGrant
    );
    assert!(!recommendation.confirmation_required);
    assert!(recommendation.lease.is_none());
}

#[test]
fn recommendation_proposes_short_least_privilege_lease_for_local_workflow() {
    let store = LocalIdentityGrantStore::new();
    let recommendation = store.recommend(&recommendation_request(Some(alice())));
    let lease = recommendation.lease.as_ref().unwrap();

    assert_eq!(
        recommendation.decision,
        GrantRecommendationDecision::RecommendLease
    );
    assert_eq!(
        recommendation.reason,
        GrantRecommendationReason::LeastPrivilegeLease
    );
    assert!(recommendation.confirmation_required);
    assert_eq!(lease.subject, alice());
    assert_eq!(lease.agent, GrantAgent::Exact("agent-a".to_string()));
    assert_eq!(lease.capability, "mail.read");
    assert_eq!(lease.tool.as_deref(), Some("list_messages"));
    assert_eq!(lease.scope, GrantScope::Read);
    assert_eq!(
        lease.expires_at,
        now() + Duration::seconds(DEFAULT_GRANT_LEASE_SECONDS)
    );
    assert_eq!(
        recommendation.audit.lease_expires_at,
        Some(lease.expires_at)
    );
}

#[test]
fn recommendation_clamps_requested_lease_duration() {
    let store = LocalIdentityGrantStore::new();
    let mut request = recommendation_request(Some(alice()));
    request.requested_lease_seconds = Some(MAX_GRANT_LEASE_SECONDS * 10);

    let recommendation = store.recommend(&request);
    let lease = recommendation.lease.as_ref().unwrap();

    assert_eq!(
        lease.expires_at,
        now() + Duration::seconds(MAX_GRANT_LEASE_SECONDS)
    );
}

#[test]
fn recommendation_requires_confirmation_for_sensitive_or_destructive_workflow() {
    let store = LocalIdentityGrantStore::new();
    let mut request = recommendation_request(Some(alice()));
    request.scope = GrantScope::Write;
    request.data_class = GrantDataClass::Sensitive;
    request.tool_risk = GrantToolRisk::Destructive;

    let recommendation = store.recommend(&request);

    assert_eq!(
        recommendation.decision,
        GrantRecommendationDecision::RequireConfirmation
    );
    assert_eq!(
        recommendation.reason,
        GrantRecommendationReason::HighRiskTool
    );
    assert!(recommendation.confirmation_required);
    assert!(recommendation.lease.is_some());
}

#[test]
fn recommendation_requests_admin_review_for_cross_user_access() {
    let store = LocalIdentityGrantStore::new();
    let recommendation = store.recommend(&recommendation_request(Some(bob())));

    assert_eq!(
        recommendation.decision,
        GrantRecommendationDecision::RequestAdmin
    );
    assert_eq!(
        recommendation.reason,
        GrantRecommendationReason::CrossUserAccess
    );
    assert!(recommendation.confirmation_required);
    assert!(recommendation.lease.is_none());
}
