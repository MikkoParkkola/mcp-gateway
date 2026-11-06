// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A grant refusal is decided by no grant row, so its invocation record names
//! the grant check and neither a rule id nor a grant id, even when the store
//! is keyed and a row that does not match holds an id.

use std::sync::Arc;

use serde_json::json;

use super::super::grant_audit_fixture::{Endpoint, PERSONAL, decisions, grant, invocations};
use super::{Who, api_key, call, gateway, invoke_args, only};
use crate::identity_grants::IdentityGrant;
use crate::security::audit::{AuditFailurePolicy, CredentialKind};
use crate::security::rule_id::RuleKey;

const ALICE: (&str, &str) = ("api_key", "alice");
const BOB: (&str, &str) = ("api_key", "bob");

/// A past instant, for an expired or a revoked row.
fn past() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_000_000_000, 0).expect("a valid instant")
}

/// `who` calls alice's personal capability with `row` as the store's one
/// grant, keyed, and is refused for `reason`: `row` holds an id, and the one
/// invocation record names the grant check and no rule or grant.
async fn refused_without_ids(case: &str, (who, reason): (Who, &str), row: IdentityGrant) {
    let (endpoint, dir) = (
        Endpoint::start(false).await,
        Arc::new(tempfile::tempdir().unwrap()),
    );
    let meta = gateway(
        &endpoint,
        vec![],
        Some(&dir),
        AuditFailurePolicy::BestEffort,
    );
    let key = RuleKey::from_derived([9; 32]);
    let store = crate::identity_grants::LocalIdentityGrantStore::from_grants(vec![row.clone()]);
    meta.set_identity_grants(store.with_rule_ids(&key));
    let (live, _) = meta.identity_grant_sink();
    let held = live.read().rule_id(&row.grant_id).cloned();
    assert!(held.is_some(), "{case}: premise, the row holds an id");
    let answer = call(&meta, &who, "gateway_invoke", invoke_args()).await;
    assert!(
        answer.get("error").is_some(),
        "{case}: premise, refused: {answer}"
    );
    let grant_record = only(decisions(&dir), "grant decision record");
    assert_eq!(
        grant_record["reason"],
        json!(reason),
        "{case}: {grant_record}"
    );
    let record = only(invocations(&dir), "invocation record");
    let decision = &record["decision"];
    assert_eq!(
        decision["kind"],
        json!("grant"),
        "{case} {PERSONAL}: {record}"
    );
    assert!(
        decision.get("rule_id").is_none(),
        "{case}: no rule_id: {record}"
    );
    assert!(
        decision.get("grant_id").is_none(),
        "{case}: no grant_id: {record}"
    );
    let id = held.expect("checked above");
    assert!(
        !record.to_string().contains(id.as_str()),
        "{case}: the record names the row: {record}"
    );
}

/// A key caller with no grant subject: the grant rule has no identity.
fn no_identity() -> Who {
    Who {
        kind: CredentialKind::ApiKey,
        api_key_name: Some("anon".to_string()),
        grant_subject: None,
        identity: None,
    }
}

#[tokio::test]
async fn a_grant_refusal_records_no_rule_or_grant_id() {
    let mut other = grant("g-other", ALICE, ALICE);
    other.capability = "another-capability".to_string();
    let mut expired = grant("g-expired", ALICE, ALICE);
    expired.expires_at = Some(past());
    let mut revoked = grant("g-revoked", ALICE, ALICE);
    revoked.revoked_at = Some(past());
    let cases = [
        (
            "another capability's grant",
            api_key("alice"),
            "missing_grant",
            other,
        ),
        (
            "an expired grant",
            api_key("alice"),
            "missing_grant",
            expired,
        ),
        (
            "a revoked grant",
            api_key("alice"),
            "missing_grant",
            revoked,
        ),
        (
            "bob's grant",
            api_key("bob"),
            "owner_mismatch",
            grant("g-bob", BOB, BOB),
        ),
        (
            "no identity",
            no_identity(),
            "missing_identity",
            grant("g-a", ALICE, ALICE),
        ),
    ];
    for (case, who, reason, row) in cases {
        Box::pin(refused_without_ids(case, (who, reason), row)).await;
    }
}
