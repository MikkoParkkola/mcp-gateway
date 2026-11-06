// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A grant refusal is decided by no grant row, so its invocation record names
//! the grant check and neither a rule id nor a grant id.

use std::sync::Arc;

use serde_json::json;

use super::super::grant_audit_fixture::{Endpoint, PERSONAL, decisions, grant, invocations};
use super::{api_key, call, gateway, invoke_args, only};
use crate::security::audit::AuditFailurePolicy;

/// `caller` calls alice's personal capability, `rows` its grants, and is
/// refused for `reason`: the one invocation record names the grant check
/// and no rule or grant.
async fn refused_without_ids(
    (caller, reason): (&str, &str),
    rows: Vec<crate::identity_grants::IdentityGrant>,
) {
    let (endpoint, dir) = (
        Endpoint::start(false).await,
        Arc::new(tempfile::tempdir().unwrap()),
    );
    let meta = gateway(&endpoint, rows, Some(&dir), AuditFailurePolicy::BestEffort);
    let answer = call(&meta, &api_key(caller), "gateway_invoke", invoke_args()).await;
    assert!(answer.get("error").is_some(), "premise, refused: {answer}");
    let grant_record = only(decisions(&dir), "grant decision record");
    assert_eq!(
        grant_record["reason"],
        json!(reason),
        "premise: {grant_record}"
    );
    let record = only(invocations(&dir), "invocation record");
    let decision = &record["decision"];
    assert_eq!(decision["kind"], json!("grant"), "{PERSONAL}: {record}");
    assert!(decision.get("rule_id").is_none(), "no rule_id: {record}");
    assert!(decision.get("grant_id").is_none(), "no grant_id: {record}");
}

#[tokio::test]
async fn a_grant_refusal_records_no_rule_or_grant_id() {
    // MissingGrant: alice holds no grant.
    refused_without_ids(("alice", "missing_grant"), vec![]).await;
    // OwnerMismatch: bob holds a grant, but the capability is alice's.
    refused_without_ids(
        ("bob", "owner_mismatch"),
        vec![grant("g-bob", ("api_key", "bob"), ("api_key", "bob"))],
    )
    .await;
}
