// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D3-a, harness H1: grant decision records through `handle_tools_call`,
//! the production dispatch tail, on a personal capability (T1-T3, T7, T8,
//! T17-T19, T25, T27).

use std::sync::Arc;

use serde_json::{Value, json};

use super::grant_audit_fixture::{
    CAPS, Endpoint, PERSONAL, capability_backend, capability_backend_exposed, decision_subject,
    decisions, entries, grant, grants, invocations, log_path, logger, trace_of,
};
use crate::backend::BackendRegistry;
use crate::gateway::meta_mcp::{Authentication, MetaMcp, MetaMcpCallerContext};
use crate::identity_grants::{GrantSubject, IdentityGrant};
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::RequestId;
use crate::security::audit::{AuditFailurePolicy, CredentialKind};

static ALLOW_ALL: crate::gateway::authz::AllowAll = crate::gateway::authz::AllowAll;

/// The API-key caller every H1 cell uses, and the capability's owner.
const ALICE: (&str, &str) = ("api_key", "alice");

/// Who calls: an API key, or a verified OIDC identity.
pub(super) struct Who {
    kind: CredentialKind,
    api_key_name: Option<String>,
    grant_subject: Option<GrantSubject>,
    identity: Option<VerifiedIdentity>,
}

/// A key caller carries the grant subject the grant rule derives for it
/// (`api_key`, name): the capability executor checks the owner against it.
pub(super) fn api_key(name: &str) -> Who {
    Who {
        kind: CredentialKind::ApiKey,
        api_key_name: Some(name.to_string()),
        grant_subject: Some(GrantSubject::new("api_key", name, Some(name.to_string()))),
        identity: None,
    }
}

fn oidc(issuer: &str, subject: &str, email: &str) -> Who {
    Who {
        kind: CredentialKind::OidcBearer,
        api_key_name: None,
        grant_subject: Some(GrantSubject::new(issuer, subject, Some(email.to_string()))),
        identity: Some(VerifiedIdentity {
            subject: subject.to_string(),
            email: email.to_string(),
            name: None,
            groups: vec![],
            issuer: issuer.to_string(),
        }),
    }
}

/// The caller context production builds for `who`.
pub(super) fn context(who: &Who) -> MetaMcpCallerContext<'_> {
    MetaMcpCallerContext {
        task: None,
        signing: None,
        execution: None,
        credential_principal: None,
        authentication: Authentication::Authenticated,
        credential_kind: who.kind,
        is_modern: false,
        protocol_revision: Some(crate::protocol::PROTOCOL_VERSION),
        authorizer: &ALLOW_ALL,
        api_key_name: who.api_key_name.as_deref(),
        agent_id: None,
        agent_declared: None,
        grant_subject: who.grant_subject.clone(),
        stdio_nonce: None,
        caller_key: None,
        verified_identity: who.identity.as_ref(),
        is_admin: false,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        era: crate::protocol::meta::Era::Legacy,
        channel: &crate::gateway::input_bridge::NoClientChannel,
    }
}

/// A gateway with the personal capability served at `endpoint`, `rows` as
/// its grants and, when `dir` is given, a log there under `policy`.
pub(super) fn gateway(
    endpoint: &Endpoint,
    rows: Vec<IdentityGrant>,
    dir: Option<&tempfile::TempDir>,
    policy: AuditFailurePolicy,
) -> MetaMcp {
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()))
        .with_identity_grants(grants(rows))
        .with_code_mode(true);
    if let Some(dir) = dir {
        meta.enable_transparency_log(logger(dir, policy));
    }
    meta.set_capabilities(capability_backend(endpoint.port, ALICE));
    meta
}

fn invoke_args() -> Value {
    json!({ "server": CAPS, "tool": PERSONAL, "arguments": {} })
}

/// One `tools/call` through the dispatch tail, answered as the client sees it.
async fn call(meta: &MetaMcp, who: &Who, tool_name: &str, arguments: Value) -> Value {
    let response = Box::pin(meta.handle_tools_call(
        RequestId::Number(1),
        tool_name,
        arguments,
        Some("d3a-session"),
        context(who),
    ))
    .await;
    serde_json::to_value(&response).expect("a response serialises")
}

fn error_code(answer: &Value) -> Option<i64> {
    answer.pointer("/error/code").and_then(Value::as_i64)
}

fn only(records: Vec<Value>, what: &str) -> Value {
    assert_eq!(
        records.len(),
        1,
        "expected exactly one {what}: {records:#?}"
    );
    records.into_iter().next().expect("one record")
}

/// T1. A denial on a personal capability is one `denied` record, paired
/// with the call's invocation record by trace.
#[tokio::test]
async fn grant_denial_writes_decision_record() {
    let (endpoint, dir) = (Endpoint::start(false).await, tempfile::tempdir().unwrap());
    let meta = gateway(
        &endpoint,
        vec![],
        Some(&dir),
        AuditFailurePolicy::BestEffort,
    );

    let answer = call(&meta, &api_key("alice"), "gateway_invoke", invoke_args()).await;
    assert_eq!(error_code(&answer), Some(-32004), "{answer}");

    let invocation = only(invocations(&dir), "invocation record");
    let record = only(decisions(&dir), "decision record");
    assert_eq!(record["outcome"], json!("denied"), "{record}");
    assert_eq!(record["reason"], json!("missing_grant"), "{record}");
    assert!(record.get("timestamp").is_some(), "{record}");
    assert_eq!(trace_of(&record), trace_of(&invocation), "{record}");
    assert!(trace_of(&record).is_some(), "{record}");
    // MIK-7663.GH2409.4: `who` is built from the subject's authority and
    // subject, the same pair the record's `subject` field carries.
    assert_eq!(
        record["who"]["authority"], record["subject"]["authority"],
        "{record}"
    );
    assert_eq!(
        record["who"]["subject"], record["subject"]["subject"],
        "{record}"
    );
    assert_eq!(record["who"]["authority"], json!("api_key"), "{record}");
    // Control for the empty-flush row below: a slot holding a note flushes.
    assert!(
        super::grant_audit::grant_bookkeeping_for_test().flushes_spawned >= 1,
        "a slot holding a decision note spawns its flush"
    );
}

/// T2. A matching grant is one `ok` record naming the grant.
#[tokio::test]
async fn grant_match_writes_allow_record() {
    let (endpoint, dir) = (Endpoint::start(false).await, tempfile::tempdir().unwrap());
    let rows = vec![grant("g1", ALICE, ALICE)];
    let meta = gateway(&endpoint, rows, Some(&dir), AuditFailurePolicy::BestEffort);

    let answer = call(&meta, &api_key("alice"), "gateway_invoke", invoke_args()).await;
    assert!(answer.get("error").is_none(), "{answer}");
    assert_eq!(
        endpoint.arrivals(),
        1,
        "the granted call reaches the capability"
    );

    let invocation = only(invocations(&dir), "invocation record");
    let record = only(decisions(&dir), "decision record");
    assert_eq!(record["outcome"], json!("ok"), "{record}");
    assert_eq!(record["grant_id"], json!("g1"), "{record}");
    assert_eq!(trace_of(&record), trace_of(&invocation), "{record}");
    assert!(trace_of(&record).is_some(), "{record}");
}

/// T3 (control). Public and shared capabilities are not grant decisions.
#[tokio::test]
async fn public_capability_writes_no_decision() {
    for exposure in ["public", "shared"] {
        let (endpoint, dir) = (Endpoint::start(false).await, tempfile::tempdir().unwrap());
        let meta = gateway(
            &endpoint,
            vec![],
            Some(&dir),
            AuditFailurePolicy::BestEffort,
        );
        meta.set_capabilities(capability_backend_exposed(endpoint.port, ALICE, exposure));

        let answer = call(&meta, &api_key("alice"), "gateway_invoke", invoke_args()).await;
        assert!(answer.get("error").is_none(), "{exposure}: {answer}");
        assert!(
            decisions(&dir).is_empty(),
            "{exposure}: {:#?}",
            entries(&dir)
        );
        only(invocations(&dir), "invocation record");
    }
    // MIK-7663.GH2409.1: a slot that collected no decision note writes
    // nothing, so it spawns no flush task.
    assert_eq!(
        super::grant_audit::grant_bookkeeping_for_test().flushes_spawned,
        0,
        "an empty slot spawns no flush"
    );
}

/// T7. Under `FailClosed` a failed decision write withholds the answer;
/// D1's invocation append is untouched, so it cannot be what failed.
#[tokio::test]
async fn grant_decision_append_failure_is_audit_unavailable() {
    let (endpoint, dir) = (Endpoint::start(false).await, tempfile::tempdir().unwrap());
    let log = logger(&dir, AuditFailurePolicy::FailClosed);
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()))
        .with_identity_grants(grants(vec![grant("g1", ALICE, ALICE)]));
    meta.enable_transparency_log(Arc::clone(&log));
    meta.set_capabilities(capability_backend(endpoint.port, ALICE));
    log.fail_next_append_of_kind_for_test(super::grant_audit_fixture::DECISION_KIND);

    let answer = call(&meta, &api_key("alice"), "gateway_invoke", invoke_args()).await;
    assert_eq!(error_code(&answer), Some(-32005), "{answer}");
    only(invocations(&dir), "invocation record");
}

/// T8. The record names the caller by `(authority, subject)`, never by label.
#[tokio::test]
async fn grant_decision_record_carries_no_label() {
    let callers = [
        (
            oidc("https://idp.test", "u-1", "x@corp.com"),
            ("https://idp.test", "u-1"),
        ),
        (api_key("ci-key"), ("api_key", "ci-key")),
    ];
    for (who, (authority, subject)) in callers {
        let (endpoint, dir) = (Endpoint::start(false).await, tempfile::tempdir().unwrap());
        let meta = gateway(
            &endpoint,
            vec![],
            Some(&dir),
            AuditFailurePolicy::BestEffort,
        );

        call(&meta, &who, "gateway_invoke", invoke_args()).await;

        let record = only(decisions(&dir), "decision record");
        assert_eq!(
            decision_subject(&record),
            (Some(authority), Some(subject)),
            "{record}"
        );
        assert!(record["subject"].get("label").is_none(), "{record}");
        assert!(record.get("label").is_none(), "{record}");
        let log = std::fs::read_to_string(log_path(&dir)).unwrap_or_default();
        assert!(
            !log.contains("x@corp.com"),
            "the label reached the log: {log}"
        );
    }
}

/// T17 (control). Listing and search are `Emit::Silent`: no decision.
#[tokio::test]
async fn listing_writes_no_decision() {
    let (endpoint, dir) = (Endpoint::start(false).await, tempfile::tempdir().unwrap());
    let meta = gateway(
        &endpoint,
        vec![],
        Some(&dir),
        AuditFailurePolicy::BestEffort,
    );
    let who = api_key("alice");

    let listed = call(&meta, &who, "gateway_list_tools", json!({ "server": CAPS })).await;
    assert!(listed.get("error").is_none(), "{listed}");
    let found = call(
        &meta,
        &who,
        "gateway_search_tools",
        json!({ "query": "calendar" }),
    )
    .await;
    assert!(found.get("error").is_none(), "{found}");
    assert!(decisions(&dir).is_empty(), "{:#?}", entries(&dir));
}

/// T18 (R1). `invoke_tool` called directly opens its own slot: one record,
/// no panic, the answer unchanged.
#[tokio::test]
async fn direct_invoke_tool_writes_one_record() {
    let (endpoint, dir) = (Endpoint::start(false).await, tempfile::tempdir().unwrap());
    let rows = vec![grant("g1", ALICE, ALICE)];
    let meta = gateway(&endpoint, rows, Some(&dir), AuditFailurePolicy::BestEffort);
    let who = api_key("alice");

    let result = meta
        .invoke_tool(&invoke_args(), Some("d3a-session"), &context(&who))
        .await
        .expect("a granted direct call succeeds");
    assert_ne!(result["isError"], json!(true), "{result}");
    let record = only(decisions(&dir), "decision record");
    assert_eq!(record["outcome"], json!("ok"), "{record}");
}

/// T19 (R2, control). With no logger, noting is a no-op: today's answers,
/// no slot and no note.
#[tokio::test]
async fn no_logger_changes_nothing() {
    let endpoint = Endpoint::start(false).await;
    let who = api_key("alice");
    let granted = gateway(
        &endpoint,
        vec![grant("g1", ALICE, ALICE)],
        None,
        AuditFailurePolicy::BestEffort,
    );
    let result = granted
        .invoke_tool(&invoke_args(), Some("d3a-session"), &context(&who))
        .await
        .expect("a granted call with no logger succeeds");
    assert_ne!(result["isError"], json!(true), "{result}");

    let ungranted = gateway(&endpoint, vec![], None, AuditFailurePolicy::BestEffort);
    let refusal = ungranted
        .invoke_tool(&invoke_args(), Some("d3a-session"), &context(&who))
        .await
        .expect_err("an ungranted call is refused");
    assert_eq!(refusal.to_rpc_code(), -32004, "{refusal}");

    assert_eq!(
        super::grant_audit::grant_bookkeeping_for_test(),
        super::grant_audit::GrantBookkeeping::default(),
        "no logger: no slot opened, no note taken"
    );
}

/// T27 (H1). A direct-name call to a surfaced personal tool is a dispatch
/// decision: the concealed -32601 answer is unchanged, and it is recorded.
#[tokio::test]
async fn surfaced_call_grant_denial_writes_one_record() {
    let (endpoint, dir) = (Endpoint::start(false).await, tempfile::tempdir().unwrap());
    let meta = gateway(
        &endpoint,
        vec![],
        Some(&dir),
        AuditFailurePolicy::BestEffort,
    )
    .with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
        server: CAPS.to_string(),
        tool: PERSONAL.to_string(),
    }]);

    let answer = call(&meta, &api_key("alice"), PERSONAL, json!({})).await;
    assert_eq!(error_code(&answer), Some(-32601), "{answer}");
    assert_eq!(endpoint.arrivals(), 0, "the refused call reaches nothing");
    let record = only(decisions(&dir), "decision record");
    assert_eq!(record["outcome"], json!("denied"), "{record}");
}
