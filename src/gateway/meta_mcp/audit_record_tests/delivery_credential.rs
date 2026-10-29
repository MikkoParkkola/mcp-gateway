// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8672: meta-route delivery records name the credential of runtime-minted
//! callers (OIDC bearer, key-server token, dashboard session), as the
//! invocation record of the same call does. Split from `audit_record_tests.rs`.

use serde_json::{Value, json};

use super::{Caller, args, context, meta, ok_result, only_record};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::response_security::DeliveryCredential;
use crate::gateway::record_principal::InternalPrincipal;
use crate::identity_grants::GrantSubject;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::audit::CredentialKind;

/// Delivery-attempt records only (MIK-8672).
fn deliveries(dir: &tempfile::TempDir) -> Vec<Value> {
    std::fs::read_to_string(dir.path().join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|e| e["event"] == "response_delivery_attempt")
        .collect()
}

fn only_delivery(dir: &tempfile::TempDir) -> Value {
    let all = deliveries(dir);
    assert_eq!(
        all.len(),
        1,
        "expected exactly one delivery record: {all:?}"
    );
    all.into_iter().next().expect("one delivery record")
}

/// The delivery record the meta route writes for `who`'s answer: the finalized
/// response, correlated as the route correlates it (MIK-8672 C3).
async fn record_delivery_for(
    meta: &MetaMcp,
    who: &Caller,
    client: &crate::gateway::auth::AuthenticatedClient,
) {
    let response = JsonRpcResponse::success(RequestId::Number(1), ok_result());
    let correlation = crate::security::response_policy::ResponseCorrelation {
        session_id: "",
        caller: who.account.as_str(),
        external_server: "alpha",
        external_tool: "gateway_invoke",
        subject: who.grant.as_ref(),
        trace_id: None,
        key: crate::security::response_policy::KeyOf::NotKnown,
    };
    assert!(
        meta.record_delivery_of(
            &response,
            &correlation,
            DeliveryCredential::of(
                Some(client),
                &crate::gateway::record_principal::test_record_key()
            ),
            None,
        )
        .await,
        "the delivery is recorded"
    );
}

/// The delivery record names `kind` and `principal`, equal to the invocation
/// record's `who`.
fn assert_delivery_matches_invocation(dir: &tempfile::TempDir, kind: &str, principal: &str) {
    let delivery = only_delivery(dir);
    let invocation = only_record(dir);
    assert_eq!(
        delivery["who"]["credential_kind"],
        json!(kind),
        "{delivery}"
    );
    // The record carries the keyed form, never the stored principal (MIK-8697).
    let keyed = crate::gateway::record_principal::InternalPrincipal::new(principal.to_owned())
        .record_form(&crate::gateway::record_principal::test_record_key());
    assert_eq!(delivery["who"]["principal"], json!(keyed), "{delivery}");
    assert_eq!(
        delivery["who"]["credential_kind"], invocation["who"]["credential_kind"],
        "{invocation}"
    );
    assert_eq!(
        delivery["who"]["principal"], invocation["who"]["principal"],
        "{invocation}"
    );
}

/// The key-server harness (loopback OIDC plus `/auth/token`), trusting
/// provider A with a policy granting every A identity all backends.
async fn key_server_harness() -> crate::key_server::oidc_test_harness::Harness {
    use crate::key_server::oidc_test_harness::{ISS_A, config_yaml};
    let extra = format!(
        "delegated_bearer: true\npolicies:\n  - match: {{ issuer: \"{ISS_A}\" }}\n    scopes: {{ backends: [\"*\"], tools: [\"*\"], rate_limit: 0 }}\n"
    );
    crate::key_server::oidc_test_harness::Harness::start(&config_yaml("[]", &extra)).await
}

/// `subject`'s ID token from provider A, as the harness's provider mints it.
fn id_token(harness: &crate::key_server::oidc_test_harness::Harness, subject: &str) -> String {
    harness.mint(
        crate::key_server::oidc_test_harness::ISS_A,
        subject,
        &json!({ "email": format!("{subject}@corp.example") }),
    )
}

/// `client` (validated by the key server) as an audit `Caller`, granted its
/// verified subject.
fn caller_of(
    client: &crate::gateway::auth::AuthenticatedClient,
    identity: crate::key_server::oidc::VerifiedIdentity,
) -> Caller {
    Caller {
        principal: client.principal.storage_form().to_owned(),
        account: client.name.clone(),
        authenticated: true,
        grant: Some(GrantSubject::new(
            identity.issuer.as_str(),
            identity.subject.as_str(),
            None,
        )),
        identity: Some(identity),
        kind: client.credential_kind,
    }
}

/// A dashboard session's caller: mirrors the private `dashboard_client`
/// mint's values (a disclosed limit).
fn dashboard_caller() -> Caller {
    Caller {
        principal: "dashboard-session".to_string(),
        account: "dashboard".to_string(),
        authenticated: true,
        grant: None,
        identity: None,
        kind: CredentialKind::DashboardSession,
    }
}

/// C3 (MIK-8672): meta delivery records name the harness credentials.
#[tokio::test]
async fn meta_delivery_records_name_the_harness_credentials() {
    // | none | Caller::Anonymous | direct, meta — direct_audit_tests C3 |
    // | api_key | Caller::Key | direct, meta — direct_audit_tests C3 |
    // | static_bearer | Caller::Bearer | direct, meta — direct_audit_tests C3 |
    // | oidc_bearer | key-server harness, delegated Bearer [REDACTED] | meta (below) |
    // | key_server_token | key-server harness, exchanged token | meta (below) |
    // | dashboard_session | UI session harness | meta (below) |
    // N/A: local_transport — stdio only (C5).
    // N/A (direct): oidc_bearer, key_server_token, dashboard_session — no
    // harness stages these credentials on the direct route.
    let harness = key_server_harness().await;
    // oidc_bearer row: the ID token itself, as a delegated bearer.
    {
        let dir = tempfile::tempdir().expect("a log directory");
        let meta = meta(Ok(ok_result()), &dir);
        let id = id_token(&harness, "c3-oidc");
        let (client, identity) = harness
            .ks
            .verify_bearer_identity(&id)
            .await
            .expect("the delegated Bearer [REDACTED]");
        let who = caller_of(&client, identity);
        meta.invoke_tool(&args(), None, &context(&AllowAll, &who))
            .await
            .expect("allowed call");
        record_delivery_for(&meta, &who, &client).await;
        assert_delivery_matches_invocation(&dir, "oidc_bearer", &who.principal);
    }
    // key_server_token row: the ID token exchanged at `/auth/token`.
    {
        let dir = tempfile::tempdir().expect("a log directory");
        let meta = meta(Ok(ok_result()), &dir);
        let id = id_token(&harness, "c3-kst");
        let (status, body) = harness.exchange(&id).await;
        assert_eq!(status, 200, "premise: the exchange succeeds: {body}");
        let token = body["access_token"]
            .as_str()
            .expect("an access token")
            .to_string();
        let (client, temp) = harness
            .ks
            .validate_token(&token)
            .await
            .expect("the exchanged token validates");
        let who = caller_of(&client, temp.identity);
        meta.invoke_tool(&args(), None, &context(&AllowAll, &who))
            .await
            .expect("allowed call");
        record_delivery_for(&meta, &who, &client).await;
        assert_delivery_matches_invocation(&dir, "key_server_token", &who.principal);
    }
    // dashboard_session row.
    {
        let dir = tempfile::tempdir().expect("a log directory");
        let meta = meta(Ok(ok_result()), &dir);
        // The middleware's own mint (`dashboard_client` in auth_clients.rs)
        // is private to `auth`, so the row carries its exact values.
        let client = crate::gateway::auth::AuthenticatedClient {
            quota_principal: Some(crate::gateway::auth::QuotaPrincipal::dashboard_session()),
            name: "dashboard".to_string(),
            principal: InternalPrincipal::new("dashboard-session".to_string()),
            rate_limit: 0,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: true,
            authenticated: true,
            credential_kind: CredentialKind::DashboardSession,
        };
        let who = dashboard_caller();
        meta.invoke_tool(&args(), None, &context(&AllowAll, &who))
            .await
            .expect("allowed call");
        record_delivery_for(&meta, &who, &client).await;
        assert_delivery_matches_invocation(&dir, "dashboard_session", &who.principal);
    }
}

/// C7 (MIK-8672): two tokens for one actor name different principals.
#[tokio::test]
async fn two_tokens_for_one_actor_name_different_principals() {
    let harness = key_server_harness().await;
    let id = id_token(&harness, "c7-actor");
    let mut principals = Vec::new();
    for _ in 0..2 {
        let (status, body) = harness.exchange(&id).await;
        assert_eq!(status, 200, "premise: the exchange succeeds: {body}");
        let token = body["access_token"]
            .as_str()
            .expect("an access token")
            .to_string();
        let (client, temp) = harness
            .ks
            .validate_token(&token)
            .await
            .expect("the exchanged token validates");
        let who = caller_of(&client, temp.identity);
        let dir = tempfile::tempdir().expect("a log directory");
        let meta = meta(Ok(ok_result()), &dir);
        meta.invoke_tool(&args(), None, &context(&AllowAll, &who))
            .await
            .expect("allowed call");
        record_delivery_for(&meta, &who, &client).await;
        principals.push(only_delivery(&dir)["who"]["principal"].clone());
    }
    assert_ne!(
        principals[0], principals[1],
        "one actor, two tokens, one principal"
    );
    for principal in &principals {
        assert!(
            principal
                .as_str()
                .is_some_and(|p| p.len() == 12 && !p.starts_with("kst:")),
            "{principal}"
        );
    }
}

/// P2 (MIK-8672): one actor's token, refresh and Bearer [REDACTED] one caller and account.
#[tokio::test]
async fn one_actors_token_refresh_and_bearer_name_one_caller_and_account() {
    let harness = key_server_harness().await;
    let id = id_token(&harness, "p2-actor");
    let mut whos = Vec::new();
    for _ in 0..2 {
        let (status, body) = harness.exchange(&id).await;
        assert_eq!(status, 200, "premise: the exchange succeeds: {body}");
        let token = body["access_token"]
            .as_str()
            .expect("an access token")
            .to_string();
        let (client, temp) = harness
            .ks
            .validate_token(&token)
            .await
            .expect("the exchanged token validates");
        whos.push((caller_of(&client, temp.identity), client));
    }
    let (client, identity) = harness
        .ks
        .verify_bearer_identity(&id)
        .await
        .expect("the delegated Bearer [REDACTED]");
    whos.push((caller_of(&client, identity), client));
    let actor = whos[0].0.account.clone();
    for (who, _) in &whos {
        assert_eq!(who.account, actor, "premise: one actor");
    }
    for (who, client) in &whos {
        let dir = tempfile::tempdir().expect("a log directory");
        let meta = meta(Ok(ok_result()), &dir);
        meta.invoke_tool(&args(), None, &context(&AllowAll, who))
            .await
            .expect("allowed call");
        record_delivery_for(&meta, who, client).await;
        let delivery = only_delivery(&dir);
        assert_eq!(delivery["caller"], json!(actor), "{delivery}");
        assert_eq!(delivery["who"]["account"], json!(actor), "{delivery}");
    }
}
