// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2231: the catalogue reads and the resource/prompt forwards resolve an
//! account-bound backend for the caller the request established, through the
//! same sole-operator predicate `gateway_invoke` uses (#1961).
//!
//! The observable is the backend request itself: its method, the per-user slot
//! it was sent on, and the grant token it carried. A listing that omits the
//! backend sends it nothing.

use serde_json::{Value, json};

use super::direct_bridge::operator_key;
use super::{
    ALICE_WORK_TOKEN, BOB_WORK_TOKEN, Bind, Descriptors, Dispatches, SEEDED_REVISION, WORK,
    account_key, caller_as, custody_with, expected_identity_key_for, gateway_in, grant, identity,
    slots,
};
use crate::config::{ApiKeyConfig, AuthConfig, api_key_digest_spec};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::server::account_bindings::ServeMode;
use crate::protocol::RequestId;
use std::sync::Arc;

const BACKEND: &str = "work-mail";
const URI: &str = "mail://inbox";
const OPERATOR_TOKEN: &str = "synthetic-operator-work-access-5d0c11";

fn api_key(name: &str, secret: &[u8]) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(api_key_digest_spec(secret)),
        expires_at: None,
        name: name.to_string(),
        rate_limit: 0,
        backends: Vec::new(),
        allowed_tools: None,
        denied_tools: None,
        admin: false,
    }
}

/// One key and `single_user`: the deployment asserts its sole operator.
fn single_user() -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: vec![api_key("operator", b"sole-operator-key")],
        single_user: true,
        ..AuthConfig::default()
    }
}

/// Two keys are two people, whatever `single_user` claims.
fn multi_key() -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: vec![
            api_key("key-a", b"scoped-key-a"),
            api_key("key-b", b"scoped-key-b"),
        ],
        single_user: true,
        ..AuthConfig::default()
    }
}

/// The HTTP client the router hands the handlers, carrying `principal`.
fn client(principal: &str) -> AuthenticatedClient {
    AuthenticatedClient {
        name: "operator".to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        principal: principal.to_string(),
        quota_principal: None,
        authenticated: !principal.is_empty(),
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    }
}

/// The operator's per-user slot.
fn operator_slot() -> String {
    expected_identity_key_for(&operator_key(), SEEDED_REVISION)
}

/// A managed-account gateway whose sole operator (and alice and bob) hold a
/// grant, every per-user slot seeded onto the capturing transport.
fn connected(auth: AuthConfig) -> (MetaMcp, Arc<Dispatches>, super::Custody) {
    let custody = custody_with(&[
        (operator_key(), grant(OPERATOR_TOKEN, u64::MAX)),
        (
            account_key("alice", WORK),
            grant(ALICE_WORK_TOKEN, u64::MAX),
        ),
        (account_key("bob", WORK), grant(BOB_WORK_TOKEN, u64::MAX)),
    ]);
    let mut seeded = slots(&[("alice", WORK), ("bob", WORK)]);
    seeded.push(operator_slot());
    let (meta, dispatches) = gateway_in(
        &[(BACKEND, Bind::Account(WORK))],
        &Descriptors::same(&[WORK]),
        &custody.installed(),
        &seeded,
        ServeMode::Http,
        auth,
    );
    (meta, dispatches, custody)
}

/// The requests for `method` that reached the backend, as (slot, token).
fn sent(dispatches: &Dispatches, method: &str) -> Vec<(Option<String>, Option<String>)> {
    dispatches
        .all()
        .into_iter()
        .filter(|d| d.method == method)
        .map(|d| (d.identity_key.clone(), d.authorization()))
        .collect()
}

/// Exactly one `method` request, on `slot`, carrying `token`.
fn assert_sent_on(dispatches: &Dispatches, method: &str, slot: &str, token: &str) {
    let sent = sent(dispatches, method);
    assert!(
        !sent.is_empty()
            && sent.iter().all(|(key, auth)| {
                key.as_deref() == Some(slot) && auth.as_deref().is_some_and(|a| a.contains(token))
            }),
        "{method} must reach the backend on slot {slot} with the grant: {sent:?}"
    );
}

/// No request of any kind reached the operator's slot or carried its token.
fn assert_operator_untouched(dispatches: &Dispatches) {
    let slot = operator_slot();
    let leaked: Vec<_> = dispatches
        .all()
        .into_iter()
        .filter(|d| d.identity_key.as_deref() == Some(slot.as_str()))
        .map(|d| d.method)
        .collect();
    assert!(
        leaked.is_empty(),
        "the operator's slot was used: {leaked:?}"
    );
}

/// Script the owner lookup's `resources/list` so `URI` resolves to BACKEND.
fn script_resource(dispatches: &Dispatches) {
    dispatches.script(&[super::Answer::Result(
        json!({"resources": [{"uri": URI, "name": "inbox"}]}),
    )]);
}

fn read_params() -> Value {
    json!({"uri": URI})
}

fn prompt_params() -> Value {
    json!({"name": format!("{BACKEND}/summary")})
}

use crate::gateway::router::CallerStanding;

/// Run every catalogue read and forward for one HTTP caller: `principal` is
/// the credential it presented, `who` its verified identity.
async fn read_everything(
    meta: &MetaMcp,
    dispatches: &Dispatches,
    principal: &str,
    who: Option<&crate::key_server::oidc::VerifiedIdentity>,
) {
    let caller = caller_as(who, Some(principal));
    let _ = meta.list_tools(&json!({}), None, &caller).await;
    let _ = meta
        .search_tools(&json!({"query": "read"}), None, &caller)
        .await;
    let scope = client(principal);
    let id = || RequestId::Number(1);
    let _ = meta
        .handle_prompts_list(id(), None, Some(&scope), who)
        .await;
    let _ = meta
        .handle_prompts_get(id(), Some(&prompt_params()), Some(&scope), who)
        .await;
    let _ = meta
        .handle_resources_templates_list(id(), None, Some(&scope), who)
        .await;
    script_resource(dispatches);
    let _ = meta
        .handle_resources_read(
            id(),
            Some(&read_params()),
            CallerStanding::Standard,
            Some(&scope),
            who,
        )
        .await;
}

/// THE FAIL-FAST CASE. A single-user gateway's operator, no identity, sees
/// the account-bound backend in every listing and reaches it on every
/// forward, on its own slot with its own grant — as `gateway_invoke` serves it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_user_operator_reads_the_account_backend_on_its_own_slot() {
    let (meta, dispatches, _custody) = connected(single_user());
    Box::pin(read_everything(&meta, &dispatches, "operator", None)).await;
    let slot = operator_slot();
    for method in [
        "tools/list",
        "prompts/list",
        "prompts/get",
        "resources/templates/list",
        "resources/list",
        "resources/read",
    ] {
        assert_sent_on(&dispatches, method, &slot, OPERATOR_TOKEN);
    }
}

/// `resources/list` on its own (the read above also lists, as its owner lookup).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_user_operator_lists_the_account_backends_resources() {
    let (meta, dispatches, _custody) = connected(single_user());
    let scope = client("operator");
    let _ = meta
        .handle_resources_list(RequestId::Number(1), None, Some(&scope), None)
        .await;
    assert_sent_on(
        &dispatches,
        "resources/list",
        &operator_slot(),
        OPERATOR_TOKEN,
    );
}

/// An anonymous caller on the SAME operator-eligible deployment: a public
/// path's empty principal is never the operator, by listing or by name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anonymous_caller_on_a_single_user_gateway_reaches_nothing() {
    let (meta, dispatches, _custody) = connected(single_user());
    Box::pin(read_everything(&meta, &dispatches, "", None)).await;
    assert_operator_untouched(&dispatches);
    for method in ["prompts/get", "resources/read"] {
        assert!(
            sent(&dispatches, method).is_empty(),
            "{method} was forwarded"
        );
    }
}

/// Two keys are two people: neither is served the operator's grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_key_caller_reaches_nothing() {
    let (meta, dispatches, _custody) = connected(multi_key());
    Box::pin(read_everything(&meta, &dispatches, "key-b", None)).await;
    assert_operator_untouched(&dispatches);
    for method in ["prompts/get", "resources/read"] {
        assert!(
            sent(&dispatches, method).is_empty(),
            "{method} was forwarded"
        );
    }
}

/// A verified identity outranks the credential it arrived with: alice and bob
/// each read on their own slot with their own grant, never the operator's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verified_callers_keep_their_own_accounts() {
    for (subject, token) in [("alice", ALICE_WORK_TOKEN), ("bob", BOB_WORK_TOKEN)] {
        let (meta, dispatches, _custody) = connected(single_user());
        let who = identity(subject);
        Box::pin(read_everything(&meta, &dispatches, "operator", Some(&who))).await;
        let slot = expected_identity_key_for(&account_key(subject, WORK), SEEDED_REVISION);
        for method in ["prompts/list", "prompts/get", "resources/read"] {
            assert_sent_on(&dispatches, method, &slot, token);
        }
        assert_operator_untouched(&dispatches);
    }
}

/// Stdio's tools listing: the context carries the stdio principal, which
/// establishes the operator on a stdio deployment with auth off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdio_operator_lists_the_account_backends_tools() {
    let custody = custody_with(&[(operator_key(), grant(OPERATOR_TOKEN, u64::MAX))]);
    let (meta, dispatches) = gateway_in(
        &[(BACKEND, Bind::Account(WORK))],
        &Descriptors::same(&[WORK]),
        &custody.installed(),
        &[operator_slot()],
        ServeMode::Stdio,
        AuthConfig::default(),
    );
    let stdio = crate::gateway::STDIO_CREDENTIAL_PRINCIPAL;
    let _ = meta
        .list_tools(&json!({}), None, &caller_as(None, Some(stdio)))
        .await;
    assert_sent_on(&dispatches, "tools/list", &operator_slot(), OPERATOR_TOKEN);
}
