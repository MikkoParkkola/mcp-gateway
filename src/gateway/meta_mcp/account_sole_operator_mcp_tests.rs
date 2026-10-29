// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1961: an account-bound MCP backend resolves its principal through the
//! same sole-operator predicate the REST account path uses.
//!
//! Every case goes through the real `code_mode_execute` -> `invoke_tool` entry
//! against a compiled `personal_managed` backend and REAL, EMPTY custody (no
//! grant stored). The observable is WHICH refusal the caller reaches:
//!
//! * served as the sole operator -> custody's own "no connected account"
//!   refusal, the state an operator who has not connected yet is in;
//! * not served -> the identity refusal, before any mint.
//!
//! No case may reach the backend: there is no grant to dispatch with.

use super::{Bind, Descriptors, WORK, custody_with, execute_as, external_cfg, gateway_in};
use crate::config::{ApiKeyConfig, AuthConfig, api_key_digest_spec};
use crate::gateway::STDIO_CREDENTIAL_PRINCIPAL;
use crate::gateway::server::account_bindings::ServeMode;

const BACKEND: &str = "work-mail";
const NOT_CONNECTED: &str = "no connected account";
const NO_IDENTITY: &str = "no verified end-user identity";
/// The answer to a caller with no principal on a `required` per-user
/// backend: it lacks every tool there, so its call answers as an unknown
/// name, before any resolution (MIK-8356, lead ruling 2026-10-11; design
/// R3.7). It replaces the identity refusal for that caller, which named the
/// backend.
const ABSENT: &str = "-32601";

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
        kind: crate::config::ApiKeyKind::Shared,
        ..Default::default()
    }
}

fn auth(enabled: bool, keys: Vec<ApiKeyConfig>, single_user: bool) -> AuthConfig {
    AuthConfig {
        enabled,
        api_keys: keys,
        single_user,
        ..AuthConfig::default()
    }
}

/// Run one call as `credential_principal` (no verified identity) and return
/// the refusal text and the number of backend dispatches.
async fn refusal(
    mode: ServeMode,
    auth: AuthConfig,
    credential_principal: Option<&str>,
) -> (String, usize) {
    let custody = custody_with(&[]);
    let (_log, meta, dispatches) = gateway_in(
        &[(BACKEND, Bind::Account(WORK))],
        &Descriptors::same(&[WORK]),
        &custody.installed(),
        &[],
        mode,
        auth,
    );
    let error = Box::pin(execute_as(&meta, BACKEND, credential_principal))
        .await
        .expect_err("no grant is stored; the call must be refused")
        .to_string();
    (error, dispatches.count())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdio_operator_is_served_the_account_on_an_mcp_backend() {
    let (error, dispatched) = refusal(
        ServeMode::Stdio,
        auth(false, Vec::new(), false),
        Some(STDIO_CREDENTIAL_PRINCIPAL),
    )
    .await;
    assert!(
        error.contains(NOT_CONNECTED) && !error.contains(NO_IDENTITY),
        "the stdio operator must reach custody, not the identity refusal: {error}"
    );
    assert_eq!(dispatched, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_user_http_operator_is_served_the_account_on_an_mcp_backend() {
    let (error, dispatched) = refusal(
        ServeMode::Http,
        auth(true, vec![api_key("operator", b"sole-operator-key")], true),
        Some("operator"),
    )
    .await;
    assert!(
        error.contains(NOT_CONNECTED) && !error.contains(NO_IDENTITY),
        "the single-user operator must reach custody, not the identity refusal: {error}"
    );
    assert_eq!(dispatched, 0);
}

/// The guard that must not regress: two keys are two people, whatever
/// `single_user` claims, so neither is served the stored grants.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_key_http_caller_without_identity_is_still_refused() {
    let (error, dispatched) = refusal(
        ServeMode::Http,
        auth(
            true,
            vec![
                api_key("key-a", b"scoped-key-a"),
                api_key("key-b", b"scoped-key-b"),
            ],
            true,
        ),
        Some("key-b"),
    )
    .await;
    assert!(
        error.contains(ABSENT) && !error.contains(NOT_CONNECTED),
        "a multi-key gateway must refuse before any mint: {error}"
    );
    assert_eq!(dispatched, 0);
}

/// A sole-operator deployment still refuses a caller it never authenticated.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anonymous_caller_on_a_sole_operator_deployment_is_refused() {
    let (error, dispatched) = refusal(ServeMode::Stdio, auth(false, Vec::new(), false), None).await;
    assert!(
        error.contains(ABSENT) && !error.contains(NOT_CONNECTED),
        "an unauthenticated caller must never be the sole operator: {error}"
    );
    assert_eq!(dispatched, 0);
}

/// Only a managed account consults the sole-operator assertion: a backend
/// minting through another strategy still needs a verified identity, even for
/// the operator. The backend is a `required` per-user one (identity
/// propagation gives each caller its own slot whatever its `session_mode`),
/// so a caller with no principal lacks its tools and is refused as an absent
/// name (MIK-8356, lead ruling 2026-10-11).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn operator_without_identity_is_refused_on_a_propagation_backend() {
    let custody = custody_with(&[]);
    let (_log, meta, dispatches) = gateway_in(
        &[(BACKEND, Bind::Propagation(external_cfg()))],
        &Descriptors::same(&[WORK]),
        &custody.installed(),
        &[],
        ServeMode::Stdio,
        auth(false, Vec::new(), false),
    );
    let error = Box::pin(execute_as(&meta, BACKEND, Some(STDIO_CREDENTIAL_PRINCIPAL)))
        .await
        .expect_err("a propagation backend must refuse a caller with no identity")
        .to_string();
    assert!(
        error.contains(ABSENT) && !error.contains(NOT_CONNECTED),
        "{error}"
    );
    assert_eq!(dispatches.count(), 0);
}
