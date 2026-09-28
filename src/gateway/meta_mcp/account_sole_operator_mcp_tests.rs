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

use super::account_resolver_fixture::{
    Bind, Descriptors, WORK, custody_with, execute_as, gateway_in,
};
use crate::config::{ApiKeyConfig, AuthConfig, api_key_digest_spec};
use crate::gateway::STDIO_CREDENTIAL_PRINCIPAL;
use crate::gateway::server::account_bindings::ServeMode;

const BACKEND: &str = "work-mail";
const NOT_CONNECTED: &str = "no connected account";
const NO_IDENTITY: &str = "no verified end-user identity";

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
    let (meta, dispatches) = gateway_in(
        &[(BACKEND, Bind::Account(WORK))],
        &Descriptors::same(&[WORK]),
        &custody.installed(),
        &[],
        mode,
        auth,
    );
    let error = Box::pin(execute_as(&meta, BACKEND, credential_principal))
        .await
        .err()
        .map(|error| error.to_string())
        .unwrap_or_else(|| panic!("no grant is stored; the call must be refused"));
    (error, dispatches.count())
}

#[tokio::test]
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

#[tokio::test]
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
#[tokio::test]
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
        error.contains(NO_IDENTITY) && !error.contains(NOT_CONNECTED),
        "a multi-key gateway must refuse before any mint: {error}"
    );
    assert_eq!(dispatched, 0);
}

/// A sole-operator deployment still refuses a caller it never authenticated.
#[tokio::test]
async fn anonymous_caller_on_a_sole_operator_deployment_is_refused() {
    let (error, dispatched) = refusal(ServeMode::Stdio, auth(false, Vec::new(), false), None).await;
    assert!(
        error.contains(NO_IDENTITY) && !error.contains(NOT_CONNECTED),
        "an unauthenticated caller must never be the sole operator: {error}"
    );
    assert_eq!(dispatched, 0);
}
