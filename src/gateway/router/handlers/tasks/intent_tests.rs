// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `task_intent_for_call`: the three answers that are not "build a task" and
//! the caller-identity refusal that guards the durable record.

use serde_json::json;

use super::{TaskIntentRequest, task_intent_for_call, task_owner_key};
use crate::config::AuthConfig;
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::router::tests::test_router_app_state_with_auth;
use crate::identity_grants::GrantSubject;
use crate::protocol::RequestId;
use crate::protocol::meta::Declared;
use crate::protocol::mrtr::RetryFields;

const TOOL: &str = "gateway_invoke";

fn request<'a>(
    arguments: &'a serde_json::Value,
    retry: &'a RetryFields,
    is_modern: bool,
) -> TaskIntentRequest<'a> {
    TaskIntentRequest {
        tool_name: TOOL,
        arguments,
        is_modern,
        retry,
        verified_identity: None,
        owner: "owner-a",
        client: None,
        oauth_agent_identity: None,
        cert_identity: None,
        api_key_name: None,
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        is_admin: false,
        input_capabilities: Declared::default(),
        session_id: None,
        protocol_revision: None,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
    }
}

fn keyed() -> RetryFields {
    RetryFields {
        idempotency_key: Some("key-1".to_string()),
        ..RetryFields::default()
    }
}

async fn state(auth_enabled: bool) -> std::sync::Arc<crate::gateway::router::AppState> {
    let auth = AuthConfig {
        enabled: auth_enabled,
        ..AuthConfig::default()
    };
    test_router_app_state_with_auth(&auth).await.0
}

/// Err(code, message) of a refusal; `None` for any other outcome.
fn refusal(
    outcome: Result<
        Option<crate::gateway::task_service::TaskIntent>,
        Box<crate::protocol::JsonRpcResponse>,
    >,
) -> Option<(i32, String)> {
    let response = outcome.err()?;
    let error = response.error?;
    Some((error.code, error.message))
}

#[tokio::test]
async fn a_pre_task_revision_never_builds_a_task() {
    let state = state(false).await;
    let (args, retry) = (json!({}), keyed());
    let outcome = task_intent_for_call(&state, RequestId::Number(1), request(&args, &retry, false));
    assert!(matches!(outcome, Ok(None)));
}

#[tokio::test]
async fn a_resumed_call_is_not_a_new_task() {
    let state = state(false).await;
    let args = json!({});
    for retry in [
        RetryFields {
            request_state: Some("sealed".to_string()),
            ..keyed()
        },
        RetryFields {
            input_responses: Some(json!({})),
            ..keyed()
        },
    ] {
        let outcome =
            task_intent_for_call(&state, RequestId::Number(2), request(&args, &retry, true));
        assert!(matches!(outcome, Ok(None)));
    }
}

#[tokio::test]
async fn auth_on_with_an_empty_owner_refuses_task_creation() {
    let state = state(true).await;
    let (args, retry) = (json!({}), keyed());
    let unattributed = TaskIntentRequest {
        owner: "",
        ..request(&args, &retry, true)
    };
    let outcome = task_intent_for_call(&state, RequestId::Number(3), unattributed);
    let (code, message) = refusal(outcome).expect("a refusal");
    assert_eq!(code, -32600);
    assert_eq!(message, "task creation requires an authenticated caller");
}

/// MIK-7967: an API-key caller has no OIDC identity but does have an owner
/// (`credential:<principal>`); that owner is what the record answers to.
#[tokio::test]
async fn auth_on_with_a_credential_owner_and_no_identity_is_not_refused() {
    let state = state(true).await;
    let (args, retry) = (json!({}), keyed());
    let api_key_caller = TaskIntentRequest {
        owner: "credential:alpha",
        ..request(&args, &retry, true)
    };
    let outcome = task_intent_for_call(&state, RequestId::Number(4), api_key_caller);
    assert!(
        matches!(outcome, Ok(Some(_))),
        "an owned caller gets a task intent"
    );
}

#[tokio::test]
async fn auth_off_builds_a_task_for_a_keyed_call() {
    let state = state(false).await;
    let (args, retry) = (json!({}), keyed());
    let outcome = task_intent_for_call(&state, RequestId::Number(4), request(&args, &retry, true));
    assert!(matches!(outcome, Ok(Some(_))));
}

fn key_holder(principal: &str) -> AuthenticatedClient {
    AuthenticatedClient {
        quota_principal: None,
        name: principal.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        // MIK-6704.IDENT.1a: a synthetic fixture, not an authorization path.
        principal: principal.to_string(),
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    }
}

fn named(subject: &str) -> GrantSubject {
    GrantSubject {
        authority: "corp-sso".to_string(),
        subject: subject.to_string(),
        label: None,
    }
}

/// MIK-7967: distinct keys own apart, a proven subject splits one shared key,
/// and a subject with no credential owns nothing.
#[test]
fn task_owner_key_separates_keys_and_subjects_but_never_stands_in_for_a_key() {
    let (alpha, bravo) = (key_holder("alpha"), key_holder("bravo"));
    let (alice, bob) = (named("alice"), named("bob"));
    assert_eq!(task_owner_key(None, None, Some(&alpha)), "credential:alpha");
    assert_ne!(
        task_owner_key(None, None, Some(&alpha)),
        task_owner_key(None, None, Some(&bravo)),
        "two keys own apart"
    );
    let alices = task_owner_key(Some(&alice), None, Some(&alpha));
    assert!(alices.starts_with("subject:"), "{alices}");
    assert_ne!(
        alices,
        task_owner_key(Some(&bob), None, Some(&alpha)),
        "two subjects behind one key own apart"
    );
    assert_eq!(
        task_owner_key(Some(&alice), None, None),
        "",
        "no key, no owner"
    );
}
