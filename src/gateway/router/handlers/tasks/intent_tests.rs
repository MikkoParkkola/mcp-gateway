// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `task_intent_for_call`: the three answers that are not "build a task" and
//! the caller-identity refusal that guards the durable record.

use serde_json::json;

use super::{TaskIntentRequest, task_intent_for_call};
use crate::config::AuthConfig;
use crate::gateway::router::tests::test_router_app_state_with_auth;
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
async fn auth_on_without_a_verified_identity_refuses_task_creation() {
    let state = state(true).await;
    let (args, retry) = (json!({}), keyed());
    let outcome = task_intent_for_call(&state, RequestId::Number(3), request(&args, &retry, true));
    let (code, message) = refusal(outcome).expect("a refusal");
    assert_eq!(code, -32600);
    assert_eq!(message, "task creation requires a verified caller identity");
}

#[tokio::test]
async fn auth_off_builds_a_task_for_a_keyed_call() {
    let state = state(false).await;
    let (args, retry) = (json!({}), keyed());
    let outcome = task_intent_for_call(&state, RequestId::Number(4), request(&args, &retry, true));
    assert!(matches!(outcome, Ok(Some(_))));
}
