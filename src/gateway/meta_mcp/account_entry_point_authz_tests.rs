// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Personal-account authorization parity across the public meta entry points
//! (MIK-6745.JOURNEY.3).
//!
//! THE CLAIM UNDER TEST. `prompts/get`, `prompts/list` and `resources/read`
//! resolve no per-user credential — each passes `has_per_user_credential =
//! false` to the one isolation chokepoint,
//! [`MetaMcp::enforce_oauth_isolation_for`]. A backend bound to one person
//! must therefore be refused there rather than served with the gateway's
//! static credential, exactly as `tools/call` refuses it.
//!
//! THREE INDEPENDENT PERSONAL BINDINGS, enumerated from `BackendConfig`
//! (`config/mod.rs:1538`, `:1568`, `:1581`) so this is the fix and not the
//! first of several:
//!
//! * `oauth` — personal unless blessed `shared_account` (ADR-008 INV-2).
//! * `account` — an `accounts.descriptors` reference that SURVIVED binding.
//!   `config::account_bindings::Bound::effective` erases it for a `shared`
//!   and an `external` descriptor, so a surviving value is `personal_managed`.
//!   It also survives a registration rebuilt from the raw config that lost its
//!   compiled strategy, which is the state `refuse_unbound_account_backend`
//!   (`invoke.rs:2409`) refuses on the call path.
//! * `identity_propagation.required` — the compiled form of an `external`
//!   descriptor, and the hand-written form operators use directly.
//!
//! EVERY ABSENCE ASSERTION IS PAIRED WITH A PERMISSIVE CONTROL. A refusal that
//! fires for an unrelated reason — a missing backend, an unroutable transport,
//! an empty catalogue — would satisfy the absence half alone. The control
//! proves the SAME fixture is served once the gateway is single-user, so the
//! only moving part is the binding under test.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use super::MetaMcp;
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::gateway::router::CallerStanding;
use crate::protocol::{
    JsonRpcResponse, Prompt, PromptsListResult, RequestId, Resource, ResourcesListResult,
};
use crate::transport::Transport;

const PROMPT: &str = "recall";
const RESOURCE_URI: &str = "memo://isolated/note";

/// Answers every meta method a prompts/resources route can issue, and COUNTS
/// them. The count is the falsifier for "the refusal precedes the round-trip":
/// a guard that fired only after a cold-cache fetch would leak the personal
/// backend's metadata before refusing, and would still pass an assertion that
/// only inspected the response.
struct CountingTransport {
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Transport for CountingTransport {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let id = RequestId::Number(1);
        Ok(match method {
            "prompts/list" => JsonRpcResponse::success_serialized(
                id,
                PromptsListResult {
                    prompts: vec![Prompt {
                        name: PROMPT.to_string(),
                        title: None,
                        description: None,
                        arguments: Vec::new(),
                    }],
                    next_cursor: None,
                },
            ),
            "resources/list" => JsonRpcResponse::success_serialized(
                id,
                ResourcesListResult {
                    resources: vec![Resource {
                        uri: RESOURCE_URI.to_string(),
                        name: "note".to_string(),
                        title: None,
                        description: None,
                        mime_type: None,
                        size: None,
                    }],
                    next_cursor: None,
                },
            ),
            _ => JsonRpcResponse::success(id, json!({ "served": true })),
        })
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// A registered backend plus the counter its transport increments.
fn meta_with(config: BackendConfig, multi_user: bool) -> (MetaMcp, Arc<AtomicUsize>) {
    let backend = Arc::new(Backend::new(
        "isomem",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let calls = Arc::new(AtomicUsize::new(0));
    let transport: Arc<dyn Transport> = Arc::new(CountingTransport {
        calls: Arc::clone(&calls),
    });
    backend.set_transport_for_test(transport);

    let registry = Arc::new(BackendRegistry::new());
    let _ = registry.register(backend);
    let meta = MetaMcp::new(registry);
    meta.set_multi_user(multi_user);
    (meta, calls)
}

fn http_transport() -> TransportConfig {
    TransportConfig::Http {
        http_url: "https://isomem.internal/mcp".to_string(),
        streamable_http: true,
        protocol_version: None,
    }
}

/// A `personal_managed` descriptor reference as it survives
/// `account_bindings::Bound::effective` — the reference is kept AND a `Vault`
/// propagation is compiled alongside it.
fn personal_managed_backend() -> BackendConfig {
    BackendConfig {
        transport: http_transport(),
        account: Some("alice-work".to_string()),
        ..BackendConfig::default()
    }
}

/// A hand-written `identity_propagation.required` backend that names no
/// descriptor — also the compiled form of an `external` descriptor, whose
/// `account` reference is erased at binding.
fn required_propagation_backend() -> BackendConfig {
    BackendConfig {
        transport: http_transport(),
        identity_propagation: Some(
            serde_json::from_value(json!({
                "strategy": "vault",
                "audience": "https://isomem.internal/",
                "required": true,
                "session_mode": "per_user",
            }))
            .expect("required propagation config"),
        ),
        ..BackendConfig::default()
    }
}

/// What a `shared` descriptor COMPILES TO: the reference is erased and no
/// propagation is installed, so the backend is indistinguishable from an
/// ordinary statically-credentialled one. This is the escape hatch, and the
/// control that proves the guard does not refuse every backend in sight.
fn shared_descriptor_backend() -> BackendConfig {
    BackendConfig {
        transport: http_transport(),
        ..BackendConfig::default()
    }
}

fn error_message(response: &JsonRpcResponse) -> String {
    response
        .error
        .as_ref()
        .expect("the refusal must carry an error")
        .message
        .clone()
}

async fn prompts_get(meta: &MetaMcp) -> JsonRpcResponse {
    meta.handle_prompts_get(
        RequestId::Number(7),
        Some(&json!({ "name": format!("isomem/{PROMPT}") })),
    )
    .await
}

async fn resources_read(meta: &MetaMcp) -> JsonRpcResponse {
    meta.handle_resources_read(
        RequestId::Number(8),
        Some(&json!({ "uri": RESOURCE_URI })),
        CallerStanding::Admin,
    )
    .await
}

fn prompt_names(response: &JsonRpcResponse) -> Vec<String> {
    let result = response.result.as_ref().expect("prompts/list succeeds");
    result["prompts"]
        .as_array()
        .expect("prompts array")
        .iter()
        .filter_map(|p| p["name"].as_str().map(str::to_string))
        .collect()
}

#[tokio::test]
async fn prompts_get_refuses_a_personal_managed_backend_on_a_multi_user_gateway() {
    let (meta, calls) = meta_with(personal_managed_backend(), true);

    let response = prompts_get(&meta).await;

    assert!(
        response.error.is_some(),
        "a backend bound to one person's account must not serve prompts/get with the \
         gateway's static credential: {response:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the refusal must precede the backend round-trip, not follow it"
    );

    // TWIN of the required-propagation assertion below. Without this arm a
    // single generic message that never mentions propagation would satisfy both.
    let message = error_message(&response);
    assert!(
        message.contains("`mode: shared`"),
        "a descriptor binding is resolved by a shared descriptor, and the message \
         must say so: {message}"
    );
}

#[tokio::test]
async fn prompts_get_serves_the_same_backend_on_a_single_user_gateway() {
    // CONTROL. Identical fixture, one principal. Without this the refusal above
    // could be an unroutable transport or a prompt name nothing answers to.
    let (meta, calls) = meta_with(personal_managed_backend(), false);

    let response = prompts_get(&meta).await;

    assert!(
        response.error.is_none(),
        "one principal owns the account, so there is no cross-user leak to refuse: {response:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the control must actually reach the backend"
    );
}

#[tokio::test]
async fn prompts_get_refuses_a_required_propagation_backend_on_a_multi_user_gateway() {
    let (meta, calls) = meta_with(required_propagation_backend(), true);

    let response = prompts_get(&meta).await;

    assert!(
        response.error.is_some(),
        "a `required` identity-propagation backend has no static fallback that would \
         still be that person: {response:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "refusal precedes dispatch");

    // The remediation must be per-reason. Propagation is already enabled and
    // already `required` on this backend, so advising the operator to enable it
    // points at the one setting that cannot resolve the refusal.
    let message = error_message(&response);
    assert!(
        !message.contains("enabling identity propagation"),
        "the required-propagation arm must not advise enabling what is already \
         required: {message}"
    );
    assert!(
        message.contains("required propagation can never be satisfied"),
        "the operator needs the reason this route cannot carry an end-user \
         identity: {message}"
    );
}

#[tokio::test]
async fn prompts_get_serves_a_compiled_shared_descriptor_on_a_multi_user_gateway() {
    // CONTROL for over-refusal. `mode: shared` is the operator's escape hatch;
    // it compiles to no reference and no propagation, and must stay served.
    let (meta, _calls) = meta_with(shared_descriptor_backend(), true);

    let response = prompts_get(&meta).await;

    assert!(
        response.error.is_none(),
        "a shared descriptor names an account the deployment already serves statically: \
         {response:?}"
    );
}

#[tokio::test]
async fn prompts_list_omits_a_personal_managed_backend_on_a_multi_user_gateway() {
    let (meta, calls) = meta_with(personal_managed_backend(), true);

    let response = meta
        .handle_prompts_list(RequestId::Number(9), None, None)
        .await;

    assert!(
        !prompt_names(&response)
            .iter()
            .any(|name| name.starts_with("isomem/")),
        "a personal backend's prompt catalogue is itself personal data: {response:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the backend must be skipped BEFORE the cold-cache prompts/list fetch"
    );
}

#[tokio::test]
async fn prompts_list_includes_the_same_backend_on_a_single_user_gateway() {
    // CONTROL. Proves the omission above is the isolation guard and not an
    // empty catalogue or a failed fetch.
    let (meta, _calls) = meta_with(personal_managed_backend(), false);

    let response = meta
        .handle_prompts_list(RequestId::Number(10), None, None)
        .await;

    assert!(
        prompt_names(&response).contains(&format!("isomem/{PROMPT}")),
        "the single-user control must list the backend's prompt: {response:?}"
    );
}

#[tokio::test]
async fn resources_read_refuses_a_personal_managed_backend_on_a_multi_user_gateway() {
    let (meta, calls) = meta_with(personal_managed_backend(), true);

    let response = resources_read(&meta).await;

    assert!(
        response.error.is_some(),
        "resources/read resolves no per-user credential, so a personal backend's \
         resource must not be read under the static credential: {response:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "refusal precedes dispatch: a refused route must not round-trip the \
         backend's catalogue while resolving the URI's owner"
    );
}

#[tokio::test]
async fn resources_read_serves_the_same_backend_on_a_single_user_gateway() {
    // CONTROL. The URI, the owner lookup and the transport are unchanged; only
    // the principal count moves.
    let (meta, calls) = meta_with(personal_managed_backend(), false);

    let response = resources_read(&meta).await;

    assert!(
        response.error.is_none(),
        "the single-user control must read the resource: {response:?}"
    );
    assert!(
        calls.load(Ordering::SeqCst) > 0,
        "the control must actually reach the backend"
    );
}
