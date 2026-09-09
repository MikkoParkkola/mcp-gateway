// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Failing-tests leg (§P2) for release criterion `MIK-7272.TASK.1` — the
//! `io.modelcontextprotocol/tasks` extension.
//!
//! Plan: `docs/design/2026-08-31-task-1-tasks-extension.md` §8, one module per
//! acceptance-criterion row.
//!
//! Written before the implementation, so a case that fails here fails because
//! the behaviour is absent — that failure is free and real. §8's last column
//! records which rows *cannot* fail today; every such case carries a `VACUOUS`
//! comment naming what must be true before it means anything. A blocking
//! criterion that closes on a test which could not have failed is a release
//! gate removed and written down as passed.
//!
//! SCOPE CARVE-OUT: the specification's `ttlMs` / `pollIntervalMs` *MAY change
//! over the task's life* clauses are no longer an open gap — the 2026-09-06
//! amendment to §11.2 closed §10.3's two rows, and the design now owns both
//! halves: 4.0.0 never mutates either field, and every reader takes the value
//! from the store record at the moment it acts rather than caching a deadline.
//! This file still asserts neither half, and that is deliberate, not an
//! omission: both are behaviours of a store and a reaper that do not exist
//! yet, so their cases live in the test plan as rows `.14`–`.17`
//! (`docs/design/2026-09-06-task-1-tasks-extension-test-plan.md`), not here.
//! The settled half (`ttlMs: number | null` present-and-nullable,
//! `pollIntervalMs?: number`) is in scope and is asserted below.

use mcp_gateway::protocol::cacheable::is_final;
use mcp_gateway::protocol::headers::mcp_name_body_field;
use mcp_gateway::protocol::meta::ADDED_IN_2026_07_28;
use mcp_gateway::protocol::tasks::{Task, TaskStatus};
use serde_json::{Value, json};

// ===========================================================================
// MIK-7272.TASK.1.5 — a 2025-era peer calling `tasks/cancel` is refused
// -32601 by the era gate.
// ===========================================================================

#[test]
fn ac_task_1_5_tasks_cancel_is_gated_as_a_2026_07_28_method() {
    // GIVEN the list the era gate consults to refuse a removed-or-added method
    // WHEN the three task methods are looked up
    // THEN all three are members: a method missing from this list is served to
    // a 2025 peer that cannot have negotiated it.
    for method in ["tasks/get", "tasks/update", "tasks/cancel"] {
        assert!(
            ADDED_IN_2026_07_28.contains(&method),
            "'{method}' must be gated as new in 2026-07-28; the list is {ADDED_IN_2026_07_28:?}"
        );
    }
}

// ===========================================================================
// MIK-7272.TASK.1.6 — a `failed` task carries the JSON-RPC `error` object; a
// tool result with `isError: true` is `completed`, never `failed`.
// ===========================================================================

/// This case is REWRITTEN, not repaired, when `Task::error()` stops returning
/// `Option<&str>` — §3.1 mandates that signature change, so the breakage is the
/// change working rather than a regression. Asserting over the *value's* shape
/// keeps it compiling against today's type while still failing on the defect.
#[test]
fn ac_task_1_6_a_failed_task_carries_an_error_object_not_a_string() {
    let mut task = Task::create("weather.get");
    task.fail("upstream refused");

    let raw = task.error().expect("a failed task reports why it failed");
    let parsed: Option<Value> = serde_json::from_str(raw).ok();
    assert!(
        parsed
            .as_ref()
            .is_some_and(|v| v.get("code").is_some() && v.get("message").is_some()),
        "the specification requires a JSON-RPC error object with `code` and \
         `message`; a bare string cannot carry either, and got {raw:?}"
    );
}

#[test]
fn ac_task_1_6_an_is_error_tool_result_is_completed_and_not_failed() {
    // A tool that ran and reported a domain failure has *completed*. Classing
    // it as `failed` loses the result the client is owed.
    let mut task = Task::create("weather.get");
    task.complete(json!({ "isError": true, "content": [] }));

    assert_eq!(
        task.status(),
        TaskStatus::Completed,
        "an `isError: true` tool result is a completed task"
    );
    assert!(
        task.result().is_some_and(|r| r["isError"] == json!(true)),
        "the result must survive the classification: {:?}",
        task.result()
    );
    assert!(
        task.error().is_none(),
        "`error` belongs to a failed task only"
    );
}

// ===========================================================================
// MIK-7272.TASK.1.7 — `Mcp-Name` on `tasks/get|update|cancel` mirrors
// `params.taskId`.
// ===========================================================================

#[test]
fn ac_task_1_7_mcp_name_mirrors_task_id_on_the_task_methods() {
    for method in ["tasks/get", "tasks/update", "tasks/cancel"] {
        assert_eq!(
            mcp_name_body_field(method),
            Some("taskId"),
            "'{method}' carries a name to mirror, and it is `taskId`; \
             returning None lets routing act on a header the body never agreed to"
        );
    }
}

// ===========================================================================
// MIK-7272.TASK.1.2 — `tasks/get` returns the per-status shape.
// ===========================================================================

/// PARTIAL, and the missing half is stated rather than skipped: `input_required`
/// and `cancelled` are not variants of `TaskStatus` today, so a case naming them
/// would not compile — and a test file that does not compile reports no failure
/// text for any case in it. What is asserted here is the three variants that
/// exist and the shape rule that separates them.
///
/// DEFERRED: `input_required` + `inputRequests`, and `cancelled`, land with the
/// enum. Until then this case says nothing about them.
#[test]
fn ac_task_1_2_each_status_carries_its_own_payload_and_no_other() {
    let working = Task::create("weather.get");
    assert_eq!(working.status(), TaskStatus::Working);
    assert!(
        working.result().is_none() && working.error().is_none(),
        "a working task carries neither result nor error"
    );

    let mut completed = Task::create("weather.get");
    completed.complete(json!({ "content": [] }));
    assert_eq!(completed.status(), TaskStatus::Completed);
    assert!(
        completed.result().is_some() && completed.error().is_none(),
        "a completed task carries `result` and no `error`"
    );

    let mut failed = Task::create("weather.get");
    failed.fail("upstream refused");
    assert_eq!(failed.status(), TaskStatus::Failed);
    assert!(
        failed.error().is_some() && failed.result().is_none(),
        "a failed task carries `error` and no `result`"
    );
}

// ===========================================================================
// MIK-7272.TASK.1.8 — a retried identical task-augmented call returns the same
// `taskId` and runs the backend once; the `CreateTaskResult` is never cached
// and never marked idempotency-completed.
// ===========================================================================

/// The guard half, and it is falsifiable against existing code: `is_final`
/// decides what may be written to the response cache and replayed. A
/// `CreateTaskResult` is a handle to work still running — replaying one returns
/// the *request* rather than the answer, and the call can never finish.
///
/// GREEN TODAY on purpose: this is the regression guard for the finality rule,
/// not a new behaviour. It goes red the moment `resultType: "task"` is treated
/// as a finished answer.
#[test]
fn ac_task_1_8_a_task_creation_result_is_never_a_final_answer() {
    let create_task_result = json!({
        "resultType": "task",
        "taskId": "task-2a4c1e60-0b1f-4a0e-9a1a-1f2b3c4d5e6f",
        "status": "working",
        "createdAt": "2026-09-06T10:00:00Z",
        "lastUpdatedAt": "2026-09-06T10:00:00Z",
        "ttlMs": null
    });
    assert!(
        !is_final(&create_task_result),
        "a task handle must never be cached or marked idempotency-completed"
    );

    // The contrast that makes the assertion mean something: the *answer* is.
    assert!(
        is_final(&json!({ "resultType": "complete", "content": [] })),
        "the completed result is what may be cached"
    );
}

// NOT COVERED HERE, and stated rather than skipped: the same-`taskId` half of
// `.8`. The dedupe key is `(authenticated principal, client idempotency key)`,
// so it needs a task store that can return the same id twice and a mock backend
// carrying a mutation counter — neither exists. Asserting it against a
// hand-built value would be a fixture making its own assertion true, which is
// the failure mode this file is written against.
//
// It becomes assertable when a task-augmented `tools/call` dispatches: the
// counter is 1 across two calls carrying the SAME key, both responses carry the
// same `taskId`, and two calls carrying DIFFERENT keys are two tasks and two
// backend runs. Never assert the body of the response cache — it is written at
// `invoke.rs:1291`, after the backend result, so a fixture that leaves caching
// enabled passes vacuously.

// ===========================================================================
// MIK-7272.TASK.1.10 — the served capabilities advertise
// `extensions["io.modelcontextprotocol/tasks"] = {}` on `server/discover`.
//
// NARROWED to discovery, team-lead ruling 2026-09-07, provisional pending the
// operator. The criterion as written also asked for `initialize`, and that half
// is unreachable by construction rather than descoped: `SUPPORTED_VERSIONS`
// (`src/protocol/mod.rs`) deliberately omits `2026-07-28` because the 2026
// lifecycle removed the handshake, so the only clients that reach `initialize`
// are 2025-era ones this extension is not for. Paying for it means changing an
// `initialize` result that MIK-7272.DISCOVER.3 pins byte-for-byte, to advertise
// something no client that can read it may use. The argument is recorded here so
// the ruling can be overruled without archaeology.
// ===========================================================================

mod capabilities {
    use std::sync::Arc;

    use mcp_gateway::backend::BackendRegistry;
    use mcp_gateway::gateway::test_helpers::MetaMcp;
    use mcp_gateway::protocol::RequestId;
    use mcp_gateway::protocol::extensions::ExtensionSet;
    use mcp_gateway::protocol::meta::{Era, classify_and_observe};
    use serde_json::{Value, json};

    const TASKS: &str = "io.modelcontextprotocol/tasks";

    fn meta() -> MetaMcp {
        MetaMcp::new(Arc::new(BackendRegistry::new()))
    }

    /// `initialize` serves the extension to a peer that declared the 2026 era.
    ///
    /// Inverted on 2026-09-07. It previously asserted that `initialize` stays
    /// silent, which was the narrowing the release standing ruling refused:
    /// the criterion is built, not scoped down to `server/discover`. What it
    /// asserts now is the built mechanism.
    ///
    /// The declaration is in `_meta`, which is what `classify_request` reads,
    /// and the era is threaded from the dispatcher. That last clause is a claim
    /// about a seam this test would otherwise stub past, so it is asserted
    /// rather than described: the era handed to `handle_initialize` is the era
    /// `classify_and_observe` derives from these exact params. Without it both
    /// era arms stay green while the dispatcher reclassifies underneath them,
    /// and `initialize` silently serves the wrong era.
    #[test]
    fn ac_task_1_10_initialize_advertises_the_tasks_extension_to_a_2026_peer() {
        let params = json!({
            "protocolVersion": "2026-07-28",
            "clientInfo": { "name": "ExampleClient", "version": "1.0.0" },
            "capabilities": {},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {
                    "extensions": { TASKS: {} }
                }
            }
        });
        assert_eq!(
            classify_and_observe("initialize", Some(&params), None, None).era(),
            Era::Modern,
            "the dispatcher must derive Modern from the very params this test \
             hands to `handle_initialize`"
        );

        let response =
            meta().handle_initialize(RequestId::Number(1), Some(&params), None, None, Era::Modern);
        let result = response.result.unwrap_or(Value::Null);

        assert_eq!(
            result.pointer(&format!(
                "/capabilities/extensions/{}",
                TASKS.replace('/', "~1")
            )),
            Some(&json!({})),
            "a peer that declared 2026 reaches `tasks/*` and must be told the \
             extension is served: {result}"
        );
    }

    /// The other half of the conditional, and the one that keeps `DISCOVER.3`.
    ///
    /// A peer that declares no era is refused `tasks/get`, `tasks/update` and
    /// `tasks/cancel` with -32601 by `ADDED_IN_2026_07_28`. Advertising the
    /// extension to it would claim a capability the gateway actively refuses
    /// that audience — a protocol-correctness objection, not a scope
    /// preference. The absence is asserted as an absent KEY, not an empty
    /// object: an always-present `"extensions": {}` is itself the handshake
    /// change `DISCOVER.3` pins against.
    #[test]
    fn ac_task_1_10_initialize_stays_silent_for_a_peer_that_declared_no_era() {
        let params = json!({
            "protocolVersion": "2025-11-25",
            "clientInfo": { "name": "ExampleClient", "version": "1.0.0" },
            "capabilities": {}
        });
        assert_eq!(
            classify_and_observe("initialize", Some(&params), None, None).era(),
            Era::Legacy,
            "the dispatcher must derive Legacy from the very params this test \
             hands to `handle_initialize`"
        );

        let response =
            meta().handle_initialize(RequestId::Number(1), Some(&params), None, None, Era::Legacy);
        let result = response.result.unwrap_or(Value::Null);

        assert_eq!(
            result.pointer("/capabilities/extensions"),
            None,
            "a 2025 peer's handshake is pinned byte-for-byte by DISCOVER.3 and \
             must carry no extensions key at all: {result}"
        );
    }

    #[test]
    fn ac_task_1_10_the_discovery_document_advertises_the_tasks_extension() {
        let document = meta().discover_document(true);

        assert_eq!(
            document.pointer(&format!(
                "/capabilities/extensions/{}",
                TASKS.replace('/', "~1")
            )),
            Some(&json!({})),
            "`server/discover` is the 2026 surface, and the only place a peer \
             that can use this extension looks for it: {document}"
        );

        // The unit test in `src/protocol/extensions.rs` pins `to_extensions`
        // against the parser that reads it back. This pins the SERVED document
        // against `to_extensions`. Neither edge implies the other: the document
        // could hand-roll the same key today and drift the moment the
        // declaration gains a second extension, with both existing cases green.
        // Equality, not containment -- a superset is exactly the drift.
        assert_eq!(
            document.pointer("/capabilities/extensions"),
            Some(&serde_json::to_value(ExtensionSet::gateway_declares().to_extensions()).unwrap()),
            "the served `extensions` object IS what the declaration produces, \
             not merely an object containing the tasks key: {document}"
        );
    }
}

// ===========================================================================
// The rows that are only observable over the wire. A criterion about what a
// *client* receives is not settled by a helper's return value.
// ===========================================================================

mod http {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use mcp_gateway::backend::BackendRegistry;
    use mcp_gateway::config::{ApiKeyConfig, AuthConfig, Config};
    use mcp_gateway::gateway::auth::ResolvedAuthConfig;
    use mcp_gateway::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
    use mcp_gateway::gateway::proxy::ProxyManager;
    use mcp_gateway::gateway::streaming::NotificationMultiplexer;
    use mcp_gateway::gateway::test_helpers::{AppState, MetaMcp, create_router};
    use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
    use mcp_gateway::protocol::headers::mcp_name_body_field;
    use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    pub(super) const TASKS: &str = "io.modelcontextprotocol/tasks";

    /// Two API keys, so "a different principal" is a fact of the fixture rather
    /// than a wish. With auth disabled every caller is the same principal and
    /// the ownership rows would pass by construction — a fixture that removes
    /// the condition it observes.
    fn two_principal_auth() -> AuthConfig {
        let key = |k: &str, name: &str| ApiKeyConfig {
            key: k.to_string(),
            name: name.to_string(),
            rate_limit: 0,
            backends: Vec::new(),
            allowed_tools: None,
            denied_tools: None,
            admin: false,
        };
        AuthConfig {
            enabled: true,
            bearer_token: None,
            api_keys: vec![key("key-a", "principal-a"), key("key-b", "principal-b")],
            public_paths: Vec::new(),
            client_circuit_breaker: None,
            single_user: false,
        }
    }

    pub(super) fn state() -> Arc<AppState> {
        state_from(two_principal_auth())
    }

    /// The shape in which an unauthenticated caller REACHES `/mcp`:
    /// authentication is on, and `/mcp` is listed public so ordinary tools stay
    /// open. Without the public listing the middleware answers 401 and no task
    /// code runs, so a case built on `state()` cannot observe what an
    /// unattributed caller can do.
    ///
    /// No shipped configuration writes it: `gateway.example.yaml`, the helm
    /// configmap and the k8s configmap all list `/health` alone. What keeps the
    /// scenario startable — and the guard below off the dead-code pile — is
    /// `network_bind_refusal`, which returns `None` for a loopback bind with no
    /// declared `server.public_url` (`src/gateway/server/support.rs:554`), the
    /// shape `Config::default()` gives this fixture. The same answer for a
    /// loopback install that lists `/mcp` public is pinned at
    /// `src/gateway/server/support.rs:979-986`. Only a NON-loopback
    /// `public_url` turns this shape into a refusal.
    pub(super) fn public_mcp_auth() -> AuthConfig {
        let mut auth = two_principal_auth();
        auth.public_paths = vec!["/mcp".to_string()];
        auth
    }

    pub(super) fn state_public_mcp() -> Arc<AppState> {
        state_from(public_mcp_auth())
    }

    pub(super) fn state_from(auth: AuthConfig) -> Arc<AppState> {
        let mut config = Config::default();
        config.server.modern_protocol = true;
        config.auth = auth;
        let backends = Arc::new(BackendRegistry::new());
        let multiplexer = Arc::new(NotificationMultiplexer::new(
            Arc::clone(&backends),
            config.streaming.clone(),
        ));
        let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
        Arc::new(AppState {
            session_lifecycle: None,
            continuation: Arc::new(mcp_gateway::protocol::continuation::ContinuationState::new()),
            env: None,
            meta_mcp: Arc::new(MetaMcp::new(Arc::clone(&backends))),
            backends,
            meta_mcp_enabled: true,
            multiplexer,
            proxy_manager,
            streaming_config: config.streaming.clone(),
            auth_config: Arc::new(ResolvedAuthConfig::from_config(&config.auth)),
            key_server: None,
            tool_policy: Arc::new(ToolPolicy::from_config(&ToolPolicyConfig::default())),
            mtls_policy: Arc::new(MtlsPolicy::from_config(&MtlsConfig::default())),
            sanitize_input: false,
            ssrf_protection: false,
            trust_configured_backends: false,
            inflight: Arc::new(tokio::sync::Semaphore::new(100)),
            agent_auth: AgentAuthState::new(false, Arc::new(AgentRegistry::new())),
            gateway_key_pair: Arc::new(GatewayKeyPair::generate().expect("RSA key gen")),
            capability_dirs: Vec::new(),
            config_path: None,
            #[cfg(feature = "firewall")]
            firewall: None,
            agent_identity_config: mcp_gateway::config::AgentIdentityConfig::default(),
            control_plane_store: None,
            live_config: Arc::new(mcp_gateway::config_reload::LiveConfig::new(config.clone())),
            export_status: None,
            transparency_log: None,
            dashboard_bootstrap: Arc::new(mcp_gateway::gateway::auth::DashboardBootstrap::new()),
            tasks: Arc::new(mcp_gateway::protocol::task_store::TaskStore::new()),
            subscriptions: Arc::new(
                mcp_gateway::gateway::subscription_registry::SubscriptionRegistry::new(64),
            ),
        })
    }

    /// A modern request. `declares_tasks` is per request on purpose: the whole
    /// point of `.4` and `.13` is that a declaration on an earlier request
    /// carries nothing forward.
    pub(super) fn modern(id: i64, method: &str, params: Value, declares_tasks: bool) -> Value {
        let mut params = params;
        params["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": if declares_tasks {
                json!({ "extensions": { TASKS: {} } })
            } else {
                json!({})
            },
            "io.modelcontextprotocol/clientInfo": { "name": "ExampleClient", "version": "1.0.0" }
        });
        json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
    }

    /// POST to `/mcp` as `principal`, returning status and body.
    ///
    /// The `Mcp-Name` mirror is derived from `mcp_name_body_field` — the
    /// production rule — so these requests keep sending what the gateway
    /// requires once `.7` lands. That is not circular: `.7` asserts the rule
    /// directly as a unit case, and nothing here asserts the header.
    pub(super) async fn post(principal: &str, body: Value) -> (StatusCode, Value) {
        post_against(state(), principal, body).await
    }

    pub(super) async fn post_against(
        state: Arc<AppState>,
        principal: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        post_as(state, Some(principal), body).await
    }

    /// A request carrying NO credential. Only reaches the handlers when `/mcp`
    /// is public — see [`state_public_mcp`].
    pub(super) async fn post_unattributed(
        state: Arc<AppState>,
        body: Value,
    ) -> (StatusCode, Value) {
        post_as(state, None, body).await
    }

    pub(super) async fn post_as(
        state: Arc<AppState>,
        principal: Option<&str>,
        body: Value,
    ) -> (StatusCode, Value) {
        let method = body["method"].as_str().unwrap_or_default().to_string();
        let mut builder = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", &method);
        if let Some(principal) = principal {
            builder = builder.header("authorization", format!("Bearer {principal}"));
        }
        if let Some(field) = mcp_name_body_field(&method)
            && let Some(name) = body
                .pointer(&format!("/params/{field}"))
                .and_then(Value::as_str)
        {
            builder = builder.header("mcp-name", name);
        }
        let request = builder
            .body(Body::from(serde_json::to_vec(&body).expect("body")))
            .expect("request");
        let response = create_router(state)
            .oneshot(request)
            .await
            .expect("router must answer");
        let status = response.status();
        // An admitted `subscriptions/listen` is an OPEN STREAM by design, so
        // draining its body never returns. Content-type is what separates the
        // two answers: a refusal is `application/json` and must be read and
        // compared; a stream is `text/event-stream` and has no body to collect.
        let streaming = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/event-stream"));
        if streaming {
            return (status, Value::Null);
        }
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body must read");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
}

mod wire {
    use axum::http::StatusCode;
    use serde_json::json;

    use super::http::{TASKS, modern, post};

    const TASK_ID: &str = "task-2a4c1e60-0b1f-4a0e-9a1a-1f2b3c4d5e6f";

    // =======================================================================
    // MIK-7272.TASK.1.4 — a client that does not declare the extension ON THAT
    // REQUEST never receives a `CreateTaskResult`, and is refused -32021.
    // =======================================================================

    /// The row that catches a stub: a dispatcher returning tasks
    /// unconditionally passes `.1` and fails this.
    #[tokio::test]
    async fn ac_task_1_4_a_declaration_on_an_earlier_request_carries_nothing_forward() {
        // GIVEN request 1 declares the extension
        let (_, first) = post(
            "key-a",
            modern(
                1,
                "tools/call",
                json!({ "name": "gateway_list_servers" }),
                true,
            ),
        )
        .await;
        assert!(
            first.get("error").is_none(),
            "the declaring call is served: {first}"
        );

        // WHEN request 2 omits the declaration and asks for a task anyway
        let (status, body) = post(
            "key-a",
            modern(
                2,
                "tools/call",
                json!({ "name": "gateway_list_servers", "task": {} }),
                false,
            ),
        )
        .await;

        // THEN it is refused, and never answered with a task handle.
        assert_ne!(
            body.pointer("/result/resultType"),
            Some(&json!("task")),
            "a client that did not declare on this request must not receive a \
             task handle: {body}"
        );
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], -32021, "{body}");
        assert_eq!(
            body.pointer(&format!(
                "/error/data/requiredCapabilities/extensions/{}",
                TASKS.replace('/', "~1")
            )),
            Some(&json!({})),
            "the refusal must name the extension the client failed to declare: {body}"
        );
    }

    // =======================================================================
    // MIK-7272.TASK.1.13 — the gate is per REQUEST, not per method family.
    // =======================================================================

    /// Written separately from `.4` because a gate implemented per *method
    /// family* passes `.4` and fails this: `subscriptions/listen` is not in the
    /// `tasks/*` family and reaches the extension anyway.
    #[tokio::test]
    async fn ac_task_1_13_an_undeclared_subscription_carrying_task_ids_is_refused() {
        let (status, body) = post(
            "key-a",
            modern(
                3,
                "subscriptions/listen",
                json!({ "taskIds": [TASK_ID] }),
                false,
            ),
        )
        .await;

        assert_eq!(body["error"]["code"], -32021, "{body}");
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(
            body.pointer(&format!(
                "/error/data/requiredCapabilities/extensions/{}",
                TASKS.replace('/', "~1")
            )),
            Some(&json!({})),
            "the same payload `.4` asserts, on the subscription path: {body}"
        );
    }
}

mod dispatch {
    use serde_json::{Value, json};

    use super::http::{modern, post, post_against, state};

    const FABRICATED_ID: &str = "task-00000000-0000-4000-8000-000000000000";

    /// A task-augmented call, declared. The tool is a meta-tool so the case does
    /// not need a backend fixture that could answer for the gateway.
    fn task_call(id: i64) -> Value {
        modern(
            id,
            "tools/call",
            json!({ "name": "gateway_list_servers", "task": {} }),
            true,
        )
    }

    // =======================================================================
    // MIK-7272.TASK.1.1 — a task-augmented call returns `CreateTaskResult` with
    // `resultType: "task"` and a `taskId` that `tasks/get` already resolves.
    // =======================================================================

    /// VACUOUS AS A CONSTRAINT, red today only because no dispatcher exists:
    /// any stub that returns a task handle passes it. `.4` is the row that
    /// catches such a stub, and `.11` the row that catches one with no ownership
    /// check. Kept because the round-trip — the created id resolves immediately,
    /// before any status change — is the criterion's own wording.
    #[tokio::test]
    async fn ac_task_1_1_a_created_task_id_resolves_immediately() {
        let state = state();
        let (_, created) = post_against(state.clone(), "key-a", task_call(10)).await;

        assert_eq!(
            created.pointer("/result/resultType"),
            Some(&json!("task")),
            "a declared task-augmented call is answered with a task handle: {created}"
        );
        let task_id = created
            .pointer("/result/taskId")
            .and_then(Value::as_str)
            .expect("a task handle carries its id")
            .to_string();

        let (_, fetched) = post_against(
            state,
            "key-a",
            modern(11, "tasks/get", json!({ "taskId": task_id.clone() }), true),
        )
        .await;
        assert_eq!(
            fetched.pointer("/result/taskId"),
            Some(&json!(task_id)),
            "the id the creator was handed resolves before any status change: {fetched}"
        );
    }

    // =======================================================================
    // MIK-7272.TASK.1.3 — `tasks/update` is accepted, refuses an
    // `inputResponses` key matching no outstanding input request, and
    // acknowledges with an empty `resultType: "complete"`.
    // =======================================================================

    /// VACUOUS until `tasks/update` is dispatched: nothing routes the method, so
    /// today the refusal arrives from the method gate rather than from the key
    /// check. It means something once an update reaches the store.
    ///
    /// CARVE-OUT (§11.6): nothing here asserts what an update does to `ttlMs` or
    /// `pollIntervalMs`. The specification's MAY-change clauses for both fields
    /// are unstated in §3 and open; a case pinning either behaviour would pin an
    /// unresolved design question.
    #[tokio::test]
    async fn ac_task_1_3_an_input_response_with_no_outstanding_request_is_refused() {
        // `input_required` is out of scope for TASK.1, so there are never
        // outstanding keys and any non-empty map is refused.
        let (_, body) = post(
            "key-a",
            modern(
                12,
                "tasks/update",
                json!({ "taskId": FABRICATED_ID, "inputResponses": { "prompt-1": "yes" } }),
                true,
            ),
        )
        .await;
        assert!(
            body.get("error").is_some(),
            "an input response matching no outstanding request is refused: {body}"
        );
    }

    /// VACUOUS with the case above, and for the same reason.
    #[tokio::test]
    async fn ac_task_1_3_an_accepted_update_acknowledges_with_an_empty_result() {
        let state = state();
        let (_, created) = post_against(state.clone(), "key-a", task_call(13)).await;
        let task_id = created
            .pointer("/result/taskId")
            .and_then(Value::as_str)
            .unwrap_or(FABRICATED_ID)
            .to_string();

        let (_, body) = post_against(
            state,
            "key-a",
            modern(14, "tasks/update", json!({ "taskId": task_id }), true),
        )
        .await;
        assert_eq!(
            body.pointer("/result/resultType"),
            Some(&json!("complete")),
            "the acknowledgement is an empty `complete` result: {body}"
        );
        // `_meta` is excluded because it is the gateway's envelope, not the
        // ack's payload: `handlers.rs` stamps `serverInfo` into every result it
        // serves, so a count including it could never be 1 and the case could
        // never go green. What the criterion is about is that the ack carries
        // NO payload of its own.
        let payload_keys: Vec<&str> = body["result"]
            .as_object()
            .expect("the ack is an object")
            .keys()
            .map(String::as_str)
            .filter(|key| *key != "_meta")
            .collect();
        assert_eq!(
            payload_keys,
            ["resultType"],
            "empty means empty: the ack carries `resultType` and nothing else: {body}"
        );
    }
}

mod ownership {
    use serde_json::{Value, json};

    use super::http::{
        modern, post_against, post_unattributed, public_mcp_auth, state, state_from,
        state_public_mcp,
    };

    const FABRICATED_ID: &str = "task-11111111-1111-4111-8111-111111111111";
    /// Stands in for A's task id while no dispatcher hands one out, so the
    /// byte-identity comparison still RUNS — and runs against a different id
    /// than `FABRICATED_ID`, never against itself. See each case's vacuity note.
    const UNDISPATCHED_ID: &str = "task-22222222-2222-4222-8222-222222222222";

    /// The gateway's answer with the request id blanked, so two answers to two
    /// different task ids can be compared for byte-identity. Blanking only what
    /// MUST differ is the point: anything else that differs is the disclosure
    /// the criterion forbids.
    fn shape(mut body: Value) -> String {
        if let Some(obj) = body.as_object_mut() {
            obj.insert("id".into(), json!(0));
        }
        body.to_string()
    }

    fn task_call(id: i64) -> Value {
        modern(
            id,
            "tools/call",
            json!({ "name": "gateway_list_servers", "task": {} }),
            true,
        )
    }

    // =======================================================================
    // MIK-7272.TASK.1.11 — a retrieval naming another principal's task is
    // answered as not-found, identically to an id that never existed.
    // =======================================================================

    /// VACUOUS UNTIL THE DISPATCHER EXISTS: with no `tasks/get` arm, both calls
    /// get the same method-level refusal and the comparison holds for the wrong
    /// reason. It means something only once `tasks/get` answers a real id — the
    /// case then goes red the moment the ownership check is missing or answers
    /// differently. It is deliberately NOT guarded by an `expect` on the created
    /// id: a panic in setup would report "no dispatcher" a fourth time and never
    /// run the byte-identity comparison, which is the assertion that carries the
    /// criterion. The fallback id stands in until `tools/call` hands out a real
    /// one, so this case is GREEN today — green for the reason stated here.
    #[tokio::test]
    async fn ac_task_1_11_another_principals_task_is_indistinguishable_from_no_task() {
        let state = state();
        let (_, created) = post_against(state.clone(), "key-a", task_call(20)).await;
        let task_id = created
            .pointer("/result/taskId")
            .and_then(Value::as_str)
            .unwrap_or(UNDISPATCHED_ID)
            .to_string();

        let (_, foreign) = post_against(
            state.clone(),
            "key-b",
            modern(21, "tasks/get", json!({ "taskId": task_id }), true),
        )
        .await;
        let (_, absent) = post_against(
            state,
            "key-b",
            modern(22, "tasks/get", json!({ "taskId": FABRICATED_ID }), true),
        )
        .await;

        assert_eq!(
            shape(foreign),
            shape(absent),
            "B's view of A's task is byte-identical to B's view of an id that never existed"
        );
    }

    // =======================================================================
    // MIK-7272.TASK.1.12 — subscription admission enforces the same ownership
    // check, and refuses indistinguishably from an id that never existed.
    // =======================================================================

    /// VACUOUS UNTIL BOTH TASK.1 AND SUB.2 LAND — and this is the row the design
    /// singles out for it. Nothing admits a subscription today, so both answers
    /// are the same refusal for the wrong reason. What must be true before it
    /// means anything: `subscriptions/listen` must actually admit a stream for a
    /// `taskId` its caller owns. Until then a green here is not coverage, and
    /// closing `.12` on it would be a release gate removed and written down as
    /// passed. The owner-admission assertion below is that guard, stated as an
    /// assertion rather than a comment so it cannot quietly stop being true.
    #[tokio::test]
    async fn ac_task_1_12_subscription_admission_hides_another_principals_task() {
        let state = state();
        let (_, created) = post_against(state.clone(), "key-a", task_call(23)).await;
        let task_id = created
            .pointer("/result/taskId")
            .and_then(Value::as_str)
            .unwrap_or(UNDISPATCHED_ID)
            .to_string();

        let (_, admitted) = post_against(
            state.clone(),
            "key-a",
            modern(
                24,
                "subscriptions/listen",
                json!({ "taskIds": [task_id.clone()] }),
                true,
            ),
        )
        .await;
        assert!(
            admitted.get("error").is_none(),
            "the owner is admitted — without this the comparison below is vacuous: {admitted}"
        );

        let (_, foreign) = post_against(
            state.clone(),
            "key-b",
            modern(
                25,
                "subscriptions/listen",
                json!({ "taskIds": [task_id] }),
                true,
            ),
        )
        .await;
        let (_, absent) = post_against(
            state,
            "key-b",
            modern(
                26,
                "subscriptions/listen",
                json!({ "taskIds": [FABRICATED_ID] }),
                true,
            ),
        )
        .await;
        assert_eq!(
            shape(foreign),
            shape(absent),
            "listening on another principal's task is byte-identical to listening on a fabricated id"
        );
    }

    // =======================================================================
    // MIK-7272.TASK.1.9 — a `subscriptions/listen` carrying `taskIds` emits
    // `notifications/tasks` and no `notifications/progress` or `.../message`.
    // =======================================================================

    /// VACUOUS UNTIL BOTH TASK.1 AND SUB.2 LAND: nothing emits task
    /// notifications, so an empty stream satisfies the negative half of the
    /// criterion trivially. What must be true first: a listen on a task the
    /// caller owns must be admitted AND the task must emit at least one
    /// `notifications/tasks`. Only the admission half is asserted here —
    /// asserting the emission today would name a notification the gateway has
    /// no producer for, which fails as an absent name rather than a defect.
    #[tokio::test]
    async fn ac_task_1_9_a_task_subscription_is_admitted_for_its_owner() {
        let state = state();
        let (_, created) = post_against(state.clone(), "key-a", task_call(27)).await;
        let task_id = created
            .pointer("/result/taskId")
            .and_then(Value::as_str)
            .unwrap_or(UNDISPATCHED_ID)
            .to_string();

        let (_, listened) = post_against(
            state,
            "key-a",
            modern(
                28,
                "subscriptions/listen",
                json!({ "taskIds": [task_id] }),
                true,
            ),
        )
        .await;
        assert!(
            listened.get("error").is_none(),
            "a `subscriptions/listen` carrying `taskIds` is admitted for the owner: {listened}"
        );
    }

    // =======================================================================
    // MIK-7272.TASK.1.18 — a caller that presented no credential owns no task,
    // and is told so in the same words as an id that never existed.
    // =======================================================================

    /// `session_owner_key` returns the empty string for a caller with no
    /// credential, and `TaskStore` compares principals by plain equality — so
    /// every unattributed caller answers to the same owner key and they own
    /// each other's tasks. The gateway states the opposite rule in that
    /// function's own doc comment ("Empty ... is not an identity, and the
    /// controls that key on this refuse rather than pool every anonymous caller
    /// into one bucket"), and the firewall arm honours it. Only the task arms
    /// pool.
    ///
    /// The credentialled half of this case is the vacuity guard: it proves the
    /// fixture can tell a retrieved task from a not-found answer, so the
    /// byte-identity assertion below is a real comparison and not two refusals
    /// agreeing for an unrelated reason.
    #[tokio::test]
    async fn ac_task_1_18_an_unattributed_caller_owns_no_task() {
        let state = state_public_mcp();

        let (_, created) = post_against(state.clone(), "key-a", task_call(30)).await;
        let owned_id = created
            .pointer("/result/taskId")
            .and_then(Value::as_str)
            .unwrap_or(UNDISPATCHED_ID)
            .to_string();
        let (_, owner_view) = post_against(
            state.clone(),
            "key-a",
            modern(31, "tasks/get", json!({ "taskId": owned_id.clone() }), true),
        )
        .await;
        let (_, owner_absent) = post_against(
            state.clone(),
            "key-a",
            modern(32, "tasks/get", json!({ "taskId": FABRICATED_ID }), true),
        )
        .await;
        assert_ne!(
            shape(owner_view),
            shape(owner_absent),
            "a credentialled owner must see its own task differently from one \
             that never existed — without this the comparison below is vacuous"
        );

        let (_, unattributed_created) = post_unattributed(state.clone(), task_call(33)).await;
        let pooled_id = unattributed_created
            .pointer("/result/taskId")
            .and_then(Value::as_str)
            .unwrap_or(UNDISPATCHED_ID)
            .to_string();
        assert_eq!(
            unattributed_created
                .pointer("/error/message")
                .and_then(Value::as_str),
            Some("no such task"),
            "the unattributed dispatch must be refused BY THE ROUTER, in the \
             id-free wording of `missing_task_error` — a middleware refusal \
             short of the router would answer 401 to everything below and make \
             the comparison vacuous: {unattributed_created}"
        );
        let (_, second_caller) = post_unattributed(
            state.clone(),
            modern(34, "tasks/get", json!({ "taskId": pooled_id }), true),
        )
        .await;
        let (_, never_existed) = post_unattributed(
            state,
            modern(35, "tasks/get", json!({ "taskId": FABRICATED_ID }), true),
        )
        .await;

        assert_eq!(
            shape(second_caller),
            shape(never_existed),
            "a task another unattributed caller dispatched is indistinguishable \
             from an id that never existed: an empty principal is not an identity"
        );
    }

    // =======================================================================
    // MIK-7272.TASK.1.19 — the subscription path is EXCLUDED from the refusal:
    // an unattributed listen is answered, never told that the id resolves.
    // =======================================================================

    /// The stream is the one arm that must not refuse. `subscriptions/listen`
    /// naming a task nobody may see returns a quiet stream, exactly as it does
    /// for a task owned by another principal — an error here would tell the
    /// caller that the id resolves to something.
    ///
    /// FORWARD GUARD, and stated as one: this case is green with the
    /// `2c522f53` production hunk reverted, because before that commit no arm
    /// refused at all. It cannot catch a regression of the fix; it fires when
    /// someone LATER widens the refusal over `subscriptions/listen` — the one
    /// change that would turn silence into disclosure. The other half of the
    /// criterion, that the caller is silently narrowed to no ids, has NO
    /// observable surface to assert against: `ListenRequest::from_params`
    /// (`src/protocol/subscriptions.rs:100`) reads only `params.notifications`
    /// and never `taskIds`, so the narrowing at `handlers.rs:1015` reaches no
    /// consumer. Assertable once task notifications become a
    /// `NotificationKind` — that is `MIK-7272.TASK.1.12`'s work, not this
    /// case's.
    #[tokio::test]
    async fn ac_task_1_19_unattributed_subscription_is_quiet_not_refused() {
        let state = state_public_mcp();
        let (_, created) = post_against(state.clone(), "key-a", task_call(36)).await;
        let owned_id = created
            .pointer("/result/taskId")
            .and_then(Value::as_str)
            .unwrap_or(UNDISPATCHED_ID)
            .to_string();

        let (_, listened) = post_unattributed(
            state,
            modern(
                37,
                "subscriptions/listen",
                json!({ "taskIds": [owned_id] }),
                true,
            ),
        )
        .await;

        assert!(
            listened.get("error").is_none(),
            "an unattributed subscription is narrowed in silence, never refused: {listened}"
        );
    }

    // =======================================================================
    // MIK-7272.TASK.1.20 — with authentication DISABLED the pool is the
    // operator's own configuration, and the refusal deliberately does not fire.
    // =======================================================================

    /// `.18` refuses the credential-less caller because, where the operator
    /// declared distinct principals, the empty owner key pooled callers who
    /// were supposed to be kept apart. The predicate therefore reads
    /// `owner.is_empty() && auth_config.enabled` — it does not ask "did this
    /// request carry a credential", it asks "did the operator draw a boundary
    /// here at all". With authentication off there is none to enforce:
    /// `anonymous_client` makes one shared caller the operator's stated choice,
    /// and an unconditional refusal would take tasks away from every
    /// single-user gateway to protect a line nobody drew.
    ///
    /// Both halves are ONE assertion and neither works alone: the same
    /// unattributed dispatch, refused and then admitted under configurations
    /// that differ in `enabled` AND NOTHING ELSE. Both come from
    /// `public_mcp_auth()`, because the earlier spelling admitted under
    /// `AuthConfig::default()`, which also drops the two API keys and the
    /// public `/mcp` listing — a guard keyed on key-count or on the public
    /// path would have kept the pair green while `enabled` did no work.
    /// The admission half on its own passes just as well against a guard
    /// someone deleted outright, and the refusal half is already `.18` — only
    /// the pair can fail for the right reason.
    ///
    /// The admission is asserted POSITIVELY — answered, with a result — not as
    /// "some message other than `no such task`". A method-not-found, a
    /// capability miss or a tool error all satisfy the negation while the
    /// caller reaches nothing, so the negation passes on a broken gateway.
    /// It cannot yet assert a task HANDLE: `tools/call` returns no
    /// `result/taskId` until the store lands (`.8a`), and a case pinned to a
    /// field nothing writes is a case that can never go green.
    #[tokio::test]
    async fn ac_task_1_20_auth_disabled_admits_the_unattributed_caller() {
        let (_, refused) = post_unattributed(state_public_mcp(), task_call(40)).await;
        assert_eq!(
            refused.pointer("/error/message").and_then(Value::as_str),
            Some("no such task"),
            "control: with auth ENABLED the same call must still be refused, or \
             the contrast below says nothing about the predicate: {refused}"
        );

        let mut disabled = public_mcp_auth();
        disabled.enabled = false;
        let (_, admitted) = post_unattributed(state_from(disabled), task_call(41)).await;
        assert!(
            admitted.get("error").is_none() && admitted.get("result").is_some(),
            "with auth DISABLED there are no principals to keep apart, so the \
             credential-less caller reaches the dispatcher like every other \
             caller on that gateway and is ANSWERED: {admitted}"
        );
    }

    // =======================================================================
    // MIK-7272.TASK.1 — the clause with no code behind it: the tool RUNS, and
    // the handle resolves to what it produced.
    //
    // Designed in `docs/design/2026-08-31-task-1-tasks-extension.md` §3.
    // Every case below compares the settled record against the SAME call made
    // without `task`, so what it asserts is "the task path answers what the
    // ordinary path answers" rather than a result shape this file invented.
    // A fixture that hard-codes the answer passes against a dispatcher that
    // fabricates it.
    // =======================================================================

    /// Poll a handle until it leaves `working`.
    ///
    /// The dispatch runs on its own task, so a settled status arrives
    /// eventually rather than immediately. A bounded poll rather than one
    /// sleep: a fixed sleep either flakes on a loaded machine or spends the
    /// wall clock on every green run, and when it does fail it reports a
    /// timeout instead of the last answer the gateway actually gave.
    async fn poll_until_settled(
        state: std::sync::Arc<mcp_gateway::gateway::test_helpers::AppState>,
        key: &str,
        task_id: &str,
    ) -> Value {
        for attempt in 0..200_i64 {
            let (_, body) = post_against(
                state.clone(),
                key,
                modern(
                    9000 + attempt,
                    "tasks/get",
                    json!({ "taskId": task_id }),
                    true,
                ),
            )
            .await;
            if body.pointer("/result/status") != Some(&json!("working")) {
                return body;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("the handle {task_id} never left `working`");
    }

    /// The `taskId` a creation response handed back.
    fn handle_of(created: &Value) -> String {
        created
            .pointer("/result/taskId")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("a task handle carries its id: {created}"))
            .to_string()
    }

    /// A call made the ordinary way, to establish what the task path owes.
    fn plain_call(id: i64, params: Value) -> Value {
        modern(id, "tools/call", params, true)
    }

    /// The tool actually runs, and the handle resolves to its result.
    ///
    /// LIMIT, stated rather than left for a reviewer to find: this does not
    /// prove the backend call runs CONCURRENTLY with the response. That needs
    /// a backend the test can hold at a barrier and release after the poll,
    /// and the harness has no such backend. Recorded as a gap.
    #[tokio::test]
    async fn ac_task_1_a_task_augmented_call_runs_its_tool() {
        let state = state();
        let (_, direct) = post_against(
            state.clone(),
            "key-a",
            plain_call(50, json!({ "name": "gateway_list_servers" })),
        )
        .await;
        let expected = direct
            .get("result")
            .cloned()
            .unwrap_or_else(|| panic!("control: the ordinary call answers with a result: {direct}"));

        let (_, created) = post_against(state.clone(), "key-a", task_call(51)).await;
        assert_eq!(
            created.pointer("/result/status"),
            Some(&json!("working")),
            "the handle is returned before the tool has finished: {created}"
        );
        assert!(
            created.pointer("/result/result").is_none(),
            "a handle carries no result yet — a creation response that already \
             had one would mean the call was awaited, not dispatched: {created}"
        );

        let settled = poll_until_settled(state, "key-a", &handle_of(&created)).await;
        assert_eq!(
            settled.pointer("/result/status"),
            Some(&json!("completed")),
            "the dispatched call settles its record: {settled}"
        );
        assert_eq!(
            settled.pointer("/result/result"),
            Some(&expected),
            "the handle resolves to what the tool produced, byte for byte the \
             answer the ordinary call gave: {settled}"
        );
    }

    /// A dispatch that answers with a JSON-RPC error settles the task
    /// `failed`, carrying that error's OWN code.
    ///
    /// The expected code is read off the ordinary call rather than written
    /// here: a literal would pass against a settle that flattens every failure
    /// to `-32603` if the two ever coincided, and would need editing every
    /// time the refusal is reworded.
    #[tokio::test]
    async fn ac_task_1_a_failing_dispatch_settles_failed_with_its_own_code() {
        let state = state();
        let unknown = json!({ "name": "no_such_tool_anywhere" });
        let (_, direct) = post_against(state.clone(), "key-a", plain_call(60, unknown.clone())).await;
        let expected_code = direct
            .pointer("/error/code")
            .cloned()
            .unwrap_or_else(|| panic!("control: the ordinary call is refused: {direct}"));

        let mut params = unknown;
        params["task"] = json!({});
        let (_, created) = post_against(state.clone(), "key-a", plain_call(61, params)).await;
        let settled = poll_until_settled(state, "key-a", &handle_of(&created)).await;

        assert_eq!(
            settled.pointer("/result/status"),
            Some(&json!("failed")),
            "a dispatch that produced no result failed, and says so rather \
             than polling `working` forever: {settled}"
        );
        assert_eq!(
            settled.pointer("/result/error/code"),
            Some(&expected_code),
            "the failure carries the refusal's own code, not a blanket \
             internal error: {settled}"
        );
    }

    /// `isError: true` is a COMPLETED task.
    ///
    /// `isError` is a field of a successful `tools/call` result, so the task
    /// produced a final answer and that answer says the tool failed. `failed`
    /// is for a task that produced no final result at all. The existing `.6`
    /// case asserts this in-process; this one asserts it on the wire, which is
    /// where the settle rule actually lives.
    #[tokio::test]
    async fn ac_task_1_6_an_is_error_result_still_completes_on_the_wire() {
        let state = state();
        let invoke = json!({
            "name": "gateway_invoke",
            "arguments": { "server": "no-such-server", "tool": "read", "arguments": {} }
        });
        let (_, direct) = post_against(state.clone(), "key-a", plain_call(70, invoke.clone())).await;
        assert_eq!(
            direct.pointer("/result/isError"),
            Some(&json!(true)),
            "control: a missing backend comes back as a RESULT carrying an \
             isError envelope, which is the premise this case rests on: {direct}"
        );

        let mut params = invoke;
        params["task"] = json!({});
        let (_, created) = post_against(state.clone(), "key-a", plain_call(71, params)).await;
        let settled = poll_until_settled(state, "key-a", &handle_of(&created)).await;

        assert_eq!(
            settled.pointer("/result/status"),
            Some(&json!("completed")),
            "a final result is a completion even when it reports a tool error: {settled}"
        );
        assert_eq!(
            settled.pointer("/result/result/isError"),
            Some(&json!(true)),
            "and the error the tool reported survives into the record: {settled}"
        );
    }

    /// A gate that refuses still refuses when the call asks for a task.
    ///
    /// The assertion that the relocated `create` is strictly safer than the
    /// one at `handlers.rs:1196`, rather than merely later: today a
    /// task-augmented call returns a handle BEFORE the admin pre-check runs,
    /// so appending `"task": {}` converts a refusal into a `200` and a record
    /// an unauthorized caller allocated.
    #[tokio::test]
    async fn ac_task_1_a_refused_call_is_refused_not_handed_a_handle() {
        let state = state();
        let admin_tool = json!({ "name": "gateway_reload_config", "task": {} });
        let (_, body) = post_against(state, "key-a", plain_call(80, admin_tool)).await;

        assert!(
            body.get("error").is_some(),
            "a non-admin caller is refused an admin tool whether or not the \
             call asks for a task: {body}"
        );
        assert!(
            body.pointer("/result/taskId").is_none(),
            "and is handed no handle, so no record exists for it to poll: {body}"
        );
    }
}
