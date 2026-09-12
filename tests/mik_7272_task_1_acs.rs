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
//!
//! FIXTURE NOTE (2026-09-08): every row that needs a REAL task now dispatches
//! `gateway_invoke` at the counted backend in [`fixture`], carrying an
//! idempotency key and a verified identity. It used to name
//! `gateway_list_servers`, which is a governed built-in the gateway answers
//! synchronously in I1 — a task-augmented call naming it is answered
//! `complete` and creates no task, so those rows were asserting against a
//! handle that never existed and falling back to a fabricated id. The
//! correction is on the fixture side only: no authorization rule is weakened,
//! no built-in is relabelled, and every assertion below is the one that was
//! there before.

#[path = "mik_7272_task_1_acs/fixture.rs"]
mod fixture;

use mcp_gateway::protocol::JsonRpcError;
use mcp_gateway::protocol::cacheable::is_final;
use mcp_gateway::protocol::headers::mcp_name_body_field;
use mcp_gateway::protocol::meta::ADDED_IN_2026_07_28;
use mcp_gateway::protocol::tasks::{Task, TaskStatus};
use serde_json::json;

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

/// The canonical model carries a typed JSON-RPC error; its serialized payload
/// must preserve the backend code, message and optional data as an object.
#[test]
fn ac_task_1_6_a_failed_task_carries_an_error_object_not_a_string() {
    let mut task = Task::create("weather.get");
    task.fail(JsonRpcError {
        code: -32001,
        message: "upstream refused".to_string(),
        data: Some(json!({ "reason": "backend-policy" })),
    });

    let error = task.error().expect("a failed task reports why it failed");
    let encoded = serde_json::to_value(error).expect("the task error serializes");
    assert_eq!(
        encoded,
        json!({
            "code": -32001,
            "message": "upstream refused",
            "data": { "reason": "backend-policy" }
        }),
        "a failed task preserves the full JSON-RPC error object, never an encoded string"
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

/// The working/completed/failed payload rules remain covered here. The
/// canonical five-status model's input-required and cancelled transitions and
/// payload projection are covered by `protocol/tasks/lifecycle_tests.rs` and
/// `protocol/tasks/snapshot_tests.rs`; this case makes no real-route claim.
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
    failed.fail(JsonRpcError {
        code: -32001,
        message: "upstream refused".to_string(),
        data: None,
    });
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
// and the counted-backend fixture below now supplies both halves the row needs
// — a real key on every create and a per-fixture `tools/call` counter. What it
// does NOT supply is the row's own home: the retry pair lives in the router's
// `task_execution_adapter` suite, which owns the adapter's dispatch-once
// claim. Asserting it here against a hand-built value would still be a fixture
// making its own assertion true, which is the failure mode this file is
// written against.
//
// It is assertable there as: the counter is 1 across two calls carrying the
// SAME key, both responses carry the same `taskId`, and two calls carrying
// DIFFERENT keys are two tasks and two backend runs. Never assert the body of
// the response cache — it is written at `invoke.rs:1291`, after the backend
// result, so a fixture that leaves caching enabled passes vacuously.

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
    use mcp_gateway::gateway::subscription_registry::SubscriptionRegistry;
    use mcp_gateway::gateway::test_helpers::{
        AppState, MetaMcp, StoreLimits, create_router, open_runtime,
    };
    use mcp_gateway::key_server::oidc::VerifiedIdentity;
    use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
    use mcp_gateway::protocol::headers::mcp_name_body_field;
    use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use crate::fixture::{self, CountedBackend, GateHandle, ServerGuard};

    pub(super) const TASKS: &str = "io.modelcontextprotocol/tasks";

    /// Where a task-augmented call carries its idempotency key
    /// (`crate::protocol::mrtr::IDEMPOTENCY_KEY_META` in the gateway, spelled
    /// out here because an integration test cannot name a private constant —
    /// the internal adapter suite's `support.rs` spells the same string for the
    /// same reason).
    pub(super) const IDEMPOTENCY_KEY_META: &str = "io.mcp-gateway/idempotency-key";

    /// Two API keys, so "a different principal" is a fact of the fixture rather
    /// than a wish. With auth disabled every caller is the same principal and
    /// the ownership rows would pass by construction — a fixture that removes
    /// the condition it observes.
    ///
    /// `backends` names [`fixture::BACKEND`] rather than being empty: an empty
    /// list is "every backend", and a credential that may reach anything cannot
    /// show that a task-producing call was authorized on its own merits. The
    /// scope is narrow and it is real — the same middleware that reads it on a
    /// production request reads it here.
    fn two_principal_auth() -> AuthConfig {
        let key = |k: &str, name: &str| ApiKeyConfig {
            key: k.to_string(),
            name: name.to_string(),
            rate_limit: 0,
            backends: vec![fixture::BACKEND.to_string()],
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

    /// Everything one test's gateway owns, held together for the test's whole
    /// life.
    ///
    /// The `TempDir` is a FIELD rather than a returned tuple element so it
    /// cannot be dropped by a destructuring `let` that only wanted the state:
    /// the task store leases that directory for as long as the service lives,
    /// and a store whose directory has been removed underneath it fails in ways
    /// that read as task defects. Bind the whole `Fixture`; never take it
    /// apart.
    ///
    /// `backend` is the per-fixture counter. Per fixture, never static, so two
    /// tests in one binary cannot read each other's dispatch count.
    ///
    /// `_server` is the fixture's own loopback HTTP listener, held for the same
    /// reason and dropped with the same `Fixture`: the registered backend
    /// reaches it over a real socket, so a guard dropped early turns every
    /// later dispatch into a connection error. It is deliberately NOT stored on
    /// `AppState` — the state would then own the server that serves the state,
    /// a cycle that keeps both alive past the test.
    pub(super) struct Fixture {
        pub(super) state: Arc<AppState>,
        pub(super) backend: Arc<CountedBackend>,
        _server: ServerGuard,
        _store_dir: tempfile::TempDir,
    }

    /// The suite's standard gateway: authentication on, two principals, one
    /// counted eligible backend that answers immediately.
    pub(super) async fn state() -> Fixture {
        state_from(two_principal_auth()).await
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

    pub(super) async fn state_public_mcp() -> Fixture {
        state_from(public_mcp_auth()).await
    }

    /// The standard gateway, but its backend HOLDS every dispatch until the
    /// returned handle releases it.
    ///
    /// For the one row that must observe a task while it is genuinely running.
    /// A backend that answers immediately races the executor there: the task
    /// can settle between the create and the update, and the row would then be
    /// reporting on a terminal task while claiming to report on a working one.
    /// The gate replaces that race with a barrier — no sleep, and no clock.
    pub(super) async fn state_holding() -> (Fixture, GateHandle) {
        let (backend, gate) = CountedBackend::holding();
        (state_from_with(two_principal_auth(), backend).await, gate)
    }

    pub(super) async fn state_from(auth: AuthConfig) -> Fixture {
        state_from_with(auth, CountedBackend::open()).await
    }

    pub(super) async fn state_from_with(auth: AuthConfig, backend: Arc<CountedBackend>) -> Fixture {
        let mut config = Config::default();
        config.server.modern_protocol = true;
        config.auth = auth;
        let backends = Arc::new(BackendRegistry::new());
        let multiplexer = Arc::new(NotificationMultiplexer::new(
            Arc::clone(&backends),
            config.streaming.clone(),
        ));
        let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));

        // One registry, shared between the state the router reads and the
        // executor that publishes through it.
        let subscriptions = Arc::new(SubscriptionRegistry::new(64));
        let store_dir = tempfile::tempdir().expect("a private task-store directory");
        let (tasks, task_executor) = open_runtime(
            &store_dir.path().join("tasks"),
            config.tasks.max_workers,
            StoreLimits::default(),
            Arc::clone(&subscriptions),
        )
        .await
        .expect("the fixture task store opens");

        let state = Arc::new(AppState {
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
            session_lifecycle: Arc::new(mcp_gateway::gateway::session_lifecycle::SessionLifecycle::new()),
            dashboard_bootstrap: Arc::new(mcp_gateway::gateway::auth::DashboardBootstrap::new()),
            tasks,
            task_executor,
            subscriptions,
        });
        // Registered AFTER the state exists and BEFORE any request runs, so
        // every row sees the same gateway a production caller would: a real
        // backend behind a real transport, reachable only by a credential
        // scoped to it.
        let server = fixture::register(&state, &backend).await;
        Fixture {
            state,
            backend,
            _server: server,
            _store_dir: store_dir,
        }
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

    /// Add the client idempotency key to an already-built modern request.
    ///
    /// The dedupe key is `(authenticated principal, client idempotency key)`, so
    /// a create that carries none is not a logical request the gateway can
    /// recognise on retry. Logical retries share a key; distinct creates carry
    /// distinct ones, which is why every call site below names its own row.
    pub(super) fn keyed(mut body: Value, key: &str) -> Value {
        body["params"]["_meta"][IDEMPOTENCY_KEY_META] = json!(key);
        body
    }

    /// A task-augmented `gateway_invoke` at the counted backend, keyed.
    ///
    /// `gateway_invoke` selecting a registered backend and one of its declared
    /// tools, rather than a governed built-in wearing a `task` member: the
    /// built-ins are answered synchronously in I1 and correctly so, and a
    /// fixture that relabelled one to get a task handle would be asserting
    /// against a route the gateway does not have. No target hint is inherited
    /// and none is set — the tool is read-only and non-destructive as declared,
    /// so nothing here borrows a destructive-authorization decision.
    pub(super) fn task_invoke(id: i64, key: &str) -> Value {
        keyed(
            modern(
                id,
                "tools/call",
                json!({
                    "name": "gateway_invoke",
                    "arguments": {
                        "server": fixture::BACKEND,
                        "tool": fixture::TOOL,
                        "arguments": {}
                    },
                    "task": {}
                }),
                true,
            ),
            key,
        )
    }

    /// The `taskId` a create was answered with, or a failure naming the whole
    /// body.
    ///
    /// Deliberately a panic and not a fallback id. A fallback let an ownership
    /// row compare two unrelated refusals and report agreement — the create had
    /// silently produced no task at all, and the row passed on a gateway that
    /// never made one.
    pub(super) fn task_id_of(created: &Value) -> String {
        created
            .pointer("/result/taskId")
            .and_then(Value::as_str)
            .unwrap_or_else(|| {
                panic!(
                    "a declared task-augmented call must be answered with a task handle: {created}"
                )
            })
            .to_string()
    }

    /// POST to `/mcp` as `principal`, returning status and body.
    ///
    /// The `Mcp-Name` mirror is derived from `mcp_name_body_field` — the
    /// production rule — so these requests keep sending what the gateway
    /// requires once `.7` lands. That is not circular: `.7` asserts the rule
    /// directly as a unit case, and nothing here asserts the header.
    pub(super) async fn post(principal: &str, body: Value) -> (StatusCode, Value) {
        // Bound until this helper returns, which is after the response body has
        // been read: the store's directory outlives the request made on it.
        let fixture = state().await;
        post_against(Arc::clone(&fixture.state), principal, body).await
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
    ///
    /// It carries no [`VerifiedIdentity`] either, and that is the point: an
    /// unattributed caller is unattributed in BOTH schemes, so no row can pass
    /// by reading the one that happens to suit it.
    pub(super) async fn post_unattributed(
        state: Arc<AppState>,
        body: Value,
    ) -> (StatusCode, Value) {
        post_as(state, None, body).await
    }

    /// Poll `tasks/get` as an unattributed caller until the task it names is
    /// TERMINAL, and return that answer.
    ///
    /// A bounded barrier, not a delay. Nothing sleeps: each turn is a real
    /// request over the real router, and the loop ends the moment the store
    /// reports a terminal status. The bound is [`fixture::BOUND`] — the suite's
    /// one outer bound, shared with the counted backend's waits rather than
    /// respelled — so a task that is created and then never settled FAILS its
    /// row finitely instead of hanging the binary.
    ///
    /// Each poll carries its own JSON-RPC id, counted up from `id_from`: a
    /// stateless client correlates answers to requests by id, and reusing one
    /// would make two answers indistinguishable.
    pub(super) async fn poll_unattributed_until_terminal(
        state: Arc<AppState>,
        id_from: i64,
        task_id: &str,
    ) -> Value {
        let mut last = Value::Null;
        tokio::time::timeout(fixture::BOUND, async {
            let mut request_id = id_from;
            loop {
                let (_, body) = post_unattributed(
                    Arc::clone(&state),
                    modern(request_id, "tasks/get", json!({ "taskId": task_id }), true),
                )
                .await;
                request_id += 1;
                if let Some("completed" | "failed" | "cancelled") =
                    body.pointer("/result/status").and_then(Value::as_str)
                {
                    return body;
                }
                last = body;
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "'{task_id}' never reached a terminal status within {:?}; \
                 the task was created and never settled: {last}",
                fixture::BOUND
            )
        })
    }

    /// The OIDC subject that belongs to each credential.
    ///
    /// Two distinct subjects from one issuer, matching the internal adapter
    /// suite's convention: `principal-a`/`alice` name the same caller in both
    /// schemes and `principal-b`/`bob` differ in both, so the strong actor id
    /// and the API key can never disagree about who is calling.
    fn verified_subject(principal: &str) -> Option<&'static str> {
        match principal {
            "key-a" => Some("alice"),
            "key-b" => Some("bob"),
            _ => None,
        }
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
        let mut request = builder
            .body(Body::from(serde_json::to_vec(&body).expect("body")))
            .expect("request");
        // The strong verified owner the design names. Placed in request
        // extensions, which is the ONLY way one ever arrives: the two
        // middleware sites that insert it both sit behind a key server this
        // in-process router has none of. The credential beside it is real — the
        // bearer above goes through the actual auth middleware, and the API-key
        // scope stays in force. Nothing here fabricates a digest, and nothing
        // widens what a caller may reach.
        if let Some(principal) = principal
            && let Some(subject) = verified_subject(principal)
        {
            request.extensions_mut().insert(VerifiedIdentity {
                subject: subject.to_string(),
                email: format!("{subject}@task-1.test"),
                name: None,
                groups: Vec::new(),
                issuer: "https://idp.task-1.test".to_string(),
            });
        }
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
    ///
    /// Keeps the built-in on purpose. What it observes is the CAPABILITY GATE,
    /// which fires before eligibility is ever consulted, so a created task is
    /// not a precondition here and a fixture backend would add a moving part
    /// the row does not need.
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
    ///
    /// The id it names never existed, which is the point: the gate must refuse
    /// before anything looks the id up, so no created task is a precondition.
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
    use std::sync::Arc;

    use serde_json::json;

    use super::http::{modern, post, post_against, state, state_holding, task_id_of, task_invoke};

    /// An id nothing ever created. A negative control, and it stays one.
    const FABRICATED_ID: &str = "task-00000000-0000-4000-8000-000000000000";

    // =======================================================================
    // MIK-7272.TASK.1.1 — a task-augmented call returns `CreateTaskResult` with
    // `resultType: "task"` and a `taskId` that `tasks/get` already resolves.
    // =======================================================================

    /// The round trip the criterion words: the created id resolves immediately,
    /// before any status change.
    ///
    /// It used to be VACUOUS AS A CONSTRAINT — any stub returning a handle
    /// passed it — and it is still `.4` that catches a stub and `.11` that
    /// catches a missing ownership check. What has changed is that the call is
    /// now eligible to BECOME a task, so the handle is a real durable UUID and
    /// the backend really ran: the dispatch count below is the half that a
    /// hand-built handle could never satisfy.
    #[tokio::test]
    async fn ac_task_1_1_a_created_task_id_resolves_immediately() {
        let fixture = state().await;
        let (_, created) = post_against(
            Arc::clone(&fixture.state),
            "key-a",
            task_invoke(10, "mik-7272-task-1-1-create"),
        )
        .await;

        assert_eq!(
            created.pointer("/result/resultType"),
            Some(&json!("task")),
            "a declared task-augmented call is answered with a task handle: {created}"
        );
        let task_id = task_id_of(&created);

        // The dispatch is spawned, so the count becomes observable only once
        // the worker has run: bounded by scheduler turns, never by a clock. The
        // equality is what matters — one create is one backend run.
        fixture.backend.wait_for_calls(1).await;

        let (_, fetched) = post_against(
            Arc::clone(&fixture.state),
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

    /// The refusal half. It names an id nothing created, which is deliberate:
    /// the rule under test is that an input response matching no outstanding
    /// request is refused, and there is no configuration of this gateway in
    /// which one is outstanding.
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

    /// The acceptance half, on a task that is genuinely RUNNING.
    ///
    /// The held backend is what makes that true. With a backend that answers
    /// immediately the task can settle between the create and the update, and
    /// the row would then be reporting on an update to a terminal task while
    /// claiming to report on an accepted one — a difference no assertion here
    /// could see. `wait_for_dispatch` is a barrier at the seam, not a delay:
    /// it returns when the dispatch has actually reached the backend and is
    /// being held there.
    #[tokio::test]
    async fn ac_task_1_3_an_accepted_update_acknowledges_with_an_empty_result() {
        let (fixture, mut gate) = state_holding().await;
        let (_, created) = post_against(
            Arc::clone(&fixture.state),
            "key-a",
            task_invoke(13, "mik-7272-task-1-3-create"),
        )
        .await;
        let task_id = task_id_of(&created);
        gate.wait_for_dispatch().await;

        let (_, body) = post_against(
            Arc::clone(&fixture.state),
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

        // An update is not a dispatch: the one held call is still the only one.
        assert_eq!(
            fixture.backend.calls(),
            1,
            "an accepted `tasks/update` must not run the tool a second time"
        );
        gate.release_all();
    }
}

mod ownership {
    use std::sync::Arc;

    use serde_json::{Value, json};

    use super::http::{
        modern, poll_unattributed_until_terminal, post_against, post_unattributed, public_mcp_auth,
        state, state_from, state_public_mcp, task_id_of, task_invoke,
    };

    /// An id nothing ever created: the negative control every "indistinguishable
    /// from no task" comparison is made against, and still a control.
    const FABRICATED_ID: &str = "task-11111111-1111-4111-8111-111111111111";
    /// A SECOND id nothing ever created, used only where a create is expected to
    /// be REFUSED and there is therefore no real id to name. Distinct from
    /// `FABRICATED_ID` so the byte-identity comparison is never run against
    /// itself. It is no longer a fallback for a create that was supposed to
    /// succeed: those now panic instead, so an ownership row can never pass on
    /// two unrelated refusals agreeing.
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

    // =======================================================================
    // MIK-7272.TASK.1.11 — a retrieval naming another principal's task is
    // answered as not-found, identically to an id that never existed.
    // =======================================================================

    /// A's task is real: the create is asserted, not hoped for. That is what
    /// makes the byte-identity comparison a comparison — B is answered about an
    /// id that DOES resolve for someone, and about one that resolves for
    /// nobody, and the two answers must be the same.
    ///
    /// The dispatch count is the ownership control. A create runs the backend
    /// once; two retrievals by a principal who owns nothing must run it zero
    /// more times. A gateway that dispatched on read would leak the task's
    /// existence through the backend even while answering not-found.
    #[tokio::test]
    async fn ac_task_1_11_another_principals_task_is_indistinguishable_from_no_task() {
        let fixture = state().await;
        let (_, created) = post_against(
            Arc::clone(&fixture.state),
            "key-a",
            task_invoke(20, "mik-7272-task-1-11-create"),
        )
        .await;
        let task_id = task_id_of(&created);
        fixture.backend.wait_for_calls(1).await;

        let (_, foreign) = post_against(
            Arc::clone(&fixture.state),
            "key-b",
            modern(21, "tasks/get", json!({ "taskId": task_id }), true),
        )
        .await;
        let (_, absent) = post_against(
            Arc::clone(&fixture.state),
            "key-b",
            modern(22, "tasks/get", json!({ "taskId": FABRICATED_ID }), true),
        )
        .await;

        assert_eq!(
            shape(foreign),
            shape(absent),
            "B's view of A's task is byte-identical to B's view of an id that never existed"
        );
        assert_eq!(
            fixture.backend.calls(),
            1,
            "a retrieval dispatches nothing: the only backend run is A's create"
        );
    }

    // =======================================================================
    // MIK-7272.TASK.1.12 — subscription admission enforces the same ownership
    // check, and refuses indistinguishably from an id that never existed.
    // =======================================================================

    /// VACUOUS UNTIL SUB.2 LANDS in one specific respect, and this is the row
    /// the design singles out for it: what must be true before the comparison
    /// carries the criterion is that `subscriptions/listen` really admits a
    /// stream for a `taskId` its caller owns. That half is now an assertion
    /// rather than a comment — and the task it names is a real durable one, so
    /// the admission is admission of something. Until the stream carries task
    /// notifications, a green here is coverage of the ownership check only, and
    /// closing `.12` on more than that would be a release gate removed and
    /// written down as passed.
    #[tokio::test]
    async fn ac_task_1_12_subscription_admission_hides_another_principals_task() {
        let fixture = state().await;
        let (_, created) = post_against(
            Arc::clone(&fixture.state),
            "key-a",
            task_invoke(23, "mik-7272-task-1-12-create"),
        )
        .await;
        let task_id = task_id_of(&created);

        let (_, admitted) = post_against(
            Arc::clone(&fixture.state),
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
            Arc::clone(&fixture.state),
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
            Arc::clone(&fixture.state),
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

    /// VACUOUS IN ITS NEGATIVE HALF UNTIL SUB.2 LANDS: nothing emits task
    /// notifications, so an empty stream satisfies "and no progress or message"
    /// trivially. What IS asserted is the half that can be: a listen naming a
    /// task the caller really owns is admitted. Asserting the emission today
    /// would name a notification the gateway has no producer for, which fails
    /// as an absent name rather than as a defect.
    #[tokio::test]
    async fn ac_task_1_9_a_task_subscription_is_admitted_for_its_owner() {
        let fixture = state().await;
        let (_, created) = post_against(
            Arc::clone(&fixture.state),
            "key-a",
            task_invoke(27, "mik-7272-task-1-9-create"),
        )
        .await;
        let task_id = task_id_of(&created);

        let (_, listened) = post_against(
            Arc::clone(&fixture.state),
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
    /// agreeing for an unrelated reason. That guard only works on a task that
    /// exists, which is why the create here is asserted rather than fallen back
    /// from — it was the fallback that let this row report agreement between
    /// two answers about nothing.
    #[tokio::test]
    async fn ac_task_1_18_an_unattributed_caller_owns_no_task() {
        let fixture = state_public_mcp().await;

        let (_, created) = post_against(
            Arc::clone(&fixture.state),
            "key-a",
            task_invoke(30, "mik-7272-task-1-18-create"),
        )
        .await;
        let owned_id = task_id_of(&created);
        fixture.backend.wait_for_calls(1).await;
        let (_, owner_view) = post_against(
            Arc::clone(&fixture.state),
            "key-a",
            modern(31, "tasks/get", json!({ "taskId": owned_id.clone() }), true),
        )
        .await;
        let (_, owner_absent) = post_against(
            Arc::clone(&fixture.state),
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

        let (_, unattributed_created) = post_unattributed(
            Arc::clone(&fixture.state),
            task_invoke(33, "mik-7272-task-1-18-unattributed"),
        )
        .await;
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
        assert_eq!(
            fixture.backend.calls(),
            1,
            "the refused unattributed create must reach no backend: the only \
             dispatch is the credentialled one above"
        );
        // That refusal is the point, so there is no pooled id to name: the
        // unattributed caller was handed nothing. The comparison below is
        // therefore between an id no unattributed caller could have been given
        // and one that never existed, which is exactly what "an empty principal
        // is not an identity" means. Its vacuity guard is the credentialled
        // half above, on a task that really does resolve.
        let pooled_id = UNDISPATCHED_ID;
        let (_, second_caller) = post_unattributed(
            Arc::clone(&fixture.state),
            modern(34, "tasks/get", json!({ "taskId": pooled_id }), true),
        )
        .await;
        let (_, never_existed) = post_unattributed(
            Arc::clone(&fixture.state),
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
    /// caller that the id resolves to something. The id it names now really
    /// does resolve, for A, which is what gives the silence something to hide.
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
        let fixture = state_public_mcp().await;
        let (_, created) = post_against(
            Arc::clone(&fixture.state),
            "key-a",
            task_invoke(36, "mik-7272-task-1-19-create"),
        )
        .await;
        let owned_id = task_id_of(&created);

        let (_, listened) = post_unattributed(
            Arc::clone(&fixture.state),
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
    /// the pair can fail for the right reason. The call is the same
    /// `task_invoke` in both halves for the same reason: a difference in the
    /// request would be a second variable, and the pair would stop being about
    /// `enabled`.
    ///
    /// The admission is asserted POSITIVELY — answered, with a REAL handle —
    /// not as "some message other than `no such task`". A method-not-found, a
    /// capability miss or a tool error all satisfy the negation while the
    /// caller reaches nothing, so the negation passes on a broken gateway. It
    /// used to stop at "answered", which was one assertion short of the
    /// criterion: "the credential-less caller reaches the dispatcher" is a
    /// claim about a task being CREATED, and an answer carrying no handle, or a
    /// handle behind which nothing runs, satisfies "answered" while the caller
    /// still reaches nothing. So the admitted half now goes the whole way — a
    /// real `taskId` (never a fabricated fallback: `task_id_of` panics), a real
    /// backend run counted exactly once, the same handle for a second
    /// unattributed request and for a same-key retry, and a real terminal
    /// outcome polled under the suite's one bound. None of that is `.1`'s claim
    /// borrowed: `.1` observes a CREDENTIALLED create, and every line here
    /// fails for this row's own predicate, on the gateway `enabled` decides.
    ///
    /// Both halves post the SAME `Value` — one `task_invoke`, cloned, down to
    /// the idempotency key — which is what retires the "a difference in the
    /// request would be a second variable" caveat rather than merely stating
    /// it. The two gateways hold separate stores and separate admission
    /// indexes, so one key across both is one request asked of two
    /// configurations, never a retry.
    #[tokio::test]
    async fn ac_task_1_20_auth_disabled_admits_the_unattributed_caller() {
        // The one request. Everything below posts THIS value.
        let call = task_invoke(40, "mik-7272-task-1-20");

        let public_fixture = state_public_mcp().await;
        let (_, refused) = post_unattributed(Arc::clone(&public_fixture.state), call.clone()).await;
        assert_eq!(
            refused.pointer("/error/message").and_then(Value::as_str),
            Some("no such task"),
            "control: with auth ENABLED the same call must still be refused, or \
             the contrast below says nothing about the predicate: {refused}"
        );
        assert_eq!(
            refused.pointer("/error/code"),
            Some(&json!(-32602)),
            "and refused in `missing_task_error`'s own code — a different error \
             wearing that message would be a different rule: {refused}"
        );
        assert_eq!(
            refused.pointer("/error/data"),
            None,
            "id-free: a refusal carrying data about a task would hand the \
             unattributed caller exactly what the wording withholds: {refused}"
        );
        // Not a racy negative. The refusal is an early return in the router,
        // before any dispatch is spawned, so a count read straight after it
        // cannot be observing work that has merely not started yet.
        assert_eq!(
            public_fixture.backend.calls(),
            0,
            "the refused create must have no backend effect whatsoever"
        );

        let mut disabled = public_mcp_auth();
        disabled.enabled = false;
        let fixture = state_from(disabled).await;

        let (_, admitted) = post_unattributed(Arc::clone(&fixture.state), call.clone()).await;
        assert!(
            admitted.get("error").is_none(),
            "with auth DISABLED there are no principals to keep apart, so the \
             credential-less caller reaches the dispatcher like every other \
             caller on that gateway and is ANSWERED: {admitted}"
        );
        assert_eq!(
            admitted.pointer("/result/resultType"),
            Some(&json!("task")),
            "and answered with a task handle, not with a synchronous result \
             that quietly dropped the `task` member: {admitted}"
        );
        // Panics rather than falling back: an id this row invented would let
        // every comparison below agree about a task that was never created.
        let task_id = task_id_of(&admitted);
        // The handle is a promise that work is under way, so the work is
        // observed: exactly one dispatch reached the real backend.
        fixture.backend.wait_for_calls(1).await;

        // A SECOND unattributed request — another credential-less caller on
        // that gateway — resolves the very handle the first was handed. This is
        // the shared anonymous owner the operator chose by turning
        // authentication off, and it is the half `.18` refuses where the
        // operator DID draw a boundary.
        let (_, fetched) = post_unattributed(
            Arc::clone(&fixture.state),
            modern(41, "tasks/get", json!({ "taskId": task_id.clone() }), true),
        )
        .await;
        assert_eq!(
            fetched.pointer("/result/taskId"),
            Some(&json!(task_id)),
            "an unattributed caller on an auth-disabled gateway sees the task \
             the shared anonymous owner created: {fetched}"
        );

        // The same key, the same operation, the same owner: the handle it
        // already owns comes back, and the tool does not run twice. The first
        // dispatch may have settled by the time this retry arrives.
        //
        // The BYTE-IDENTICAL value, request id included: unlike the polls
        // below, which are distinct requests and carry distinct ids, this one is
        // deliberately the create resent. A retry that differed anywhere would
        // leave open which difference admission keyed on.
        let (_, retried) = post_unattributed(Arc::clone(&fixture.state), call.clone()).await;
        assert_eq!(
            retried.pointer("/result/taskId"),
            Some(&json!(task_id)),
            "a same-key retry is the same logical request and must be answered \
             with the same handle: {retried}"
        );
        assert_eq!(
            fixture.backend.calls(),
            1,
            "and must not run the tool a second time: the dedupe key is \
             (owner, idempotency key), and the anonymous owner is an owner"
        );

        // Real work, really finished. The poll is bounded by the suite's one
        // bound and ends on the store's own terminal status, so a handle behind
        // which nothing ever runs fails this row instead of passing it.
        let terminal =
            poll_unattributed_until_terminal(Arc::clone(&fixture.state), 42, &task_id).await;
        assert_eq!(
            terminal.pointer("/result/status"),
            Some(&json!("completed")),
            "the backend answered, so the task settles completed: {terminal}"
        );
        assert_eq!(
            terminal
                .pointer("/result/result/structuredContent/marker")
                .and_then(Value::as_str),
            Some(super::fixture::MARKER),
            "the completed task preserves the actual backend payload: {terminal}"
        );
        assert_eq!(
            fixture.backend.calls(),
            1,
            "one create, one retry, one dispatch: settling is not a second run"
        );
    }
}
