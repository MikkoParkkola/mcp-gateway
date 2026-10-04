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
    use mcp_gateway::gateway::test_helpers::{CallerStanding, InvokeScope, MetaMcp};
    use mcp_gateway::protocol::RequestId;
    use mcp_gateway::protocol::extensions::ExtensionSet;
    use mcp_gateway::protocol::meta::{Era, classify_and_observe};
    use serde_json::{Value, json};

    const TASKS: &str = "io.modelcontextprotocol/tasks";

    fn meta() -> MetaMcp {
        MetaMcp::new(Arc::new(BackendRegistry::new()))
    }
    fn init(params: &Value, era: Era) -> mcp_gateway::protocol::JsonRpcResponse {
        let admin = InvokeScope::unscoped(CallerStanding::Admin);
        meta().handle_initialize(RequestId::Number(1), Some(params), None, None, era, admin)
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

        let result = init(&params, Era::Modern).result.unwrap_or(Value::Null);

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

        let result = init(&params, Era::Legacy).result.unwrap_or(Value::Null);

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

#[path = "mik_7272_task_1_acs/http.rs"]
mod http;

mod wire {
    use axum::http::StatusCode;
    use serde_json::json;

    use super::http::{TASKS, modern, modern_declaring, post};

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
    // MIK-7272.EXT.1 — the gate reads the declaration through ONE parser.
    // =======================================================================

    /// The route-level half of E5b. A parse-level assertion on
    /// `RequestShape::declared_extensions` stays green while the live gate runs
    /// its own hand-rolled `is_some()` check, so the two parsers can disagree
    /// with every unit test passing. This case fails unless the gate and
    /// `ExtensionSet::from_capabilities` answer the same bytes the same way.
    #[tokio::test]
    async fn ac_ext_1_e6_a_non_object_settings_value_does_not_declare_the_extension() {
        for malformed in [json!(3), json!(null), json!("yes"), json!([]), json!(true)] {
            // GIVEN a request that names the extension identifier but puts
            // something other than a settings object behind it
            let (status, body) = post(
                "key-a",
                modern_declaring(
                    1,
                    "tools/call",
                    json!({ "name": "gateway_list_servers", "task": {} }),
                    json!({ "extensions": { TASKS: malformed } }),
                ),
            )
            .await;

            // THEN presence is not agreement: the request is refused exactly as
            // if the identifier had been absent.
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "settings value {malformed}: {body}"
            );
            assert_eq!(
                body["error"]["code"], -32021,
                "settings value {malformed}: {body}"
            );
        }
    }

    /// The companion to the row above: the valid declaration still passes.
    /// Without it, a gate that refuses every request would satisfy E6.
    #[tokio::test]
    async fn ac_ext_1_e7_a_valid_settings_object_still_declares_the_extension() {
        // GIVEN the shape the specification requires
        let (_, body) = post(
            "key-a",
            modern_declaring(
                1,
                "tools/call",
                json!({ "name": "gateway_list_servers", "task": {} }),
                json!({ "extensions": { TASKS: {} } }),
            ),
        )
        .await;

        // THEN the gate lets it through
        assert!(
            body.get("error").is_none(),
            "a validly declared extension must still be served: {body}"
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

    /// MIK-7778: the tasks extension names the filter under `notifications`,
    /// and the gate must refuse it there exactly as it refuses the root form.
    #[tokio::test]
    async fn ac_task_1_13_an_undeclared_nested_task_filter_is_refused() {
        let (status, body) = post(
            "key-a",
            modern(
                3,
                "subscriptions/listen",
                json!({ "notifications": { "taskIds": [TASK_ID] } }),
                false,
            ),
        )
        .await;

        assert_eq!(body["error"]["code"], -32021, "{body}");
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
}

#[path = "mik_7272_task_1_acs/dispatch.rs"]
mod dispatch;
#[path = "mik_7272_task_1_acs/scope.rs"]
mod scope;

#[path = "mik_7272_task_1_acs/ownership.rs"]
mod ownership;
