// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7272.OWNER.2, in-crate rows U1–U9 of the I4 test plan
//! (the sub4 stdio owner test plan; design D6 rev 5).
//! Every task here is created through the stdio intent path, never seeded.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use super::super::stdio_tasks::{self, IntentRequest, StdioTasks};
use crate::config::{BackendConfig, Config, TransportConfig};
use crate::gateway::Gateway;
use crate::gateway::meta_mcp::LOCAL_OPERATOR_PRINCIPAL;
use crate::gateway::task_route::{TaskOwnerText, TaskRoute};
use crate::gateway::task_service::TaskIntent;
use crate::protocol::RequestId;
use crate::protocol::meta::Declared;
use crate::protocol::mrtr::RetryFields;
use crate::security::{ToolPolicy, ToolPolicyConfig};

pub(crate) const BACKEND: &str = "fixture";
pub(crate) const TOOL: &str = "echo";
pub(super) const DENIED: &str = "forbidden";

/// A counting backend answering every tool at once.
pub(crate) async fn backend() -> (String, Arc<AtomicUsize>) {
    backend_listing(json!([
        // MIK-8393: `echo` declares itself read-only, so U2's repeat is a
        // cache hit.
        {"name": TOOL, "inputSchema": {"type": "object"}, "annotations": {"readOnlyHint": true}},
        {"name": DENIED, "inputSchema": {"type": "object"}},
    ]))
    .await
}

/// [`backend`] whose `tools/list` answers `tools` (the route x check matrix
/// lists a destructive tool, MIK-8137 b3).
pub(crate) async fn backend_listing(tools: Value) -> (String, Arc<AtomicUsize>) {
    let rounds = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&rounds);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let counted = Arc::clone(&counted);
            let tools = tools.clone();
            async move {
                let result = match request.get("method").and_then(Value::as_str) {
                    Some("initialize") => json!({
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": BACKEND, "version": "0"},
                    }),
                    Some("tools/list") => json!({"tools": tools}),
                    Some("tools/call") => {
                        counted.fetch_add(1, Ordering::SeqCst);
                        // Echoes a `cmd` argument as sent, so a row can see
                        // what reached the backend (route x check matrix).
                        let text = request["params"]["arguments"]["cmd"]
                            .as_str()
                            .unwrap_or("done")
                            .to_string();
                        json!({"content": [{"type": "text", "text": text}]})
                    }
                    _ => json!({}),
                };
                axum::Json(json!({"jsonrpc": "2.0", "id": request.get("id"), "result": result}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address");
    tokio::spawn(async move { drop(axum::serve(listener, app).await) });
    (format!("http://{address}/"), rounds)
}

/// A stdio task store over a production-built `MetaMcp`, under `policy`.
pub(crate) struct Fixture {
    pub(super) tasks: Arc<StdioTasks>,
    pub(super) meta: Arc<crate::gateway::meta_mcp::MetaMcp>,
    pub(super) policy: Arc<ToolPolicy>,
    mtls: Arc<crate::mtls::MtlsPolicy>,
    pub(super) rounds: Arc<AtomicUsize>,
    /// `security.sanitize_input` as `run_stdio_on` reads it from the config.
    sanitize: crate::gateway::server::stdio_single::InputSanitizing,
    pub(super) store: Arc<tempfile::TempDir>,
    pub(super) expiry: Option<crate::gateway::task_service::execution::ExpirySweep>,
    _data: std::sync::Arc<tempfile::TempDir>,
}

pub(super) async fn fixture(policy: Option<ToolPolicyConfig>) -> Fixture {
    fixture_on(backend().await, policy).await
}

/// [`fixture`] over the backend at `url`.
pub(super) async fn fixture_on(
    backend: (String, Arc<AtomicUsize>),
    policy: Option<ToolPolicyConfig>,
) -> Fixture {
    Box::pin(fixture_on_with(backend, policy, |_| {})).await
}

/// [`fixture_on`] with `configure` applied to the gateway config before it is
/// built (the route x check matrix surfaces a tool through it, MIK-8137 b3).
pub(crate) async fn fixture_on_with(
    (url, rounds): (String, Arc<AtomicUsize>),
    policy: Option<ToolPolicyConfig>,
    configure: impl FnOnce(&mut Config),
) -> Fixture {
    let store = crate::test_dir_keep::kept_tempdir();
    let mut config = Config::default();
    config.tasks.store_dir = store.path().display().to_string();
    config.backends.insert(
        BACKEND.to_string(),
        BackendConfig {
            enabled: true,
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            ..BackendConfig::default()
        },
    );
    configure(&mut config);
    if let Some(policy) = policy {
        config.security.tool_policy = policy;
    }
    let data = crate::test_dir_keep::kept_tempdir();
    let built = Gateway::new(config.clone())
        .await
        .expect("the production constructor accepts this configuration")
        .with_data_dir(data.path().to_path_buf())
        .build_meta_mcp_published()
        .await
        .expect("the production builder accepts this configuration");
    let tool_policy = built.tool_policy;
    let (tasks, expiry) = stdio_tasks::open(
        &config,
        &built.meta_mcp,
        &std::sync::Arc::new(crate::config_reload::LiveConfig::with_auth(
            config.clone(),
            std::sync::Arc::new(crate::gateway::server::stdio_tasks::default_auth(
                &crate::config::EnvOverlay::default(),
                std::sync::Arc::new(crate::gateway::record_principal::test_record_key()),
            )),
        )),
    )
    .await
    .expect("the stdio store opens");
    tasks.service.keep_test_dir(Arc::clone(&store));
    Fixture {
        tasks,
        meta: built.meta_mcp,
        policy: tool_policy,
        mtls: built.mtls_policy,
        rounds,
        sanitize: crate::gateway::server::stdio_single::InputSanitizing::from_setting(
            config.security.sanitize_input,
        ),
        store,
        expiry: Some(expiry),
        _data: data,
    }
}

pub(super) fn keyed(key: &str) -> RetryFields {
    RetryFields {
        idempotency_key: Some(key.to_owned()),
        ..RetryFields::default()
    }
}

/// The intent stdio builds for a keyed task-augmented `gateway_invoke`.
pub(super) fn intent(tasks: &StdioTasks, tool: &str, retry: &RetryFields) -> TaskIntent {
    let arguments = json!({"server": BACKEND, "tool": tool, "arguments": {}});
    tasks
        .intent(&IntentRequest {
            id: RequestId::Number(1),
            tool_name: "gateway_invoke",
            arguments: &arguments,
            is_modern: true,
            retry,
            input_capabilities: Declared::NONE,
            session_id: super::super::STDIO_SESSION_ID,
            protocol_revision: None,
            scope: crate::gateway::meta_mcp::InvokeScope {
                authorizer: &crate::gateway::authz::AllowAll,
                admin: crate::gateway::authz::AdminStanding::None,
                api_key_name: None,
                grant_key: None,
                agent_id: None,
                grant_subject: None,
                caller: crate::identity_propagation::CallerProof::Anonymous,
            },
        })
        .expect("a keyed modern call is accepted")
        .expect("a dispatchable tool becomes a task")
}

/// U1: the worker's rebuilt context keeps the stdio mark, so the reserved
/// owner keys the call's cache and retry entries and provenance is the local
/// transport. The pinned path: without the carry the owner falls away.
#[tokio::test]
async fn a_stdio_task_dispatch_keeps_its_owner_mark() {
    let fixture = Box::pin(fixture(None)).await;
    let retry = keyed("u1");
    let intent = intent(&fixture.tasks, TOOL, &retry);
    let live = intent.owned.host().upgrade().expect("the host is alive");
    let generation = live.generation();
    let authorizer = live.authorizer(intent.owned.authorizer(), &generation);
    let caller = intent
        .owned
        .dispatch_context(&live, &authorizer, &generation);
    assert_eq!(caller.owner_principal(), Some(LOCAL_OPERATOR_PRINCIPAL));
    assert_eq!(
        caller.provenance(),
        crate::identity_propagation::CallerProvenance::LocalTransport
    );
    assert!(
        matches!(
            authorizer,
            crate::gateway::task_service::host::HostAuthorizer::Stdio(_)
        ),
        "a stdio task is authorized as stdio, never as HTTP"
    );
}

/// U3: HTTP owner text cannot name the local operator's task.
#[tokio::test]
async fn http_owner_text_cannot_name_the_local_operator() {
    let fixture = Box::pin(fixture(None)).await;
    let created = settle(&fixture, TOOL, "u3").await;
    let operator = TaskOwnerText::LocalOperator;
    assert!(
        reads(&fixture.tasks, &operator, &created).await,
        "the local operator reads its own task"
    );
    for text in [
        "\0local-operator.v1",
        "\0",
        "\0local-operator.v1x",
        "stdio",
        "local:auth-disabled:tasks:v1",
        "credential:0123456789abcdef",
    ] {
        let owner = TaskOwnerText::Http(text.to_owned());
        assert!(
            !reads(&fixture.tasks, &owner, &created).await,
            "HTTP owner {text:?} reached the stdio task"
        );
    }
}

/// U4: a worker that outlives its stdio session cannot reach the host.
#[tokio::test]
async fn a_stdio_worker_outliving_its_session_settles_before_dispatch() {
    let fixture = Box::pin(fixture(None)).await;
    let retry = keyed("u4");
    let intent = intent(&fixture.tasks, TOOL, &retry);
    let Fixture {
        tasks,
        store,
        expiry,
        ..
    } = fixture;
    drop(expiry);
    drop(tasks);
    assert!(
        intent.owned.host().upgrade().is_none(),
        "the session held the only strong reference"
    );
    drop(store);
}

/// A modern `gateway_invoke` of `tool`, keyed `key`, task-augmented when `task`.
pub(super) fn modern_call(id: u64, tool: &str, key: &str, task: bool) -> Value {
    let mut params = json!({
        "name": "gateway_invoke",
        "arguments": {"server": BACKEND, "tool": tool, "arguments": {}},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":
                {"extensions": {"io.modelcontextprotocol/tasks": {}}},
            "io.modelcontextprotocol/clientInfo": {"name": "owner2", "version": "1"},
            "io.mcp-gateway/idempotency-key": key,
        },
    });
    if task {
        params["task"] = json!({});
    }
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params})
}

/// One request through the stdio dispatcher, with this fixture's store.
pub(crate) async fn dispatch(fixture: &Fixture, request: Value) -> Value {
    Gateway::dispatch_single_for_client(
        &fixture.meta,
        &crate::gateway::authz::published_line(&fixture.meta),
        &fixture.mtls,
        request,
        super::super::StdioClient {
            session_id: super::super::STDIO_SESSION_ID,
            channel: &crate::gateway::input_bridge::NoClientChannel,
            handshake_capabilities: Declared::NONE,
            tasks: Some(&fixture.tasks),
            serving: crate::gateway::server::stdio_single::ModernServing::Enabled,
            discover: crate::gateway::server::stdio_single::DiscoverListing::Configured,
            sanitize: fixture.sanitize,
        },
    )
    .await
    .expect("a request is answered")
}

/// Create a task through the stdio intent path and wait until it is terminal.
async fn settle(fixture: &Fixture, tool: &str, key: &str) -> String {
    let created = dispatch(fixture, modern_call(1, tool, key, true)).await;
    let id = created
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("a task handle: {created}"))
        .to_owned();
    wait_terminal(fixture, id).await
}

/// Wait until task `id` is terminal, and return its id.
pub(super) async fn wait_terminal(fixture: &Fixture, id: String) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let task = fixture
            .tasks
            .service
            .get(LOCAL_OPERATOR_PRINCIPAL, &id)
            .expect("the local operator owns its task");
        if matches!(
            task.task.status(),
            crate::protocol::tasks::TaskStatus::Completed
                | crate::protocol::tasks::TaskStatus::Failed
                | crate::protocol::tasks::TaskStatus::Cancelled
        ) {
            return id;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "task {id} not terminal"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Whether `owner` reads task `id` through the shared route.
async fn reads(tasks: &StdioTasks, owner: &TaskOwnerText, id: &str) -> bool {
    let route = TaskRoute {
        service: &tasks.service,
        executor: &tasks.executor,
        owner,
    };
    let answer = route
        .get(
            RequestId::Number(9),
            Some(&json!({"taskId": id})),
            |_| std::future::ready(()),
            |_| None,
            |_, _| {},
        )
        .await;
    answer.error.is_none()
}

/// U2: a stdio task's inner call is response-cached under the operator, so a
/// synchronous repeat of the same call is served without a second round.
/// Without the carried mark the task's cache principal is unresolved, nothing
/// is stored, and the repeat reaches the backend again.
#[tokio::test]
async fn a_stdio_task_s_inner_call_is_cached_under_the_operator() {
    let fixture = Box::pin(fixture(None)).await;
    settle(&fixture, TOOL, "u2-task").await;
    assert_eq!(fixture.rounds.load(Ordering::SeqCst), 1);
    let repeat = dispatch(&fixture, modern_call(2, TOOL, "u2-sync", false)).await;
    assert!(repeat.get("error").is_none(), "{repeat}");
    assert_eq!(
        fixture.rounds.load(Ordering::SeqCst),
        1,
        "the synchronous repeat is a cache hit: {repeat}"
    );
}

/// U5: a stdio task runs under the current tool policy. A denied tool is
/// refused at submit by the route stage (route-check-parity P3, r2.1 H1),
/// with the policy's own refusal, exactly as its synchronous call is, and no
/// task (MIK-8315); a neighbour still runs. The worker re-checks at run time
/// through the dispatch chokepoint.
#[tokio::test]
async fn a_stdio_task_runs_under_the_current_tool_policy() {
    let denying = ToolPolicyConfig {
        deny: vec![DENIED.to_string()],
        ..ToolPolicyConfig::default()
    };
    let fixture = Box::pin(fixture(Some(denying))).await;
    let sync = dispatch(&fixture, modern_call(1, DENIED, "u5-denied-sync", false)).await;
    let refused = dispatch(&fixture, modern_call(2, DENIED, "u5-denied", true)).await;
    // MIK-8361: refused at submit as a name the backend does not list, not
    // by the policy, exactly as its synchronous call is, and no task.
    let text = refused
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        refused.get("error").is_none()
            && refused["result"]["isError"] == true
            && text.contains(&crate::backend::text_absent(DENIED)),
        "not refused as an absent name at submit: {refused}"
    );
    assert!(
        refused.pointer("/result/taskId").is_none(),
        "a task was made for a denied tool: {refused}"
    );
    assert_eq!(
        refused.pointer("/result/content"),
        sync.pointer("/result/content"),
        "{refused}"
    );
    assert_eq!(
        fixture.rounds.load(Ordering::SeqCst),
        0,
        "the denied call never ran"
    );
    settle(&fixture, TOOL, "u5-neighbour").await;
    assert_eq!(
        fixture.rounds.load(Ordering::SeqCst),
        1,
        "the neighbour ran"
    );
}

/// U7: a `tasks/*` method the stdio body does not name is not found, never
/// handled as one it does (a cancel, say) on the caller's task id.
#[tokio::test]
async fn an_unnamed_tasks_method_fails_closed() {
    let fixture = Box::pin(fixture(None)).await;
    let id = settle(&fixture, TOOL, "u7").await;
    let policy = ToolPolicy::default();
    let authorizer = crate::gateway::authz::ToolPolicyAuthorizer {
        tool_policy: &policy,
        generation: None,
    };
    let retry = RetryFields::default();
    let caller = Gateway::build_stdio_caller_context(
        true,
        None,
        &authorizer,
        &retry,
        &crate::protocol::meta::RequestShape::Legacy,
        super::super::StdioClient {
            session_id: super::super::STDIO_SESSION_ID,
            channel: &crate::gateway::input_bridge::NoClientChannel,
            handshake_capabilities: Declared::NONE,
            tasks: Some(&fixture.tasks),
            serving: crate::gateway::server::stdio_single::ModernServing::Enabled,
            discover: crate::gateway::server::stdio_single::DiscoverListing::Configured,
            sanitize: crate::gateway::server::stdio_single::InputSanitizing::Off,
        },
        (&crate::gateway::record_principal::test_record_key(), None),
    );
    let answer = fixture
        .tasks
        .dispatch(
            "tasks/list",
            RequestId::Number(7),
            Some(&json!({"taskId": id})),
            &caller,
            super::super::STDIO_SESSION_ID,
        )
        .await;
    assert_eq!(
        answer.error.as_ref().map(|error| error.code),
        Some(-32601),
        "{answer:?}"
    );
}

/// U8: a legacy `tools/call` carrying a `task` member is answered
/// synchronously, as before stdio had a store: a legacy shape cannot declare
/// the extension, so it is neither refused nor made a task.
#[tokio::test]
async fn a_legacy_task_member_is_answered_synchronously() {
    let fixture = Box::pin(fixture(None)).await;
    let legacy = json!({"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {
        "name": "gateway_invoke",
        "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {}},
        "task": {},
    }});
    let answer = dispatch(&fixture, legacy).await;
    assert!(answer.get("error").is_none(), "not refused: {answer}");
    assert!(
        answer.pointer("/result/taskId").is_none(),
        "not a task: {answer}"
    );
    assert_eq!(fixture.rounds.load(Ordering::SeqCst), 1, "{answer}");
}

/// Open the stdio store `config` names, as the next process would.
pub(super) async fn reopen_stdio_store(
    config: &Config,
) -> Result<
    (
        Arc<crate::gateway::task_service::TaskService>,
        Arc<crate::gateway::task_service::TaskExecutor>,
    ),
    crate::gateway::task_service::ServiceError,
> {
    let auth_config = crate::gateway::auth::ResolvedAuthConfig::try_from_config(
        &config.auth,
        &crate::config::EnvOverlay::default(),
        crate::gateway::record_principal::TEST_RECORD_KEY,
    )
    .expect("auth config");
    crate::gateway::task_service::open_runtime(
        &stdio_tasks::store_dir(config),
        1,
        crate::gateway::task_service::StoreLimits::default(),
        Arc::new(
            crate::gateway::subscription_registry::SubscriptionRegistry::new(
                1,
                crate::gateway::auth::AuthState {
                    key_server: None,
                    dashboard_bootstrap: Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
                    tls_enabled: false,
                    live_config: Arc::new(crate::config_reload::LiveConfig::with_auth(
                        config.clone(),
                        Arc::new(auth_config),
                    )),
                    agent_auth: crate::gateway::oauth::AgentAuthState::new(
                        false,
                        std::sync::Arc::default(),
                    ),
                },
            ),
        ),
    )
    .await
}

/// A backend whose `held` tool reports arrival, then answers only once the
/// test opens the barrier.
pub(super) async fn held_backend() -> (
    String,
    tokio::sync::watch::Receiver<usize>,
    tokio::sync::watch::Sender<bool>,
) {
    let (arrived_tx, arrived) = tokio::sync::watch::channel(0_usize);
    let (release, release_rx) = tokio::sync::watch::channel(false);
    let arrived_tx = Arc::new(arrived_tx);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let arrived = Arc::clone(&arrived_tx);
            let mut release = release_rx.clone();
            async move {
                let result = match request.get("method").and_then(Value::as_str) {
                    Some("initialize") => json!({
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": BACKEND, "version": "0"},
                    }),
                    Some("tools/list") => json!({"tools": [
                        {"name": "held", "inputSchema": {"type": "object"}},
                    ]}),
                    Some("tools/call") => {
                        arrived.send_modify(|seen| *seen += 1);
                        drop(release.wait_for(|open| *open).await);
                        json!({"content": [{"type": "text", "text": "done"}]})
                    }
                    _ => json!({}),
                };
                axum::Json(json!({"jsonrpc": "2.0", "id": request.get("id"), "result": result}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address");
    tokio::spawn(async move { drop(axum::serve(listener, app).await) });
    (format!("http://{address}/"), arrived, release)
}

/// The stdio task store at the end of a session.
#[path = "owner2_stdio_shutdown_tests.rs"]
mod shutdown;

/// use the real gateway opener, without an explicit store keep.
async fn registered_gateway_tasks(
    path: &std::path::Path,
    data: &std::path::Path,
) -> (
    Arc<StdioTasks>,
    crate::gateway::task_service::execution::ExpirySweep,
) {
    let mut config = Config::default();
    config.tasks.store_dir = path.display().to_string();
    config.events.enabled = false;
    let built = Gateway::new(config.clone())
        .await
        .expect("gateway constructor")
        .with_data_dir(data.to_path_buf())
        .build_meta_mcp_published()
        .await
        .expect("gateway meta layer");
    let live = Arc::new(crate::config_reload::LiveConfig::with_auth(
        config.clone(),
        Arc::new(stdio_tasks::default_auth(
            &crate::config::EnvOverlay::default(),
            Arc::new(crate::gateway::record_principal::test_record_key()),
        )),
    ));
    stdio_tasks::open(&config, &built.meta_mcp, &live)
        .await
        .expect("gateway task runtime starts")
}

#[tokio::test]
async fn registered_gateway_task_directory_lives_until_the_last_store_handle() {
    use crate::gateway::task_service::CreateOutcome;
    use crate::idempotency::admission::{Mode, Request};
    use crate::protocol::tasks::Task;

    let dir = crate::test_dir_keep::kept_tempdir();
    let root = dir.path().to_owned();
    let path = root.join("tasks");
    let data = crate::test_dir_keep::kept_tempdir();
    let (tasks, expiry) = registered_gateway_tasks(&path, data.path()).await;
    // Join the sweep so the final owner is controlled by this row.
    expiry.shutdown().await.expect("expiry sweep stops");
    let service = Arc::clone(&tasks.service);
    let last_store = service.store.clone();
    drop(tasks);
    drop(dir);
    assert!(root.is_dir(), "the opener retained the original directory");

    let task = Task::create("late-write").expect("task clock");
    let operation = json!({"tool": "late-write"});
    let representation = json!({});
    let permit = Arc::new(tokio::sync::Semaphore::new(1));
    let created = service
        .create(
            Request {
                principal: LOCAL_OPERATOR_PRINCIPAL,
                key: "registered-gateway-late-write",
                operation: &operation,
                representation: &representation,
                mode: Mode::Task,
            },
            &task,
            BACKEND,
            move || permit.try_acquire_owned().ok(),
        )
        .await
        .expect("late create completes");
    assert!(matches!(created, CreateOutcome::Created { .. }));
    drop(created);
    assert!(
        path.join("stdio")
            .join(format!("{}.json", task.id()))
            .is_file()
    );
    drop(service);
    assert!(
        root.is_dir(),
        "the last store handle still owns the directory"
    );
    drop(last_store);
    assert!(
        !root.exists(),
        "the directory goes with the last store handle"
    );
}

#[tokio::test]
#[should_panic(expected = "kept_tempdir")]
async fn registered_gateway_task_opener_refuses_a_plain_tempdir() {
    let dir = tempfile::tempdir().expect("an unregistered directory");
    let path = dir.path().join("tasks");
    let attempted = path.clone();
    let result = tokio::spawn(async move {
        let data = crate::test_dir_keep::kept_tempdir();
        let (tasks, expiry) = registered_gateway_tasks(&attempted, data.path()).await;
        expiry
            .shutdown()
            .await
            .expect("expiry stops on an unexpected open");
        drop(tasks);
    })
    .await;
    if let Err(error) = result {
        let panic = error.into_panic();
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert!(
            message.contains(&path.join("stdio").display().to_string()),
            "missing store path"
        );
        assert!(message.contains("kept_tempdir"), "missing ownership hint");
        assert!(!path.exists(), "refusal must precede store creation");
        std::panic::resume_unwind(panic);
    }
    // Returning normally makes should_panic fail when the exemption survives.
}
