// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7272.OWNER.2, in-crate rows U1–U9 of the I4 test plan
//! (`docs/design/2026-09-30-sub4-stdio-owner-test-plan.md`; design D6 rev 5).
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
const DENIED: &str = "forbidden";

/// A counting backend answering every tool at once.
pub(crate) async fn backend() -> (String, Arc<AtomicUsize>) {
    backend_listing(json!([
        {"name": TOOL, "inputSchema": {"type": "object"}},
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
    meta: Arc<crate::gateway::meta_mcp::MetaMcp>,
    policy: Arc<ToolPolicy>,
    mtls: Arc<crate::mtls::MtlsPolicy>,
    rounds: Arc<AtomicUsize>,
    pub(super) store: tempfile::TempDir,
    pub(super) expiry: Option<crate::gateway::task_service::execution::ExpirySweep>,
    _data: tempfile::TempDir,
}

async fn fixture(policy: Option<ToolPolicy>) -> Fixture {
    fixture_on(backend().await, policy).await
}

/// [`fixture`] over the backend at `url`.
pub(super) async fn fixture_on(
    backend: (String, Arc<AtomicUsize>),
    policy: Option<ToolPolicy>,
) -> Fixture {
    Box::pin(fixture_on_with(backend, policy, |_| {})).await
}

/// [`fixture_on`] with `configure` applied to the gateway config before it is
/// built (the route x check matrix surfaces a tool through it, MIK-8137 b3).
pub(crate) async fn fixture_on_with(
    (url, rounds): (String, Arc<AtomicUsize>),
    policy: Option<ToolPolicy>,
    configure: impl FnOnce(&mut Config),
) -> Fixture {
    let store = tempfile::tempdir().expect("store root");
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
    let data = tempfile::tempdir().expect("data dir");
    let built = Gateway::new(config.clone())
        .await
        .expect("the production constructor accepts this configuration")
        .with_data_dir(data.path().to_path_buf())
        .build_meta_mcp()
        .await
        .expect("the production builder accepts this configuration");
    let tool_policy = policy.map_or(built.tool_policy, Arc::new);
    let (tasks, expiry) = stdio_tasks::open(
        &config,
        &crate::config::EnvOverlay::default(),
        &built.meta_mcp,
        &tool_policy,
    )
    .await
    .expect("the stdio store opens");
    Fixture {
        tasks,
        meta: built.meta_mcp,
        policy: tool_policy,
        mtls: built.mtls_policy,
        rounds,
        store,
        expiry: Some(expiry),
        _data: data,
    }
}

fn keyed(key: &str) -> RetryFields {
    RetryFields {
        idempotency_key: Some(key.to_owned()),
        ..RetryFields::default()
    }
}

/// The intent stdio builds for a keyed task-augmented `gateway_invoke`.
fn intent(tasks: &StdioTasks, tool: &str, retry: &RetryFields) -> TaskIntent {
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
    let authorizer = live.authorizer(intent.owned.authorizer());
    let caller = intent.owned.dispatch_context(&live, &authorizer);
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
    Gateway::dispatch_single_with_sink(
        &fixture.meta,
        &fixture.policy,
        &fixture.mtls,
        request,
        super::super::StdioClient {
            session_id: super::super::STDIO_SESSION_ID,
            channel: &crate::gateway::input_bridge::NoClientChannel,
            handshake_capabilities: Declared::NONE,
            tasks: Some(&fixture.tasks),
            modern: false,
        },
        &super::super::StdioTelemetry::default(),
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

/// U5: a stdio task runs under the current tool policy.
#[tokio::test]
async fn a_stdio_task_runs_under_the_current_tool_policy() {
    let denying = ToolPolicy::from_config(&ToolPolicyConfig {
        deny: vec![DENIED.to_string()],
        ..ToolPolicyConfig::default()
    });
    let fixture = Box::pin(fixture(Some(denying))).await;
    // Settled terminal by its own worker: the authorizer refused it.
    settle(&fixture, DENIED, "u5-denied").await;
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

/// U6: EOF releases the stdio store's lease before `run_stdio_on` returns.
#[tokio::test]
async fn stdio_eof_releases_the_store_lease_before_returning() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let (url, _rounds) = backend().await;
    let store = tempfile::tempdir().expect("store root");
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
    let data = tempfile::tempdir().expect("data dir");
    let gateway = Gateway::new(config.clone())
        .await
        .expect("gateway boots")
        .with_data_dir(data.path().to_path_buf());
    let (mut stdin, input) = tokio::io::duplex(64 * 1024);
    let (output, reader) = tokio::io::duplex(1 << 20);
    let served = tokio::spawn(async move { gateway.run_stdio_on(input, output, None).await });
    let mut lines = BufReader::new(reader).lines();
    let handshake = json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "owner2", "version": "1"}}});
    stdin
        .write_all(format!("{handshake}\n").as_bytes())
        .await
        .expect("write");
    tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await
        .expect("handshake answered in time")
        .expect("read");
    let created = modern_call(1, TOOL, "u6", true);
    stdin
        .write_all(format!("{created}\n").as_bytes())
        .await
        .expect("write");
    let answer = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await
        .expect("answered in time")
        .expect("read")
        .expect("a line");
    assert!(answer.contains("taskId"), "a task was created: {answer}");
    drop(stdin);
    tokio::time::timeout(Duration::from_secs(40), served)
        .await
        .expect("EOF returns within the bound")
        .expect("no panic")
        .expect("run_stdio_on returns Ok");
    let reopened = reopen(&config).await;
    assert!(
        reopened.is_ok(),
        "the lease is free once run_stdio_on returned"
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
            modern: false,
        },
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
pub(super) async fn reopen(
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
                    auth_config: Arc::new(auth_config),
                    key_server: None,
                    dashboard_bootstrap: Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
                    tls_enabled: false,
                    live_config: Arc::new(crate::config_reload::LiveConfig::new(config.clone())),
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

/// U9: EOF while a task is still running waits for it. `run_stdio_on` is
/// still serving while the held call is open, returns once it settles, and
/// the store, reopened at once, is free and holds the backend's own result:
/// the worker finished before the store closed. A task cut off instead would
/// recover at reopen as completed with a restart error, never with `done`.
#[tokio::test]
async fn eof_drains_a_running_task_before_returning() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let (url, mut arrived, release) = held_backend().await;
    let store = tempfile::tempdir().expect("store root");
    let mut config = Config::default();
    config.tasks.store_dir = store.path().display().to_string();
    config.server.shutdown_timeout = Duration::from_secs(20);
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
    let data = tempfile::tempdir().expect("data dir");
    let gateway = Gateway::new(config.clone())
        .await
        .expect("gateway boots")
        .with_data_dir(data.path().to_path_buf());
    let (mut stdin, input) = tokio::io::duplex(64 * 1024);
    let (output, reader) = tokio::io::duplex(1 << 20);
    let mut served = tokio::spawn(async move { gateway.run_stdio_on(input, output, None).await });
    let mut lines = BufReader::new(reader).lines();
    let handshake = json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "owner2", "version": "1"}}});
    stdin
        .write_all(format!("{handshake}\n").as_bytes())
        .await
        .expect("write");
    tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await
        .expect("handshake answered in time")
        .expect("read");
    let created = modern_call(1, "held", "u9", true);
    stdin
        .write_all(format!("{created}\n").as_bytes())
        .await
        .expect("write");
    let answer = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await
        .expect("answered in time")
        .expect("read")
        .expect("a line");
    let answer: Value = serde_json::from_str(&answer).expect("one frame");
    let id = answer
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("a task handle: {answer}"))
        .to_owned();
    tokio::time::timeout(Duration::from_secs(10), arrived.wait_for(|seen| *seen >= 1))
        .await
        .expect("the held call reaches the backend")
        .expect("fixture alive");
    drop(stdin);
    // Five seconds is far past EOF's own work; a server that does not drain
    // returns well inside it, one that does is still held by the barrier.
    assert!(
        tokio::time::timeout(Duration::from_secs(5), &mut served)
            .await
            .is_err(),
        "EOF waits for the running task instead of returning past it"
    );
    release.send_modify(|open| *open = true);
    tokio::time::timeout(Duration::from_secs(30), served)
        .await
        .expect("EOF returns once the task settled")
        .expect("no panic")
        .expect("run_stdio_on returns Ok");
    let (service, _executor) = reopen(&config)
        .await
        .expect("the lease is free once run_stdio_on returned");
    let task = service
        .get(LOCAL_OPERATOR_PRINCIPAL, &id)
        .expect("the local operator's task is in its store");
    let wire = serde_json::to_value(task.task.wire()).expect("the task serializes");
    assert_eq!(
        task.task.status(),
        crate::protocol::tasks::TaskStatus::Completed,
        "{wire}"
    );
    assert!(
        wire.to_string().contains("done") && !wire.to_string().contains("gateway_restart"),
        "settled by its own worker with the backend's result, not by recovery: {wire}"
    );
}

/// `MIK-7638.GH2543.2`: stdio serves no listener route, so its task store does
/// not depend on the gateway's auth configuration. A bearer token whose
/// secret reference cannot be resolved leaves the store open.
#[tokio::test]
async fn an_unresolvable_auth_config_leaves_the_stdio_store_open() {
    let fixture = Box::pin(fixture(None)).await;
    let store = tempfile::tempdir().expect("store root");
    let mut config = Config::default();
    config.tasks.store_dir = store.path().display().to_string();
    config.auth.bearer_token = Some("env:MIK_7638_UNSET_FIXTURE_TOKEN".to_string());
    assert!(
        crate::gateway::auth::ResolvedAuthConfig::try_from_config(
            &config.auth,
            &crate::config::EnvOverlay::default()
        )
        .is_err(),
        "premise: the fixture's auth secret must not resolve"
    );
    let opened = stdio_tasks::open(
        &config,
        &crate::config::EnvOverlay::default(),
        &fixture.meta,
        &fixture.policy,
    )
    .await;
    assert!(
        opened.is_some(),
        "an auth secret stdio never uses turned its task store off"
    );
    if let Some((tasks, expiry)) = opened {
        let window = std::time::Duration::from_secs(5);
        let budget = super::super::task_runtime::ShutdownBudget::within(window, window);
        stdio_tasks::shutdown(&tasks, expiry, budget).await;
    }
}
