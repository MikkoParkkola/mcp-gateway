// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7272.OWNER.2, in-crate rows U1–U6 of the I4 test plan
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

const BACKEND: &str = "fixture";
const TOOL: &str = "echo";
const DENIED: &str = "forbidden";

/// A counting backend answering every tool at once.
async fn backend() -> (String, Arc<AtomicUsize>) {
    let rounds = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&rounds);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let counted = Arc::clone(&counted);
            async move {
                let result = match request.get("method").and_then(Value::as_str) {
                    Some("initialize") => json!({
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": BACKEND, "version": "0"},
                    }),
                    Some("tools/list") => json!({"tools": [
                        {"name": TOOL, "inputSchema": {"type": "object"}},
                        {"name": DENIED, "inputSchema": {"type": "object"}},
                    ]}),
                    Some("tools/call") => {
                        counted.fetch_add(1, Ordering::SeqCst);
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
    (format!("http://{address}/"), rounds)
}

/// A stdio task store over a production-built `MetaMcp`, under `policy`.
struct Fixture {
    tasks: Arc<StdioTasks>,
    meta: Arc<crate::gateway::meta_mcp::MetaMcp>,
    policy: Arc<ToolPolicy>,
    mtls: Arc<crate::mtls::MtlsPolicy>,
    rounds: Arc<AtomicUsize>,
    store: tempfile::TempDir,
    _data: tempfile::TempDir,
}

async fn fixture(policy: Option<ToolPolicy>) -> Fixture {
    let (url, rounds) = backend().await;
    let store = tempfile::tempdir().expect("store root");
    let mut config = Config::default();
    config.tasks.store_dir = store.path().display().to_string();
    config.backends.insert(
        BACKEND.to_string(),
        BackendConfig {
            enabled: true,
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: true,
                protocol_version: None,
            },
            ..BackendConfig::default()
        },
    );
    let data = tempfile::tempdir().expect("data dir");
    let built = Gateway::new(config.clone())
        .await
        .expect("the production constructor accepts this configuration")
        .with_data_dir(data.path().to_path_buf())
        .build_meta_mcp()
        .await
        .expect("the production builder accepts this configuration");
    let tool_policy = policy.map_or(built.tool_policy, Arc::new);
    let (tasks, _expiry) = stdio_tasks::open(
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
    let fixture = fixture(None).await;
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
    let fixture = fixture(None).await;
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
    let fixture = fixture(None).await;
    let retry = keyed("u4");
    let intent = intent(&fixture.tasks, TOOL, &retry);
    let Fixture { tasks, store, .. } = fixture;
    drop(tasks);
    assert!(
        intent.owned.host().upgrade().is_none(),
        "the session held the only strong reference"
    );
    drop(store);
}

/// A modern `gateway_invoke` of `tool`, keyed `key`, task-augmented when `task`.
fn modern_call(id: u64, tool: &str, key: &str, task: bool) -> Value {
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
async fn dispatch(fixture: &Fixture, request: Value) -> Value {
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
    let fixture = fixture(None).await;
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
    let fixture = fixture(Some(denying)).await;
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
                streamable_http: true,
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
    let reopened = crate::gateway::task_service::open_runtime(
        &stdio_tasks::store_dir(&config),
        1,
        crate::gateway::task_service::StoreLimits::default(),
        Arc::new(
            crate::gateway::subscription_registry::SubscriptionRegistry::new(
                1,
                crate::gateway::auth::AuthState {
                    auth_config: Arc::new(
                        crate::gateway::auth::ResolvedAuthConfig::try_from_config(
                            &config.auth,
                            &crate::config::EnvOverlay::default(),
                        )
                        .expect("auth config"),
                    ),
                    key_server: None,
                    dashboard_bootstrap: Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
                    tls_enabled: false,
                    live_config: Arc::new(crate::config_reload::LiveConfig::new(config.clone())),
                },
            ),
        ),
    )
    .await;
    assert!(
        reopened.is_ok(),
        "the lease is free once run_stdio_on returned"
    );
}
