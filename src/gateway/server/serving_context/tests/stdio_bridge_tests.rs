// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Draft WIRE.9/11/13 controls for the one production generic stdio loop.
//! Intentionally unregistered until the tests gate and shared serving API exist.

use super::isolated_child;
use crate::gateway::input_bridge::{ClientChannel, DeliveryError, DeliveryProgress};
use crate::gateway::proxy::ProxyManager;
use crate::gateway::server::serving_context::{StdioServeContext, StdioServeLimits};
use crate::gateway::server::{CleanupRuntime, Gateway};
use crate::gateway::streaming::NotificationMultiplexer;
use serde_json::{Value, json};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{
    AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader, DuplexStream, Lines, ReadHalf, WriteHalf,
};

const BOUND: Duration = Duration::from_secs(5);

struct Client {
    reader: Lines<BufReader<ReadHalf<DuplexStream>>>,
    writer: WriteHalf<DuplexStream>,
}

impl Client {
    async fn send(&mut self, value: &Value) {
        let mut bytes = serde_json::to_vec(value).unwrap();
        bytes.push(b'\n');
        tokio::time::timeout(BOUND, self.writer.write_all(&bytes))
            .await
            .expect("client write bound")
            .expect("client write");
    }

    async fn receive(&mut self) -> Value {
        let line = tokio::time::timeout(BOUND, self.reader.next_line())
            .await
            .expect("production writer must yield a complete frame")
            .expect("client read")
            .expect("stdio remains open");
        serde_json::from_str(&line).expect("one non-interleaved JSON frame per line")
    }

    async fn initialize(&mut self) {
        self.send(
            &json!({"jsonrpc":"2.0","id":"init","method":"initialize","params":{
                "protocolVersion":"2025-06-18", "capabilities":{"roots":{}},
                "clientInfo":{"name":"stdio-transport-test","version":"1"}
            }}),
        )
        .await;
        let response = self.receive().await;
        assert_eq!(response["id"], "init");
        assert!(
            response.get("error").is_none(),
            "successful handshake: {response}"
        );
        assert!(response["result"].is_object());
        self.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await;
    }
}

/// A real writer adapter, never a second serialization or dispatch loop.
struct FaultWriter<W> {
    inner: W,
    failure: Arc<AtomicU8>,
    attempted_failure: Arc<AtomicUsize>,
    flush_gate: Arc<FlushGate>,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for FaultWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.failure.load(Ordering::SeqCst) == 1 {
            self.attempted_failure.fetch_add(1, Ordering::SeqCst);
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.failure.load(Ordering::SeqCst) == 2 {
            self.attempted_failure.fetch_add(1, Ordering::SeqCst);
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        self.flush_gate.waker.register(cx.waker());
        if self.flush_gate.held.load(Ordering::SeqCst) {
            self.flush_gate.entered.fetch_add(1, Ordering::SeqCst);
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct Serving {
    client: Client,
    serve: tokio::task::JoinHandle<crate::Result<()>>,
    proxy: Arc<ProxyManager>,
    mux: Arc<NotificationMultiplexer>,
    failure: Arc<AtomicU8>,
    attempted_failure: Arc<AtomicUsize>,
    flush_gate: Arc<FlushGate>,
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.serve.abort();
    }
}

async fn serving(backend: Option<&str>) -> Serving {
    let mut config: crate::config::Config = if let Some(url) = backend {
        serde_yaml::from_str(&format!(
            "backends:\n  held-backend:\n    http_url: {url:?}\n    streamable_http: true\n    timeout: 30s\n"
        )).expect("fixture config")
    } else {
        crate::config::Config::default()
    };
    config.cache.enabled = false;
    let gateway = Gateway::new(config).await.expect("real gateway builder");
    let built = gateway
        .build_meta_mcp(CleanupRuntime::with_clock(Arc::new(|| 1_000)))
        .await
        .expect("real serving owner, clock and shared pair");
    let proxy = Arc::clone(&built.proxy);
    let mux = Arc::clone(&built.multiplexer);
    let context = StdioServeContext {
        owner: built.owner,
        tool_policy: built.tool_policy,
        mtls_policy: built.mtls_policy,
        proxy: built.proxy,
        multiplexer: built.multiplexer,
        protocol_telemetry_sink: None,
        limits: StdioServeLimits {
            max_frame_bytes: 64 * 1024,
            shutdown_timeout: Duration::from_millis(200),
            max_inflight: 2,
            pre_initialize_capacity: 2,
            response_queue_capacity: 4,
        },
    };
    let (client, server) = tokio::io::duplex(128);
    let (reader, writer) = tokio::io::split(server);
    let failure = Arc::new(AtomicU8::new(0));
    let attempted_failure = Arc::new(AtomicUsize::new(0));
    let flush_gate = Arc::new(FlushGate::default());
    let writer = FaultWriter {
        inner: writer,
        failure: Arc::clone(&failure),
        attempted_failure: Arc::clone(&attempted_failure),
        flush_gate: Arc::clone(&flush_gate),
    };
    let serve = tokio::spawn(crate::gateway::server::stdio::serve_stdio(
        context,
        BufReader::new(reader),
        writer,
    ));
    let (reader, writer) = tokio::io::split(client);
    Serving {
        client: Client {
            reader: BufReader::new(reader).lines(),
            writer,
        },
        serve,
        proxy,
        mux,
        failure,
        attempted_failure,
        flush_gate,
    }
}

fn ask(
    serving: &Serving,
    id: &'static str,
) -> tokio::task::JoinHandle<Result<Value, DeliveryError>> {
    assert_eq!(
        serving.mux.session_count(),
        1,
        "the loop owns one private session"
    );
    let session = serving.mux.first_session_id().expect("stdio session");
    let proxy = Arc::clone(&serving.proxy);
    tokio::spawn(async move {
        proxy
            .send_request(
                &session,
                id,
                "roots/list",
                None,
                Arc::new(DeliveryProgress::default()),
            )
            .await
    })
}

async fn delivered_prompt(
    serving: &mut Serving,
    id: &'static str,
) -> tokio::task::JoinHandle<Result<Value, DeliveryError>> {
    let wait = ask(serving, id);
    assert_eq!(
        serving.client.receive().await,
        json!({"jsonrpc":"2.0","id":id,"method":"roots/list"})
    );
    wait
}

async fn lost_prompt(wait: tokio::task::JoinHandle<Result<Value, DeliveryError>>) {
    assert_eq!(
        tokio::time::timeout(BOUND, wait)
            .await
            .expect("pending reply cleanup bound")
            .expect("channel task did not panic"),
        Err(DeliveryError::NoSession)
    );
}

#[tokio::test]
async fn mik_7212_stdio_eof_removes_a_delivered_prompt_and_session() {
    let name = concat!(
        module_path!(),
        "::mik_7212_stdio_eof_removes_a_delivered_prompt_and_session"
    )
    .split_once("::")
    .unwrap()
    .1;
    if isolated_child(name) {
        return;
    }
    let mut serving = serving(None).await;
    serving.client.initialize().await;
    let sid = serving.mux.first_session_id().unwrap();
    let id = "stdio-eof-question";
    let wait = delivered_prompt(&mut serving, id).await;
    serving.client.writer.shutdown().await.expect("client EOF");
    tokio::time::timeout(BOUND, &mut serving.serve)
        .await
        .expect("EOF shutdown bound")
        .expect("serving task did not panic")
        .expect("normal EOF shutdown");
    lost_prompt(wait).await;
    assert_eq!(serving.mux.session_count(), 0);
    assert!(!serving.proxy.resolve_pending(
        id,
        &sid,
        json!({"jsonrpc":"2.0","id":id,"result":{"roots":[]}})
    ));
    println!("COMPLETED {name}");
}

#[tokio::test]
async fn mik_7212_stdio_outer_cancel_removes_a_delivered_prompt_and_session() {
    let name = concat!(
        module_path!(),
        "::mik_7212_stdio_outer_cancel_removes_a_delivered_prompt_and_session"
    )
    .split_once("::")
    .unwrap()
    .1;
    if isolated_child(name) {
        return;
    }
    let mut serving = serving(None).await;
    serving.client.initialize().await;
    let sid = serving.mux.first_session_id().unwrap();
    let id = "stdio-cancel-question";
    let wait = delivered_prompt(&mut serving, id).await;
    serving.serve.abort();
    assert!(
        tokio::time::timeout(BOUND, &mut serving.serve)
            .await
            .expect("abort join bound")
            .expect_err("outer serving task cancelled")
            .is_cancelled()
    );
    lost_prompt(wait).await;
    assert_eq!(serving.mux.session_count(), 0);
    assert!(!serving.proxy.resolve_pending(
        id,
        &sid,
        json!({"jsonrpc":"2.0","id":id,"result":{"roots":[]}})
    ));
    println!("COMPLETED {name}");
}

async fn writer_failure(failure: u8) {
    let mut serving = serving(None).await;
    serving.client.initialize().await;
    serving.failure.store(failure, Ordering::SeqCst);
    let wait = ask(&serving, "stdio-broken-writer");
    lost_prompt(wait).await;
    assert!(
        serving.attempted_failure.load(Ordering::SeqCst) > 0,
        "NoSession without an actual failing production write/flush is invalid staging"
    );
    assert!(
        tokio::time::timeout(BOUND, &mut serving.serve)
            .await
            .expect("I/O shutdown bound")
            .expect("serving task did not panic")
            .is_err()
    );
    assert_eq!(serving.mux.session_count(), 0);
}

#[tokio::test]
async fn mik_7212_stdio_write_error_refuses_and_removes_session() {
    let name = concat!(
        module_path!(),
        "::mik_7212_stdio_write_error_refuses_and_removes_session"
    )
    .split_once("::")
    .unwrap()
    .1;
    if isolated_child(name) {
        return;
    }
    writer_failure(1).await;
    println!("COMPLETED {name}");
}

#[tokio::test]
async fn mik_7212_stdio_flush_error_refuses_and_removes_session() {
    let name = concat!(
        module_path!(),
        "::mik_7212_stdio_flush_error_refuses_and_removes_session"
    )
    .split_once("::")
    .unwrap()
    .1;
    if isolated_child(name) {
        return;
    }
    writer_failure(2).await;
    println!("COMPLETED {name}");
}

struct HeldBackend {
    url: String,
    started: tokio::sync::mpsc::Receiver<Value>,
    release: Arc<tokio::sync::Semaphore>,
    calls: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for HeldBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl HeldBackend {
    async fn start() -> Self {
        let (started_tx, started) = tokio::sync::mpsc::channel(8);
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let app_release = Arc::clone(&release);
        let calls = Arc::new(AtomicUsize::new(0));
        let app_calls = Arc::clone(&calls);
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
                let started = started_tx.clone();
                let release = Arc::clone(&app_release);
                let calls = Arc::clone(&app_calls);
                async move {
                    let id = request.get("id").cloned().unwrap_or(Value::Null);
                    let result = match request["method"].as_str() {
                        Some("server/discover") => {
                            return axum::Json(json!({
                                "jsonrpc":"2.0", "id":id,
                                "error":{"code":-32601,"message":"legacy fixture"}
                            }));
                        }
                        Some("initialize") => json!({
                            "protocolVersion":"2025-06-18", "capabilities":{"tools":{}},
                            "serverInfo":{"name":"held-backend","version":"1"}
                        }),
                        Some("tools/list") => json!({"tools":[{
                            "name":"held_read", "description":"held read for reader progress",
                            "inputSchema":{"type":"object"},
                            "annotations":{"readOnlyHint":true}
                        }]}),
                        Some("tools/call") => {
                            assert_eq!(request["params"]["name"], "held_read");
                            calls.fetch_add(1, Ordering::SeqCst);
                            started
                                .send(request.clone())
                                .await
                                .expect("held call witness");
                            release
                                .acquire()
                                .await
                                .expect("release held backend")
                                .forget();
                            json!({"content":[{"type":"text","text":"held-complete"}]})
                        }
                        _ => json!({}),
                    };
                    axum::Json(json!({"jsonrpc":"2.0","id":id,"result":result}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("held backend bind");
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            url,
            started,
            release,
            calls,
            task,
        }
    }

    async fn admitted(&mut self, marker: &str) {
        let request = tokio::time::timeout(BOUND, self.started.recv())
            .await
            .expect("the real gateway dispatch reaches the held backend")
            .expect("backend remains running");
        assert_eq!(request["params"]["arguments"]["marker"], marker);
    }
}

fn held_call(id: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{
        "name":"gateway_invoke", "arguments":{
            "server":"held-backend", "tool":"held_read", "arguments":{"marker":id}
        }
    }})
}

async fn answered(wait: tokio::task::JoinHandle<Result<Value, DeliveryError>>, reply: Value) {
    assert_eq!(
        tokio::time::timeout(BOUND, wait)
            .await
            .expect("reader must resolve the client reply before the backend is released")
            .expect("channel task did not panic"),
        Ok(reply)
    );
}

async fn shutdown(serving: &mut Serving) {
    serving.client.writer.shutdown().await.expect("client EOF");
    tokio::time::timeout(BOUND, &mut serving.serve)
        .await
        .expect("bounded stdio shutdown")
        .expect("serving join")
        .expect("normal EOF");
    assert_eq!(serving.mux.session_count(), 0);
}

#[tokio::test]
async fn mik_7212_stdio_reader_resolves_reply_while_real_backend_is_held() {
    let name = concat!(
        module_path!(),
        "::mik_7212_stdio_reader_resolves_reply_while_real_backend_is_held"
    )
    .split_once("::")
    .unwrap()
    .1;
    if isolated_child(name) {
        return;
    }
    let mut backend = HeldBackend::start().await;
    let mut serving = serving(Some(&backend.url)).await;
    serving.client.initialize().await;
    serving.client.send(&held_call("held-one")).await;
    backend.admitted("held-one").await;
    assert_eq!(
        backend.release.available_permits(),
        0,
        "backend stays blocked"
    );
    let wait = delivered_prompt(&mut serving, "reader-progress").await;
    let reply = json!({"jsonrpc":"2.0","id":"reader-progress","result":{"roots":[]}});
    serving.client.send(&reply).await;
    answered(wait, reply).await;
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        backend.release.available_permits(),
        0,
        "reply precedes backend release"
    );
    serving
        .client
        .send(&json!({"jsonrpc":"2.0","id":"live-ping","method":"ping"}))
        .await;
    assert_eq!(
        serving.client.receive().await,
        json!({"jsonrpc":"2.0","id":"live-ping","result":{}})
    );
    backend.release.add_permits(1);
    let final_result = serving.client.receive().await;
    assert_eq!(final_result["id"], "held-one");
    assert!(final_result.get("error").is_none(), "{final_result}");
    assert!(final_result.to_string().contains("held-complete"));
    shutdown(&mut serving).await;
    println!("COMPLETED {name}");
}

#[tokio::test]
async fn mik_7212_stdio_saturation_refuses_excess_and_still_resolves_reply() {
    let name = concat!(
        module_path!(),
        "::mik_7212_stdio_saturation_refuses_excess_and_still_resolves_reply"
    )
    .split_once("::")
    .unwrap()
    .1;
    if isolated_child(name) {
        return;
    }
    let mut backend = HeldBackend::start().await;
    let mut serving = serving(Some(&backend.url)).await;
    serving.client.initialize().await;
    for id in ["capacity-one", "capacity-two"] {
        serving.client.send(&held_call(id)).await;
        backend.admitted(id).await;
    }
    let wait = delivered_prompt(&mut serving, "capacity-reply").await;
    serving.client.send(&held_call("capacity-excess")).await;
    let reply = json!({"jsonrpc":"2.0","id":"capacity-reply","result":{"roots":[]}});
    serving.client.send(&reply).await;
    answered(wait, reply).await;
    let excess = serving.client.receive().await;
    assert_eq!(excess["id"], "capacity-excess");
    assert_eq!(excess["error"]["code"], -32000);
    assert_eq!(excess["error"]["message"], "Gateway is at capacity");
    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        2,
        "configured two-dispatch bound"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), backend.started.recv())
            .await
            .is_err(),
        "the excess request must never reach the backend"
    );
    backend.release.add_permits(2);
    let mut ids = vec![
        serving.client.receive().await,
        serving.client.receive().await,
    ];
    ids.sort_by_key(|frame| frame["id"].as_str().unwrap().to_string());
    assert_eq!(ids[0]["id"], "capacity-one");
    assert_eq!(ids[1]["id"], "capacity-two");
    assert!(ids.iter().all(|frame| frame.get("error").is_none()));
    // Actual new backend admission after both slots drain proves reclamation.
    serving.client.send(&held_call("capacity-recovered")).await;
    backend.admitted("capacity-recovered").await;
    assert_eq!(backend.calls.load(Ordering::SeqCst), 3);
    backend.release.add_permits(1);
    assert_eq!(serving.client.receive().await["id"], "capacity-recovered");
    shutdown(&mut serving).await;
    println!("COMPLETED {name}");
}

#[derive(Default)]
struct FlushGate {
    held: AtomicBool,
    entered: AtomicUsize,
    waker: futures::task::AtomicWaker,
}

impl FlushGate {
    fn release(&self) {
        self.held.store(false, Ordering::SeqCst);
        self.waker.wake();
    }

    async fn entered(&self) {
        let start = std::time::Instant::now();
        while self.entered.load(Ordering::SeqCst) == 0 {
            assert!(
                start.elapsed() < BOUND,
                "initialize flush must reach the actual held writer"
            );
            tokio::task::yield_now().await;
        }
    }
}

fn initialize_request() -> Value {
    json!({"jsonrpc":"2.0","id":"init","method":"initialize","params":{
        "protocolVersion":"2025-06-18", "capabilities":{"roots":{}},
        "clientInfo":{"name":"stdio-transport-test","version":"1"}
    }})
}

async fn no_client_frame(serving: &mut Serving) {
    assert!(
        tokio::time::timeout(Duration::from_millis(20), serving.client.reader.next_line())
            .await
            .is_err(),
        "no complete frame or EOF may cross the held barrier"
    );
}

async fn no_backend_admission(backend: &mut HeldBackend) {
    assert!(
        tokio::time::timeout(Duration::from_millis(20), backend.started.recv())
            .await
            .is_err(),
        "prompt-capable work must wait behind the handshake barrier"
    );
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn mik_7212_stdio_initialize_flush_and_initialized_both_gate_work() {
    let name = concat!(
        module_path!(),
        "::mik_7212_stdio_initialize_flush_and_initialized_both_gate_work"
    )
    .split_once("::")
    .unwrap()
    .1;
    if isolated_child(name) {
        return;
    }
    let mut backend = HeldBackend::start().await;
    let mut serving = serving(Some(&backend.url)).await;
    serving.flush_gate.held.store(true, Ordering::SeqCst);
    serving.client.send(&initialize_request()).await;
    let initialized_response = serving.client.receive().await;
    assert_eq!(initialized_response["id"], "init");
    assert!(initialized_response.get("error").is_none());
    serving.flush_gate.entered().await;
    serving.client.send(&held_call("barrier-held-call")).await;
    let wait = ask(&serving, "barrier-question");
    no_backend_admission(&mut backend).await;
    no_client_frame(&mut serving).await;
    // Releasing only the real initialize flush still does not authorize work.
    serving.flush_gate.release();
    no_backend_admission(&mut backend).await;
    no_client_frame(&mut serving).await;
    serving
        .client
        .send(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        .await;
    backend.admitted("barrier-held-call").await;
    assert_eq!(
        serving.client.receive().await,
        json!({"jsonrpc":"2.0","id":"barrier-question","method":"roots/list"})
    );
    let reply = json!({"jsonrpc":"2.0","id":"barrier-question","result":{"roots":[]}});
    serving.client.send(&reply).await;
    answered(wait, reply).await;
    backend.release.add_permits(1);
    assert_eq!(serving.client.receive().await["id"], "barrier-held-call");
    shutdown(&mut serving).await;
    println!("COMPLETED {name}");
}

#[tokio::test]
async fn mik_7212_stdio_pre_initialize_queue_is_bounded_and_recovers() {
    let name = concat!(
        module_path!(),
        "::mik_7212_stdio_pre_initialize_queue_is_bounded_and_recovers"
    )
    .split_once("::")
    .unwrap()
    .1;
    if isolated_child(name) {
        return;
    }
    let mut backend = HeldBackend::start().await;
    let mut serving = serving(Some(&backend.url)).await;
    for id in ["pre-init-one", "pre-init-two", "pre-init-excess"] {
        serving.client.send(&held_call(id)).await;
    }
    let excess = serving.client.receive().await;
    assert_eq!(excess["id"], "pre-init-excess");
    assert_eq!(excess["error"]["code"], -32000);
    assert_eq!(excess["error"]["message"], "Gateway is at capacity");
    no_backend_admission(&mut backend).await;
    serving
        .client
        .send(&json!({"jsonrpc":"2.0","id":"pre-init-ping","method":"ping"}))
        .await;
    assert_eq!(
        serving.client.receive().await,
        json!({"jsonrpc":"2.0","id":"pre-init-ping","result":{}})
    );
    serving.client.initialize().await;
    // Reader order is not a backend scheduling requirement; both must arrive.
    let mut markers = Vec::new();
    for _ in 0..2 {
        let request = tokio::time::timeout(BOUND, backend.started.recv())
            .await
            .unwrap()
            .unwrap();
        markers.push(
            request["params"]["arguments"]["marker"]
                .as_str()
                .unwrap()
                .to_string(),
        );
    }
    markers.sort();
    assert_eq!(markers, ["pre-init-one", "pre-init-two"]);
    backend.release.add_permits(2);
    let mut ids = [
        serving.client.receive().await,
        serving.client.receive().await,
    ];
    ids.sort_by_key(|frame| frame["id"].as_str().unwrap().to_string());
    assert_eq!(ids[0]["id"], "pre-init-one");
    assert_eq!(ids[1]["id"], "pre-init-two");
    assert!(ids.iter().all(|frame| frame.get("error").is_none()));
    shutdown(&mut serving).await;
    println!("COMPLETED {name}");
}
