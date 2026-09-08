// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Actual HTTP/TLS lifetime tests for MIK-7212.MRTR.8b (HTTP.1–HTTP.5).

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::json;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use super::Gateway;
use super::continuation_cleanup::{CleanupEvent, CleanupRuntime};
use super::test_support::{isolated_child, observed_without_time_advance};
use crate::config::Config;
use crate::mtls::{CaParams, CertGenerator, LeafCertParams};
use crate::protocol::continuation::ContinuationState;
use crate::{Error, Result};

const EPOCH: u64 = 1_000;

pub(super) enum HttpLifecycleEvent {
    Built(Arc<ContinuationState>),
    Bound(SocketAddr),
}

struct Fixture {
    _dir: tempfile::TempDir,
    config: Config,
    ca_pem: Option<String>,
}

impl Fixture {
    fn new(tls: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.server.host = "127.0.0.1".into();
        config.server.port = 0;
        config.auth.enabled = false;
        config.capabilities.enabled = false;
        let ca_pem = tls.then(|| {
            let ca = CertGenerator::init_ca(&CaParams {
                cn: "Lifecycle test CA",
                validity_days: 1,
            })
            .unwrap();
            let leaf = CertGenerator::issue_leaf(
                &LeafCertParams {
                    cn: "localhost",
                    ou: None,
                    san_dns: vec!["localhost".into()],
                    san_uris: vec![],
                    validity_days: 1,
                },
                &ca.cert_pem,
                &ca.key_pem,
            )
            .unwrap();
            for (name, pem) in [
                ("ca.crt", &ca.cert_pem),
                ("server.crt", &leaf.cert_pem),
                ("server.key", &leaf.key_pem),
            ] {
                std::fs::write(dir.path().join(name), pem).unwrap();
            }
            config.mtls.enabled = true;
            config.mtls.require_client_cert = false;
            config.mtls.ca_cert = dir.path().join("ca.crt").to_str().unwrap().into();
            config.mtls.server_cert = dir.path().join("server.crt").to_str().unwrap().into();
            config.mtls.server_key = dir.path().join("server.key").to_str().unwrap().into();
            ca.cert_pem
        });
        Self {
            _dir: dir,
            config,
            ca_pem,
        }
    }

    async fn request(&self, address: SocketAddr, id: u64) {
        let mut builder = reqwest::Client::builder().no_proxy();
        let url = if let Some(ca) = &self.ca_pem {
            builder = builder
                .tls_backend_rustls()
                .tls_certs_only([reqwest::Certificate::from_pem(ca.as_bytes()).unwrap()])
                .resolve("localhost", address);
            format!("https://localhost:{}/mcp", address.port())
        } else {
            format!("http://{address}/mcp")
        };
        let client = builder.build().unwrap();
        observe(async {
            let response = client
                .post(url)
                .header("accept", "application/json, text/event-stream")
                .header("mcp-protocol-version", "2026-07-28")
                .header("mcp-method", "tools/list")
                .json(&json!({
                    "jsonrpc": "2.0", "id": id, "method": "tools/list",
                    "params": {"_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities": {}
                    }}
                }))
                .send()
                .await
                .expect("real HTTP/TLS request must connect before interpreting lifecycle");
            assert!(response.status().is_success(), "HTTP fixture: {response:?}");
            let body: serde_json::Value = response.json().await.unwrap();
            assert_eq!(body["id"], id, "must echo the real request ID");
            assert!(body.get("error").is_none(), "MCP fixture refusal: {body}");
            assert!(
                body["result"]["tools"].is_array(),
                "not a tools/list result"
            );
        })
        .await;
    }
}

struct DropWitness(Arc<AtomicU64>);

impl Drop for DropWitness {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct Running {
    task: JoinHandle<Result<()>>,
    lifecycle: mpsc::UnboundedReceiver<HttpLifecycleEvent>,
    scans: mpsc::UnboundedReceiver<CleanupEvent>,
    epoch: Arc<AtomicU64>,
    calls: Arc<AtomicU64>,
    shutdown: Option<oneshot::Sender<()>>,
    dropped: Arc<AtomicU64>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Running {
    fn start(gateway: Gateway) -> Self {
        let (events, lifecycle) = mpsc::unbounded_channel();
        let (scan_tx, scans) = mpsc::unbounded_channel();
        let epoch = Arc::new(AtomicU64::new(EPOCH));
        let calls = Arc::new(AtomicU64::new(0));
        let clock_epoch = Arc::clone(&epoch);
        let clock_calls = Arc::clone(&calls);
        let runtime = CleanupRuntime::with_events(
            Arc::new(move || {
                clock_calls.fetch_add(1, Ordering::SeqCst);
                clock_epoch.load(Ordering::SeqCst)
            }),
            scan_tx,
        );
        let (shutdown, signal) = oneshot::channel();
        let dropped = Arc::new(AtomicU64::new(0));
        let witness = DropWitness(Arc::clone(&dropped));
        let task = tokio::spawn(gateway.run_with_runtime(
            runtime,
            move |sender| async move {
                let _witness = witness;
                let _ = signal.await;
                let _ = sender.send(());
            },
            Some(events),
        ));
        Self {
            task,
            lifecycle,
            scans,
            epoch,
            calls,
            shutdown: Some(shutdown),
            dropped,
        }
    }

    async fn built(&mut self) -> Arc<ContinuationState> {
        match observe(self.lifecycle.recv()).await {
            Some(HttpLifecycleEvent::Built(state)) => state,
            _ => panic!("first production lifecycle event must be Built"),
        }
    }

    async fn bound(&mut self) -> SocketAddr {
        match observe(self.lifecycle.recv()).await {
            Some(HttpLifecycleEvent::Bound(address)) => address,
            _ => panic!("second production lifecycle event must be Bound"),
        }
    }

    async fn tick(&mut self, removed: usize) {
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            observe(self.scans.recv()).await,
            Some(CleanupEvent::Scanned { removed })
        );
    }

    async fn end_events(&mut self) {
        assert!(
            observe(self.lifecycle.recv()).await.is_none(),
            "extra or out-of-order lifecycle event"
        );
    }

    async fn stopped(&mut self, state: &ContinuationState) {
        let hold = state
            .in_flight()
            .hold("retained-clone", EPOCH + 100, EPOCH)
            .await
            .unwrap();
        let raw = state.in_flight().snapshot().await;
        assert!(raw.contains_key(&hold));
        let calls = self.calls.load(Ordering::SeqCst);
        self.epoch.store(EPOCH + 101, Ordering::SeqCst);
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }
        assert_eq!(
            self.calls.load(Ordering::SeqCst),
            calls,
            "scan after server ended"
        );
        assert_eq!(
            state.in_flight().snapshot().await,
            raw,
            "retained state reclaimed after stop"
        );
    }
}

async fn observe<F: Future>(future: F) -> F::Output {
    observed_without_time_advance(future)
        .await
        .expect("real-time observation watchdog expired without Tokio clock travel")
}

#[derive(Clone, Copy)]
enum ExitCase {
    Idle,
    Graceful,
    Abort,
}

async fn live_case(tls: bool, case: ExitCase) {
    let fixture = Fixture::new(tls);
    let mut running = Running::start(Gateway::new(fixture.config.clone()).await.unwrap());
    let state = running.built().await;
    let address = running.bound().await;
    assert_eq!(
        observe(running.scans.recv()).await,
        Some(CleanupEvent::Ready)
    );
    fixture.request(address, if tls { 701 } else { 702 }).await;

    if matches!(case, ExitCase::Idle) {
        let expired = state
            .in_flight()
            .hold("actual-http-state", EPOCH + 1, EPOCH)
            .await
            .unwrap();
        let live = state
            .in_flight()
            .hold("actual-http-state", EPOCH + 100, EPOCH)
            .await
            .unwrap();
        running.epoch.store(EPOCH + 2, Ordering::SeqCst);
        running.tick(1).await;
        let raw = state.in_flight().snapshot().await;
        assert_eq!(raw.len(), 1);
        assert!(!raw.contains_key(&expired));
        assert_eq!(raw.get(&live), Some(&(EPOCH + 100)));
    } else {
        running.tick(0).await;
        if matches!(case, ExitCase::Graceful) {
            running.tick(0).await;
        }
    }

    let survivor = state
        .in_flight()
        .hold("held-through-serving-exit", EPOCH + 100, EPOCH)
        .await
        .unwrap();
    let before_shutdown = state.in_flight().snapshot().await;

    if matches!(case, ExitCase::Abort) {
        running.task.abort();
        assert!(observe(&mut running.task).await.unwrap_err().is_cancelled());
    } else {
        running.shutdown.take().unwrap().send(()).unwrap();
        observe(&mut running.task).await.unwrap().unwrap();
    }
    running.end_events().await;
    assert_eq!(
        state.in_flight().snapshot().await,
        before_shutdown,
        "serving exit changed a continuation held during service"
    );
    running.stopped(&state).await;
    assert_eq!(
        state.in_flight().snapshot().await.get(&survivor),
        Some(&(EPOCH + 100)),
        "continuation held during service changed after stopped-clock ticks"
    );
    let shutdown_dropped = observed_without_time_advance(async {
        while running.dropped.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_eq!(
        shutdown_dropped,
        Some(()),
        "shutdown future survived the completed serving task"
    );
    assert_eq!(
        running.dropped.load(Ordering::SeqCst),
        1,
        "shutdown future detached"
    );
}

async fn startup_failure(tls: bool) {
    let mut fixture = Fixture::new(tls);
    let occupied = if tls {
        None
    } else {
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        fixture.config.server.port = socket.local_addr().unwrap().port();
        Some(socket)
    };
    let gateway = Gateway::new(fixture.config.clone()).await.unwrap();
    if tls {
        std::fs::write(&fixture.config.mtls.server_cert, "not a certificate PEM").unwrap();
    }
    let mut running = Running::start(gateway);
    let state = running.built().await;
    let address = if tls {
        Some(running.bound().await)
    } else {
        None
    };
    let error = observe(&mut running.task).await.unwrap().unwrap_err();
    if tls {
        assert!(
            matches!(error, Error::Config(ref message)
                if message == &format!("No certificates found in '{}'", fixture.config.mtls.server_cert)),
            "wrong TLS certificate-loader failure after bind: {error:?}"
        );
    } else {
        assert!(matches!(error, Error::Io(ref e) if e.kind() == std::io::ErrorKind::AddrInUse));
    }
    running.end_events().await;
    running.stopped(&state).await;
    if let Some(address) = address {
        let rebound = tokio::net::TcpListener::bind(address).await.unwrap();
        assert_eq!(rebound.local_addr().unwrap(), address);
    }
    drop(occupied);
}

macro_rules! lifecycle_test {
    ($name:ident, $case:expr) => {
        #[tokio::test(start_paused = true)]
        async fn $name() {
            let name = concat!(module_path!(), "::", stringify!($name))
                .split_once("::")
                .unwrap()
                .1;
            if isolated_child(name) {
                return;
            }
            $case.await;
            println!("COMPLETED {name}");
        }
    };
}

lifecycle_test!(expiry_http_idle, live_case(false, ExitCase::Idle));
lifecycle_test!(expiry_tls_idle, live_case(true, ExitCase::Idle));
lifecycle_test!(expiry_http_graceful, live_case(false, ExitCase::Graceful));
lifecycle_test!(expiry_tls_graceful, live_case(true, ExitCase::Graceful));
lifecycle_test!(expiry_http_abort, live_case(false, ExitCase::Abort));
lifecycle_test!(expiry_tls_abort, live_case(true, ExitCase::Abort));
lifecycle_test!(expiry_http_bind_failure, startup_failure(false));
lifecycle_test!(expiry_tls_startup_failure, startup_failure(true));
