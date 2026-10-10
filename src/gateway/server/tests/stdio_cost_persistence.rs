// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stdio gateway keeps today's cost-governance spend across a restart.
//!
//! Driven in process through `Gateway::run_stdio_on` over in-memory pipes,
//! with the data directory pointed at a tempdir. The spend is read back
//! through `boot_cost_governance`, the loader the next process runs, so a
//! save that wrote an empty or unreadable snapshot fails here too.
//!
//! Each case computes "today" when it runs; one that straddles UTC midnight
//! can see the earlier day's spend dropped by the loader.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};
use tokio::time::timeout;

use crate::config::Config;
use crate::cost_accounting::persistence::{self as cost_persistence, PersistedCosts, ToolTotal};
use crate::gateway::Gateway;
use crate::gateway::server::persistence::boot_cost_governance;

const BACKEND: &str = "fixture";
const TOOL: &str = "echo";
const KEY: &str = "seeded-key";
/// Bound on every wait for a frame that must arrive.
const ARRIVAL: Duration = Duration::from_secs(10);
/// How long after EOF the held backend answer is released: far longer than
/// the loop needs to read EOF from an in-memory pipe.
const EOF_HOLD: Duration = Duration::from_millis(300);

/// An HTTP MCP backend with one tool. `called` flips when a `tools/call`
/// arrives; its answer is held until `release` is notified, so the test can
/// close stdin while the call is still in flight.
async fn spawn_backend(called: Arc<AtomicBool>, release: Arc<tokio::sync::Notify>) -> String {
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let (called, release) = (Arc::clone(&called), Arc::clone(&release));
            async move {
                if request.get("method").and_then(Value::as_str) == Some("tools/call") {
                    let released = release.notified();
                    called.store(true, Ordering::SeqCst);
                    released.await;
                }
                let result = match request.get("method").and_then(Value::as_str) {
                    Some("initialize") => json!({
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": BACKEND, "version": "0"},
                    }),
                    Some("tools/list") => json!({"tools": [{
                        "name": TOOL,
                        "description": "answers after a hold",
                        "inputSchema": {"type": "object"},
                    }]}),
                    Some("tools/call") => json!({"content": [{"type": "text", "text": "ok"}]}),
                    _ => json!({}),
                };
                axum::Json(json!({"jsonrpc": "2.0", "id": request.get("id"), "result": result}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture backend");
    let address = listener.local_addr().expect("fixture address");
    tokio::spawn(async move { drop(axum::serve(listener, app).await) });
    format!("http://{address}/")
}

/// Cost governance at 0.6 per call against a 1.0 daily budget.
const GOVERNANCE: &str =
    "cost_governance:\n  enabled: true\n  default_cost: 0.6\n  budgets:\n    daily: 1.0\n";

fn load(dir: &Path, yaml: &str) -> Config {
    let path = dir.join("gateway.yaml");
    // The task store under the test's own directory, never the default under $HOME.
    let yaml = format!(
        "{yaml}tasks:\n  store_dir: {}\n",
        serde_json::to_string(&dir.join("tasks").display().to_string()).expect("a JSON string")
    );
    crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    Config::load(Some(&path)).expect("config loads")
}

/// A stdio gateway on `data_dir`, and the client ends of its pipes.
struct Served {
    client: DuplexStream,
    lines: tokio::io::Lines<BufReader<DuplexStream>>,
    task: tokio::task::JoinHandle<()>,
    config: Config,
}

async fn serve(data_dir: &Path, yaml: &str) -> Served {
    let config = load(data_dir, yaml);
    let gateway = Gateway::new(config.clone())
        .await
        .expect("gateway boots")
        .with_data_dir(data_dir.to_path_buf());
    let (client, input) = tokio::io::duplex(64 * 1024);
    let (output, reader) = tokio::io::duplex(1 << 20);
    let task = tokio::spawn(async move {
        drop(gateway.run_stdio_on(input, output, None).await);
    });
    Served {
        client,
        lines: BufReader::new(reader).lines(),
        task,
        config,
    }
}

impl Served {
    async fn send(&mut self, frame: &Value) {
        self.client
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .expect("write to the gateway's stdin");
    }

    /// The response to request `id`, skipping notifications.
    async fn response(&mut self, id: i64) -> Value {
        timeout(ARRIVAL, async {
            loop {
                let line = self
                    .lines
                    .next_line()
                    .await
                    .expect("read the gateway's stdout")
                    .expect("stdout closed before the response");
                let frame: Value = serde_json::from_str(&line).expect("one JSON frame per line");
                if frame.get("id").and_then(Value::as_i64) == Some(id)
                    && frame.get("method").is_none()
                {
                    return frame;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no response to request {id}"))
    }

    async fn initialize(&mut self) {
        self.send(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "stdio-costs", "version": "0"},
            },
        }))
        .await;
        let response = self.response(1).await;
        assert!(
            response.get("result").is_some(),
            "initialize failed: {response}"
        );
    }

    /// Close stdin (EOF, the MCP stdio shutdown) and wait for the loop to end.
    async fn close(self) {
        self.close_then(async {}).await;
    }

    /// Close stdin, run `after_eof`, then wait for the loop to end.
    async fn close_then(self, after_eof: impl std::future::Future<Output = ()>) {
        drop(self.client);
        after_eof.await;
        timeout(ARRIVAL, self.task)
            .await
            .expect("the stdio loop did not end after EOF")
            .expect("the stdio loop panicked");
    }
}

/// Today's spend the next process would boot with, from `data_dir`: global,
/// for [`TOOL`], and for [`KEY`].
fn restored_daily(served_config: &Config, data_dir: &Path) -> (f64, Option<f64>, Option<f64>) {
    let (_, enforcer) = boot_cost_governance(&served_config.cost_governance, data_dir);
    let snap = enforcer.expect("governance is enabled").snapshot();
    (
        snap.global_daily_usd,
        snap.tool_daily.get(TOOL).copied(),
        snap.key_daily.get(KEY).copied(),
    )
}

/// R-EXIT: a call still in flight at EOF is drained, and its spend is on
/// disk once the loop ends. The save must follow the drain: the spend is
/// recorded only when the held answer arrives, after stdin has closed.
#[tokio::test]
async fn stdio_exit_saves_todays_spend() {
    let dir = tempfile::tempdir().expect("tempdir");
    let called = Arc::new(AtomicBool::new(false));
    let release = Arc::new(tokio::sync::Notify::new());
    let backend = spawn_backend(Arc::clone(&called), Arc::clone(&release)).await;
    let yaml = format!(
        "backends:\n  {BACKEND}:\n    http_url: \"{backend}\"\n    streamable_http: true\n{GOVERNANCE}"
    );
    let mut served = serve(dir.path(), &yaml).await;
    served.initialize().await;
    served
        .send(&json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "gateway_invoke", "arguments": {
                "server": BACKEND, "tool": TOOL, "arguments": {},
            }},
        }))
        .await;
    timeout(ARRIVAL, async {
        while !called.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("control: the call never reached the backend");
    let config = served.config.clone();
    // EOF first, with the backend still holding its answer. The answer is
    // released a hold after EOF (nothing outside the loop can observe the
    // loop reading EOF), so the spend is recorded during the drain and a
    // save made before the drain misses it.
    served
        .close_then(async {
            tokio::time::sleep(EOF_HOLD).await;
            release.notify_one();
        })
        .await;

    assert!(
        dir.path().join("costs.json").exists(),
        "the stdio exit wrote no costs.json"
    );
    let (global, tool, _) = restored_daily(&config, dir.path());
    assert!(
        (global - 0.6).abs() < 1e-9,
        "the stdio exit did not save the drained call's spend: the next boot reads {global}"
    );
    assert!(
        tool.is_some_and(|t| (t - 0.6).abs() < 1e-9),
        "the saved snapshot lost the per-tool spend: {tool:?}"
    );
}

/// R-PERIODIC: while stdin stays open, spend keeps reaching disk, not only at
/// the first interval. An interval skipped while a write still held the lock is
/// caught up by a later one (MIK-8157, MIK-8216).
#[tokio::test]
async fn stdio_saves_spend_periodically_before_exit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let costs = dir.path().join("costs.json");
    let mut seeded = PersistedCosts {
        saved_at: cost_persistence::now_secs(),
        ..PersistedCosts::default()
    };
    seeded.tool_totals.insert(
        TOOL.to_string(),
        ToolTotal {
            call_count: 0,
            total_cost_usd: 0.3,
            avg_cost_usd: 0.0,
        },
    );
    seeded.key_totals.insert(KEY.to_string(), 0.3);
    cost_persistence::save(&costs, &seeded).expect("seed costs.json");

    let mut served = serve(dir.path(), GOVERNANCE).await;
    // Boot is over once initialize is answered: the seeded spend is loaded.
    served.initialize().await;

    // Paused only now, so no timer inside the boot was advanced.
    tokio::time::pause();
    // Several ticks per round: see `advance_until_saved` (MIK-8216).
    for round in 1..=2 {
        std::fs::remove_file(&costs).expect("remove costs.json; only a save can bring it back");
        let landed = super::advance_until_saved(&costs).await;
        assert!(
            landed.is_ok(),
            "no periodic save in round {round} while stdin stayed open: the save {}",
            landed.err().unwrap_or_default()
        );
    }
    tokio::time::resume();
    let (global, tool, key) = restored_daily(&served.config, dir.path());
    assert!(
        (global - 0.3).abs() < 1e-9 && tool.is_some_and(|t| (t - 0.3).abs() < 1e-9),
        "the periodic save lost the loaded spend: global {global}, tool {tool:?}"
    );
    assert!(
        key.is_some_and(|k| (k - 0.3).abs() < 1e-9),
        "the periodic save lost the per-key spend: {key:?}"
    );
    served.close().await;
}
