// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8054`: a backend added or replaced by hot reload is warm-started like
//! one present at boot, so its tools reach the shared cache without waiting
//! for a discovery call to fill it.
//!
//! Driven through the real stdio serve path and its `gateway_reload_config`
//! tool, so the wiring between reload and warm-start is what is tested.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, DuplexStream};

use crate::backend::BackendRegistry;
use crate::config::Config;
use crate::gateway::server::Gateway;

/// A minimal MCP server over plain HTTP JSON: `initialize` and one tool.
async fn mock(tool: &'static str) -> String {
    use axum::Json;
    use axum::routing::post;

    let app = axum::Router::new().route(
        "/mcp",
        post(move |Json(req): Json<serde_json::Value>| async move {
            let id = req["id"].clone();
            Json(match req["method"].as_str().unwrap_or("") {
                "initialize" => serde_json::json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                               "serverInfo": {"name": "mock", "version": "0"}}}),
                "tools/list" => serde_json::json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": {"tools": [{"name": tool, "description": "a tool",
                               "inputSchema": {"type": "object", "properties": {}}}]}}),
                _ => serde_json::json!({
                    "jsonrpc": "2.0", "id": id,
                    "error": {"code": -32601, "message": "Method not found"}}),
            })
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { drop(axum::serve(listener, app).await) });
    format!("http://{addr}/mcp")
}

/// The gateway config file, with `backends` as given (YAML mapping body).
fn write_config(dir: &Path, backends: &str) -> std::path::PathBuf {
    let path = dir.join("gateway.yaml");
    let tasks = dir.join("tasks");
    // Owner-only: config loading refuses a file other users can read. The
    // path is single-quoted YAML: backslashes stay literal, apostrophes double.
    crate::gateway::test_helpers::write_owner_only(
        &path,
        format!(
            "meta_mcp:\n  enabled: true\ntasks:\n  store_dir: '{}'\nbackends:{backends}\n",
            tasks.display().to_string().replace('\'', "''")
        ),
    )
    .unwrap();
    path
}

fn http_backend(name: &str, url: &str) -> String {
    format!("\n  {name}:\n    http_url: \"{url}\"\n")
}

/// A stdio gateway on in-memory pipes, its registry, and the client end.
struct Running {
    registry: Arc<BackendRegistry>,
    client: DuplexStream,
    reader: tokio::io::BufReader<DuplexStream>,
    task: tokio::task::JoinHandle<()>,
    next_id: u64,
}

impl Running {
    async fn start(dir: &Path, config_path: std::path::PathBuf) -> Self {
        let config = Config::load(Some(&config_path)).expect("the fixture config loads");
        let gateway = Gateway::new_with_path(config, Some(config_path))
            .await
            .expect("valid config")
            .with_data_dir(dir.to_path_buf());
        let registry = Arc::clone(&gateway.backends);
        let (client, input) = tokio::io::duplex(64 * 1024);
        let (output, reader) = tokio::io::duplex(1 << 20);
        let task =
            tokio::spawn(async move { drop(gateway.run_stdio_on(input, output, None).await) });
        let mut running = Self {
            registry,
            client,
            reader: tokio::io::BufReader::new(reader),
            task,
            next_id: 1,
        };
        running
            .call(
                "initialize",
                serde_json::json!({"protocolVersion": "2025-06-18", "capabilities": {},
                                   "clientInfo": {"name": "mik-8054", "version": "0"}}),
            )
            .await;
        let note = serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        running
            .client
            .write_all(format!("{note}\n").as_bytes())
            .await
            .unwrap();
        running
    }

    /// Send one request and return its response (skipping notifications).
    async fn call(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        let id = self.next_id;
        self.next_id += 1;
        let req =
            serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.client
            .write_all(format!("{req}\n").as_bytes())
            .await
            .unwrap();
        loop {
            let mut line = String::new();
            let n = tokio::time::timeout(Duration::from_secs(30), self.reader.read_line(&mut line))
                .await
                .expect("a response within 30 s")
                .unwrap();
            assert!(n > 0, "the gateway closed its output");
            let msg: serde_json::Value = serde_json::from_str(&line).unwrap();
            if msg["id"] == serde_json::json!(id) {
                return msg;
            }
        }
    }

    async fn reload(&mut self) {
        let reply = self
            .call(
                "tools/call",
                serde_json::json!({"name": "gateway_reload_config", "arguments": {}}),
            )
            .await;
        assert!(reply.get("error").is_none(), "reload refused: {reply}");
        assert_ne!(reply["result"]["isError"], true, "reload failed: {reply}");
    }

    /// Whether `name`'s CURRENT instance caches `tool` within `secs`, with no
    /// discovery or direct call made in the meantime.
    async fn warms(&self, name: &str, tool: &str, secs: u64) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        while tokio::time::Instant::now() < deadline {
            if self.registry.get(name).is_some_and(|b| caches(&b, tool)) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
}

/// Whether `backend` has `tool` in its shared tool cache.
fn caches(backend: &crate::backend::Backend, tool: &str) -> bool {
    backend
        .get_cached_tools_snapshot()
        .iter()
        .any(|t| t.name == tool)
}

impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// `MIK-8054.WARM.1`: a backend added by hot reload is warmed without a
/// discovery call, as one present at boot is.
#[tokio::test]
async fn a_backend_added_by_hot_reload_is_warmed() {
    let dir = tempfile::tempdir().unwrap();
    let boot = mock("boot_tool").await;
    let path = write_config(dir.path(), &http_backend("boot", &boot));
    let mut gw = Running::start(dir.path(), path).await;
    // Control: the same fixture warms when present at boot, so a failure
    // below is the missing reload warm-start, not a fixture the gateway
    // cannot talk to.
    assert!(
        gw.warms("boot", "boot_tool", 10).await,
        "boot warm-start control"
    );
    let url = mock("added_tool").await;
    let both = format!(
        "{}{}",
        http_backend("boot", &boot),
        http_backend("added", &url)
    );
    write_config(dir.path(), &both);
    gw.reload().await;
    assert!(
        gw.registry.get("added").is_some(),
        "the reload registered it"
    );
    assert!(
        gw.warms("added", "added_tool", 10).await,
        "a hot-added backend's tools never reached the cache without a discovery call"
    );
}

/// `MIK-8054.WARM.2`: a backend replaced by hot reload is warmed again; its
/// boot warm-start already finished, so nothing else fills the new instance.
#[tokio::test]
async fn a_backend_replaced_by_hot_reload_is_warmed_again() {
    let dir = tempfile::tempdir().unwrap();
    let first = mock("first_tool").await;
    let path = write_config(dir.path(), &http_backend("svc", &first));
    let mut gw = Running::start(dir.path(), path).await;
    assert!(
        gw.warms("svc", "first_tool", 10).await,
        "boot warm-start control"
    );
    let second = mock("second_tool").await;
    write_config(dir.path(), &http_backend("svc", &second));
    gw.reload().await;
    assert!(
        gw.warms("svc", "second_tool", 10).await,
        "a hot-replaced backend's tools never reached the cache without a discovery call"
    );
}

/// `MIK-8054` wiring (HTTP): an edit the config watcher picks up warms the
/// backend it adds. Linux-only, as the other real-watcher rows (inotify).
#[cfg(target_os = "linux")]
#[tokio::test]
async fn http_a_backend_added_by_a_watched_edit_is_warmed() {
    let dir = tempfile::tempdir().unwrap();
    let boot = mock("boot_tool").await;
    let path = write_config(dir.path(), &http_backend("boot", &boot));
    let mut config = Config::load(Some(&path)).expect("the fixture config loads");
    config.server.host = "127.0.0.1".to_string();
    // Port 0: the gateway reports the port it bound (MIK-7984).
    config.server.port = 0;
    let mut gateway = Gateway::new_with_path(config, Some(path))
        .await
        .expect("valid config")
        .with_data_dir(dir.path().to_path_buf());
    let registry = Arc::clone(&gateway.backends);
    let bound = gateway.bound_port_for_test();
    let server = tokio::spawn(async move { drop(Box::pin(gateway.run()).await) });
    tokio::time::timeout(Duration::from_secs(60), bound)
        .await
        .expect("the gateway bound within 60 s")
        .expect("the gateway bound");
    let warmed = |name: &'static str, tool: &'static str| {
        let registry = Arc::clone(&registry);
        async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
            while tokio::time::Instant::now() < deadline {
                if registry.get(name).is_some_and(|b| caches(&b, tool)) {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            false
        }
    };
    let control = warmed("boot", "boot_tool").await;
    let url = mock("added_tool").await;
    let both = format!(
        "{}{}",
        http_backend("boot", &boot),
        http_backend("added", &url)
    );
    write_config(dir.path(), &both);
    let added = warmed("added", "added_tool").await;
    server.abort();
    assert!(control, "boot warm-start control");
    assert!(added, "a backend added by a watched edit was not warmed");
}
