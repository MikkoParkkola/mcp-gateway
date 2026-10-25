// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8854 T13: a call counted by one gateway run is still counted after a
//! graceful shutdown and a restart on the same data directory, and the
//! restart is marked.

use std::time::Duration;

use super::super::Gateway;
use crate::config::Config;
use crate::counters::{CounterStore, Filter, MarkerKind, Metric, Query, Window};

fn config(dir: &std::path::Path) -> Config {
    let mut config = Config::default();
    config.server.host = "127.0.0.1".to_string();
    config.server.port = 0;
    config.tasks.store_dir = dir.join("tasks").to_string_lossy().into_owned();
    config
}

/// Run a gateway on `dir` until a triggered shutdown, sending one
/// `gateway_invoke` first when `call` is set.
async fn run_once(dir: &std::path::Path, call: bool) {
    let mut gateway = Gateway::new(config(dir))
        .await
        .unwrap()
        .with_data_dir(dir.to_path_buf());
    let bound = gateway.bound_port_for_test();
    let trigger = gateway.shutdown_trigger_for_test();
    let server = tokio::spawn(async move { Box::pin(gateway.run()).await });
    let port = tokio::time::timeout(Duration::from_secs(60), bound)
        .await
        .expect("the gateway binds within a minute")
        .expect("the gateway reports the port it bound");
    if call {
        let body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "gateway_invoke",
                       "arguments": {"server": "nope", "tool": "t", "arguments": {}},
                       "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                 "io.modelcontextprotocol/clientCapabilities": {}}}});
        let response = reqwest::Client::new()
            .post(format!("http://127.0.0.1:{port}/mcp"))
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", "tools/call")
            .header("mcp-name", "gateway_invoke")
            .json(&body)
            .send()
            .await
            .expect("the call is answered");
        assert!(response.status().is_success() || response.status().is_client_error());
    }
    trigger.send(()).expect("run still holds the trigger");
    let ended = tokio::time::timeout(Duration::from_secs(30), server)
        .await
        .expect("run returns after the trigger")
        .expect("run does not panic");
    assert!(ended.is_ok(), "{ended:?}");
}

fn saved(dir: &std::path::Path) -> CounterStore {
    let bytes = std::fs::read(dir.join("counters.json")).expect("counters.json was saved");
    let now = crate::clock::unix_secs().expect("a readable clock");
    CounterStore::from_bytes(&bytes, now, env!("CARGO_PKG_VERSION"), &chrono::Local)
        .expect("a valid file")
        .0
}

fn calls(store: &CounterStore) -> u64 {
    let now = crate::clock::unix_secs().expect("a readable clock");
    store
        .series(
            &Query::new(Metric::Calls, Window::Day, Filter::All),
            now,
            &chrono::Local,
        )
        .points
        .iter()
        .map(|p| p.v)
        .sum()
}

#[tokio::test]
async fn t13_a_counted_call_survives_a_restart_and_the_restart_is_marked() {
    let dir = tempfile::tempdir().unwrap();
    run_once(dir.path(), true).await;
    let first = saved(dir.path());
    assert_eq!(calls(&first), 1, "the shutdown save holds the call");
    let since = first.since();
    run_once(dir.path(), false).await;
    let second = saved(dir.path());
    assert_eq!(calls(&second), 1, "the restart kept it");
    assert_eq!(second.since(), since, "coverage did not restart");
    let kinds: Vec<MarkerKind> = second.markers(0).into_iter().map(|m| m.kind).collect();
    assert_eq!(kinds, vec![MarkerKind::Restart]);
}
