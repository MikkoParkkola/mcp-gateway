// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The HTTP gateway saves today's cost-governance spend on its interval,
//! not only at shutdown.
//!
//! `Gateway::run` is driven in process on a loopback port with the data
//! directory pointed at a tempdir. Once it serves, the clock is paused and
//! moved past the save interval; the removed `costs.json` must come back
//! while the server is still running. The task is then aborted, so no
//! shutdown save can stand in for the periodic one.
//!
//! The case computes "today" when it runs; one that straddles UTC midnight
//! sees the loader drop the seeded day.

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::Config;
use crate::cost_accounting::persistence::{self as cost_persistence, PersistedCosts, ToolTotal};
use crate::gateway::Gateway;
use crate::gateway::server::persistence::boot_cost_governance;

async fn answers_livez(port: u16) -> bool {
    let Ok(mut stream) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await else {
        return false;
    };
    let request =
        format!("GET /livez HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    let mut answer = String::new();
    stream.write_all(request.as_bytes()).await.is_ok()
        && stream.read_to_string(&mut answer).await.is_ok()
        && answer.starts_with("HTTP/1.1 200")
}

fn seed(costs: &Path) {
    let mut seeded = PersistedCosts {
        saved_at: cost_persistence::now_secs(),
        ..PersistedCosts::default()
    };
    seeded.tool_totals.insert(
        "seeded_tool".to_string(),
        ToolTotal {
            call_count: 0,
            total_cost_usd: 0.3,
            avg_cost_usd: 0.0,
        },
    );
    cost_persistence::save(costs, &seeded).expect("seed costs.json");
}

#[tokio::test]
async fn http_saves_spend_periodically_while_serving() {
    let dir = tempfile::tempdir().expect("tempdir");
    let costs = dir.path().join("costs.json");
    seed(&costs);
    let yaml = format!(
        "server:\n  host: 127.0.0.1\n  port: 0\nauth:\n  enabled: false\n\
         cost_governance:\n  enabled: true\n  budgets:\n    daily: 10.0\n\
         tasks:\n  store_dir: {}\n",
        dir.path().join("tasks").display()
    );
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    let config = Config::load(Some(&path)).expect("config loads");
    let mut gateway = Gateway::new(config.clone())
        .await
        .expect("gateway boots")
        .with_data_dir(dir.path().to_path_buf());
    let bound = gateway.bound_port_for_test();
    let server = tokio::spawn(async move { drop(Box::pin(gateway.run()).await) });
    let port = tokio::time::timeout(Duration::from_secs(60), bound)
        .await
        .expect("the HTTP gateway bound a port")
        .expect("the gateway reports the port it bound");

    // Real time until the server answers: boot timers run as in production.
    let listening = tokio::time::timeout(Duration::from_secs(60), async {
        while !answers_livez(port).await {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(listening.is_ok(), "the HTTP gateway never answered /livez");

    std::fs::remove_file(&costs).expect("remove costs.json; only a save can bring it back");
    tokio::time::pause();
    // Read on the paused clock, so only an advanced interval can explain it;
    // several ticks: see `advance_until_saved` (MIK-8216).
    let saved = super::advance_until_saved(&costs).await;
    tokio::time::resume();
    // Still serving: a server that had stopped would have made its shutdown
    // save, which must not pass for the periodic one.
    let still_serving = !server.is_finished()
        && tokio::time::timeout(Duration::from_secs(10), answers_livez(port))
            .await
            .unwrap_or(false);
    // Aborted, not shut down: no shutdown save can stand in for the periodic one.
    server.abort();
    drop(server.await);
    assert!(
        still_serving,
        "control: the HTTP gateway stopped serving, so a shutdown save could explain the file"
    );
    assert!(
        saved.is_ok(),
        "the HTTP gateway made no periodic save while serving: the save {}",
        saved.err().unwrap_or_default()
    );
    let (_, enforcer) = boot_cost_governance(&config.cost_governance, dir.path());
    let global = enforcer
        .expect("governance is enabled")
        .snapshot()
        .global_daily_usd;
    assert!(
        (global - 0.3).abs() < 1e-9,
        "the periodic save lost the loaded spend: the next boot reads {global}"
    );
}
