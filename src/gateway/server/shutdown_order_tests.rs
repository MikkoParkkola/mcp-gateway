// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8156: `run`'s graceful shutdown, started the way a signal starts it.
//!
//! Every other test that drives `run` ends it with `abort()`, which skips the
//! whole shutdown sequence. This one sends the shutdown trigger while it holds
//! a request open, and checks the operations themselves, not their log lines:
//! the backends are not stopped while that request is in flight, they are
//! stopped once it ends, and `run` returns Ok.

use std::sync::Arc;
use std::time::Duration;

use super::super::Gateway;
use crate::config::Config;

fn config(dir: &std::path::Path) -> Config {
    let mut config = Config::default();
    config.server.host = "127.0.0.1".to_string();
    // Port 0: the gateway reports the port it bound (MIK-7984).
    config.server.port = 0;
    // Far longer than the test holds its request, so only the request's end,
    // never the drain's timeout, can let the shutdown past the drain.
    config.server.shutdown_timeout = Duration::from_secs(30);
    // The task store under the test's own directory, never the default under $HOME.
    config.tasks.store_dir = dir.join("tasks").to_string_lossy().into_owned();
    config
}

#[tokio::test]
async fn a_triggered_shutdown_drains_then_stops_the_backends_and_returns_ok() {
    let dir = tempfile::tempdir().unwrap();
    let mut gateway = Gateway::new(config(dir.path()))
        .await
        .unwrap()
        .with_data_dir(dir.path().to_path_buf());
    let bound = gateway.bound_port_for_test();
    let gate = gateway.inflight_for_test();
    let trigger = gateway.shutdown_trigger_for_test();
    let backends = Arc::clone(&gateway.backends);
    let server = tokio::spawn(async move { Box::pin(gateway.run()).await });

    tokio::time::timeout(Duration::from_secs(60), bound)
        .await
        .expect("the gateway binds within a minute")
        .expect("the gateway reports the port it bound");
    let gate = gate.await.expect("run hands over its in-flight gate");
    // A request in flight, as a handler holds it.
    let request = Arc::clone(&gate)
        .acquire_owned()
        .await
        .expect("the gate is open before shutdown");

    trigger.send(()).expect("run still holds the trigger");
    // The drain is waiting once it has taken every permit but the held one.
    tokio::time::timeout(Duration::from_secs(20), async {
        while gate.available_permits() > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the shutdown reaches the drain");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !backends.is_stopping(),
        "the backends are stopped while a request is still in flight"
    );

    drop(request);
    let ended = tokio::time::timeout(Duration::from_secs(30), server)
        .await
        .expect("run returns once the request ends")
        .expect("run does not panic");
    assert!(ended.is_ok(), "a graceful shutdown returns Ok: {ended:?}");
    assert!(
        backends.is_stopping(),
        "the backends are stopped before run returns"
    );
}
