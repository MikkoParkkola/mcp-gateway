// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8156: `run`'s graceful shutdown, started the way a signal starts it.
//!
//! Every other test that drives `run` ends it with `abort()`, which skips the
//! whole shutdown sequence. This one sends the shutdown trigger and checks
//! that `run` returns Ok, draining in-flight requests before it stops the
//! backends.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::super::Gateway;
use crate::config::Config;

/// An INFO-and-above log capture for the current thread. The test runs on a
/// current-thread runtime, so the spawned `run` task logs under it. A
/// process-wide registry keeps every callsite's interest open, so an info line
/// is never filtered out by an interest cached on another thread.
fn capture() -> (tracing::subscriber::DefaultGuard, Arc<Mutex<Vec<u8>>>) {
    static INTEREST: std::sync::Once = std::sync::Once::new();
    struct W(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for W {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    INTEREST.call_once(|| {
        use tracing_subscriber::prelude::*;
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::Registry::default()
                .with(tracing::level_filters::LevelFilter::TRACE),
        );
    });
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&buffer);
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || W(Arc::clone(&writer)))
        .finish();
    (tracing::subscriber::set_default(subscriber), buffer)
}

fn config(dir: &std::path::Path) -> Config {
    let mut config = Config::default();
    config.server.host = "127.0.0.1".to_string();
    // Port 0: the gateway reports the port it bound (MIK-7984).
    config.server.port = 0;
    config.server.shutdown_timeout = Duration::from_secs(5);
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
    let trigger = gateway.shutdown_trigger_for_test();
    let (_guard, logs) = capture();
    let server = tokio::spawn(async move { Box::pin(gateway.run()).await });

    let port = tokio::time::timeout(Duration::from_secs(60), bound)
        .await
        .expect("the gateway binds within a minute")
        .expect("the gateway reports the port it bound");
    tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("the gateway accepts a connection before shutdown");

    trigger.send(()).expect("run still holds the trigger");
    let ended = tokio::time::timeout(Duration::from_secs(30), server)
        .await
        .expect("run returns within the drain timeout and its cleanup")
        .expect("run does not panic");
    assert!(ended.is_ok(), "a graceful shutdown returns Ok: {ended:?}");

    let text = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
    let drain = text.find("Draining in-flight requests");
    let stop = text.find("Shutting down backends");
    assert!(
        matches!((drain, stop), (Some(d), Some(s)) if d < s),
        "drain precedes the backend stop: {text}"
    );
}
