// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8364: a stdio request does not write the protocol-revision telemetry
//! window; the window is saved off the request path and on every graceful
//! stop.
//!
//! Driven in process through `Gateway::run_stdio_on` over in-memory pipes,
//! with the data directory in a tempdir. Writes are counted per window file
//! by `durable::write_seam`, and the saved counts are read back with
//! `load_durable_window`, the loader an operator's report uses.

use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::config::Config;
use crate::gateway::Gateway;
use crate::protocol_revision_telemetry::{durable_window_path, load_durable_window, write_seam};

/// Bound on every wait for a frame or a session end that must happen.
const ARRIVAL: Duration = Duration::from_secs(30);
/// Requests each row sends.
const PINGS: u64 = 20;
/// A saver interval no row outlives, so the only saves a row sees are the
/// ones it is about (MIK-8364).
const NO_TICK: Duration = Duration::from_secs(3600);

struct Session {
    client: DuplexStream,
    lines: Lines<BufReader<DuplexStream>>,
    task: JoinHandle<crate::Result<()>>,
    data: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

impl Session {
    /// A stdio session whose saver never ticks during the row, and, when
    /// `trigger` is given, a stop the test can start as a signal would.
    async fn start(trigger: Option<&mut Option<tokio::sync::oneshot::Sender<()>>>) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        // A temp task store: a test must never open the operator's real one.
        let tasks = dir.path().join("tasks");
        let yaml = format!(
            "tasks:\n  store_dir: {}\n",
            serde_json::to_string(&tasks.display().to_string()).expect("a JSON string")
        );
        crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
        let evaluated = Config::load_evaluated(Some(&path)).expect("config evaluates");
        let env = std::sync::Arc::new(crate::config::LiveEnv::new(
            evaluated.overlay,
            evaluated.env_paths,
        ));
        let data = dir.path().join("data");
        let mut gateway = Gateway::new_with_env(evaluated.config, env, Some(path))
            .await
            .expect("gateway boots")
            .with_data_dir(data.clone())
            .with_telemetry_save_interval(NO_TICK);
        if let Some(slot) = trigger {
            *slot = Some(gateway.shutdown_trigger_for_test());
        }
        let (client, input) = tokio::io::duplex(1 << 20);
        let (output, stdout) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(async move { gateway.run_stdio_on(input, output, None).await });
        Self {
            client,
            lines: BufReader::new(stdout).lines(),
            task,
            data,
            _dir: dir,
        }
    }

    async fn send(&mut self, frame: &Value) {
        let mut line = serde_json::to_vec(frame).expect("a frame serialises");
        line.push(b'\n');
        self.client
            .write_all(&line)
            .await
            .expect("stdin accepts the frame");
    }

    /// The answer to `id`, skipping notifications.
    async fn answer(&mut self, id: u64) -> Value {
        loop {
            let line = timeout(ARRIVAL, self.lines.next_line())
                .await
                .expect("an answer arrives")
                .expect("stdout reads")
                .expect("stdout stays open");
            let frame: Value = serde_json::from_str(&line).expect("a JSON frame");
            if frame["id"] == json!(id) {
                return frame;
            }
        }
    }

    async fn handshake(&mut self) {
        self.send(
            &json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "mik8364", "version": "0"}}}),
        )
        .await;
        self.answer(0).await;
        self.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
    }

    async fn pings(&mut self) {
        for id in 1..=PINGS {
            self.send(&json!({"jsonrpc": "2.0", "id": id, "method": "ping"}))
                .await;
            self.answer(id).await;
        }
    }

    fn window_writes(&self) -> usize {
        write_seam::writes(&durable_window_path(&self.data))
    }

    /// Close stdin, then wait for the session to end. Returns what the saved
    /// window holds; the tempdir lives until it is read.
    async fn close(self) -> u64 {
        let Self {
            client,
            lines,
            task,
            data,
            _dir,
        } = self;
        drop(client);
        drop(lines);
        Self::end(task, &data).await
    }

    /// Wait for the session to end with stdin still open, so only a stop
    /// other than EOF can end it. Returns what the saved window holds.
    async fn wait_end(self) -> u64 {
        let Self {
            client,
            lines,
            task,
            data,
            _dir,
        } = self;
        let saved = Self::end(task, &data).await;
        drop((client, lines));
        saved
    }

    async fn end(task: JoinHandle<crate::Result<()>>, data: &std::path::Path) -> u64 {
        timeout(ARRIVAL, task)
            .await
            .expect("the session ends")
            .expect("no panic")
            .expect("Ok");
        saved_stdio_requests(data)
    }
}

/// Requests the saved window under `data` holds for the stdio transport.
fn saved_stdio_requests(data: &std::path::Path) -> u64 {
    load_durable_window(data)
        .expect("the window file reads")
        .snapshot
        .by_transport
        .get("stdio")
        .copied()
        .unwrap_or(0)
}

/// ASYNC.1: answering requests writes no telemetry window. Every request
/// used to persist the window synchronously under the sink lock, which cost
/// ~7-18 ms per request on a real disk and serialised them (MIK-8364).
#[tokio::test]
async fn a_stdio_request_writes_no_telemetry_window() {
    let mut session = Session::start(None).await;
    session.handshake().await;
    let before = session.window_writes();
    session.pings().await;
    let written = session.window_writes() - before;
    assert_eq!(
        written, 0,
        "{PINGS} answered stdio requests wrote the telemetry window {written} times on the request path"
    );
    drop(session.client);
}

/// SHUTDOWN.1 (stdin EOF): every request observed before EOF is in the saved
/// window, although the saver never ticked.
#[tokio::test]
async fn stdin_eof_saves_every_observed_request() {
    let mut session = Session::start(None).await;
    session.handshake().await;
    session.pings().await;
    let saved = session.close().await;
    assert!(
        saved > PINGS,
        "the window saved at EOF holds {saved} stdio requests; at least {} were observed",
        PINGS + 1
    );
}

/// SHUTDOWN.1 (signal): a stop started as Ctrl+C or SIGTERM would (the
/// test's trigger) ends the stdio session through its graceful path and saves
/// every observed request. Before MIK-8364 stdio had no signal handler, so
/// the session ran on.
#[tokio::test]
async fn a_signal_stop_ends_stdio_and_saves_every_observed_request() {
    let mut trigger = None;
    let mut session = Session::start(Some(&mut trigger)).await;
    session.handshake().await;
    session.pings().await;
    trigger
        .take()
        .expect("the trigger was taken")
        .send(())
        .expect("the gateway holds the trigger's receiver");
    let saved = session.wait_end().await;
    assert!(
        saved > PINGS,
        "the window saved after a signal stop holds {saved} stdio requests; at least {} were observed",
        PINGS + 1
    );
}
