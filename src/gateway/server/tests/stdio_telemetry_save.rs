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
//!
//! The saved window holds the process-wide counter registry, so in a test
//! binary it also carries other tests' observations. Counts are therefore
//! asserted as lower bounds (a missing save reads 0), and the drain-window
//! row tracks its own request by a revision label no other test sends.

use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::config::Config;
use crate::gateway::Gateway;
use crate::protocol_revision_telemetry::{
    Snapshot, durable_window_path, load_durable_window, write_seam,
};

/// Bound on every wait for a frame or a session end that must happen.
const ARRIVAL: Duration = Duration::from_secs(30);
/// Requests each row sends.
const PINGS: u64 = 20;
/// A saver interval no row outlives, so the only saves a row sees are the
/// ones it is about (MIK-8364).
const NO_TICK: Duration = Duration::from_secs(3600);
/// How long a stop may take with a dispatch hung: the drain deadline, the
/// teardown deadline, and room for the scheduler. A literal for the timing
/// lint; the assertion below keeps it above the deadlines it must cover.
const HUNG_STOP_BOUND: Duration = Duration::from_secs(70);
const _: () = assert!(
    HUNG_STOP_BOUND.as_secs()
        >= super::super::STDIO_DRAIN_TIMEOUT.as_secs()
            + super::super::stdio_shutdown::STDIO_TEARDOWN_TIMEOUT.as_secs()
            + 20,
    "HUNG_STOP_BOUND must cover the drain and teardown deadlines with room to spare"
);
/// The revision the drain-window row's held request names on `_meta`: a
/// measured label no other request-sending test uses, because the saved
/// window holds the process-wide registry (see the module note).
const HELD_REVISION: &str = "2024-10-07";

struct Session {
    client: DuplexStream,
    lines: Lines<BufReader<DuplexStream>>,
    task: JoinHandle<crate::Result<()>>,
    data: std::path::PathBuf,
    /// The pause at the start of this session's dispatches, and the notice
    /// that its drain has begun.
    hold: std::sync::Arc<crate::test_pause::Slot>,
    drain_started: std::sync::Arc<tokio::sync::Notify>,
    _dir: tempfile::TempDir,
}

impl Session {
    /// A stdio session whose saver never ticks during the row, and, when
    /// `trigger` is given, a stop the test can start as a signal would.
    async fn start(trigger: Option<&mut Option<tokio::sync::oneshot::Sender<()>>>) -> Self {
        Self::start_saving_every(trigger, NO_TICK).await
    }

    async fn start_saving_every(
        trigger: Option<&mut Option<tokio::sync::oneshot::Sender<()>>>,
        every: Duration,
    ) -> Self {
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
            .with_telemetry_save_interval(every);
        if let Some(slot) = trigger {
            *slot = Some(gateway.shutdown_trigger_for_test());
        }
        let (hold, drain_started) = gateway.stdio_drain_seams_for_test();
        let (client, input) = tokio::io::duplex(1 << 20);
        let (output, stdout) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(async move { gateway.run_stdio_on(input, output, None).await });
        Self {
            client,
            lines: BufReader::new(stdout).lines(),
            task,
            data,
            hold,
            drain_started,
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
        self.initialize().await;
        self.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
    }

    /// `initialize` alone, answered, with nothing else in flight after it.
    async fn initialize(&mut self) {
        self.send(
            &json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "mik8364", "version": "0"}}}),
        )
        .await;
        self.answer(0).await;
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
    async fn close(self) -> Snapshot {
        let Self {
            client,
            lines,
            task,
            data,
            _dir,
            ..
        } = self;
        drop(client);
        drop(lines);
        Self::end(task, &data).await
    }

    /// Wait for the session to end with stdin still open, so only a stop
    /// other than EOF can end it. Returns what the saved window holds.
    async fn wait_end(self) -> Snapshot {
        let Self {
            client,
            lines,
            task,
            data,
            _dir,
            ..
        } = self;
        let saved = Self::end(task, &data).await;
        drop((client, lines));
        saved
    }

    async fn end(task: JoinHandle<crate::Result<()>>, data: &std::path::Path) -> Snapshot {
        timeout(ARRIVAL, task)
            .await
            .expect("the session ends")
            .expect("no panic")
            .expect("Ok");
        load_durable_window(data)
            .expect("the window file reads")
            .snapshot
    }
}

/// Requests the saved window holds for the stdio transport.
fn stdio_requests(saved: &Snapshot) -> u64 {
    saved.by_transport.get("stdio").copied().unwrap_or(0)
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
    let saved = stdio_requests(&session.close().await);
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
    let saved = stdio_requests(&session.wait_end().await);
    assert!(
        saved > PINGS,
        "the window saved after a signal stop holds {saved} stdio requests; at least {} were observed",
        PINGS + 1
    );
}

/// SHUTDOWN.1 (drain window, review round 3): a request read before the stop
/// but not yet dispatched is observed during the drain, so the final save
/// must come after the drain. Held at the start of its dispatch, it is
/// released only once the drain has begun.
#[tokio::test]
async fn a_request_observed_during_the_drain_is_in_the_final_save() {
    let mut trigger = None;
    let mut session = Session::start(Some(&mut trigger)).await;
    // `initialize` only: a `notifications/initialized` dispatched after the
    // hold is armed would take the one-shot hold instead of the ping (seen
    // when a final save placed before the drain still passed this row).
    session.initialize().await;
    let (reached, release) = session.hold.arm();
    let reached = reached.notified();
    // Its own revision on `_meta`, so the final save can be checked for this
    // request: the handshake negotiated 2025-06-18.
    session
        .send(
            &json!({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {
            "_meta": {"io.modelcontextprotocol/protocolVersion": HELD_REVISION}}}),
        )
        .await;
    crate::test_pause::within("the ping reaching its dispatch hold", reached).await;
    let drain_started = std::sync::Arc::clone(&session.drain_started);
    let drained = drain_started.notified();
    trigger
        .take()
        .expect("the trigger was taken")
        .send(())
        .expect("the gateway holds the trigger's receiver");
    crate::test_pause::within("the drain starting after the stop", drained).await;
    release.notify_one();
    let saved = session.wait_end().await;
    assert!(
        saved.by_revision.get(HELD_REVISION).copied().unwrap_or(0) >= 1,
        "the request observed during the drain is missing from the final save: {saved:?}"
    );
}

/// The saver persists while the session runs: with a short interval, the
/// observed requests reach the window file with no stop at all.
#[tokio::test]
async fn the_saver_persists_observed_requests_while_the_session_runs() {
    let mut session = Session::start_saving_every(None, Duration::from_millis(50)).await;
    session.handshake().await;
    session.pings().await;
    let data = session.data.clone();
    let saved = crate::test_pause::within("the saver writing the observed requests", async {
        loop {
            let saved = load_durable_window(&data)
                .map(|window| stdio_requests(&window.snapshot))
                .unwrap_or(0);
            if saved > PINGS {
                return saved;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(saved > PINGS, "the saver wrote {saved} stdio requests");
    drop(session.client);
}

/// SHUTDOWN.1 (Option A condition): a dispatch that never completes cannot
/// keep a stop from ending the session. The drain gives up at its deadline,
/// the teardown is bounded, and the final save still lands.
#[tokio::test]
async fn a_stop_with_a_hung_dispatch_still_ends_and_saves() {
    let mut trigger = None;
    let mut session = Session::start(Some(&mut trigger)).await;
    session.initialize().await;
    // Armed and never released: this dispatch hangs for the rest of the row.
    let (reached, _never) = session.hold.arm();
    let reached = reached.notified();
    session
        .send(&json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
        .await;
    crate::test_pause::within("the ping reaching its dispatch hold", reached).await;
    trigger
        .take()
        .expect("the trigger was taken")
        .send(())
        .expect("the gateway holds the trigger's receiver");
    let Session {
        task, data, _dir, ..
    } = session;
    timeout(HUNG_STOP_BOUND, task)
        .await
        .expect("a stop with a hung dispatch still ends the session")
        .expect("no panic")
        .expect("Ok");
    let saved = load_durable_window(&data)
        .expect("the window file reads")
        .snapshot;
    assert!(
        stdio_requests(&saved) >= 1,
        "the final save after a hung dispatch holds no stdio request: {saved:?}"
    );
}
