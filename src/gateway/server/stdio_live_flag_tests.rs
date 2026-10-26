// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `security.sanitize_input` over stdio follows a reload (ADR-023).
//!
//! Driven through the real stdio serve path and its `gateway_reload_config`
//! tool. Each line takes the generation current when it is read, and keeps it
//! for its whole dispatch.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, DuplexStream};

use crate::config::Config;
use crate::gateway::server::Gateway;
use crate::gateway::test_helpers::write_owner_only;
use crate::test_pause::Slot;

const NUL: &str = "a\u{0}b";

/// The config with `sanitize_input` = `on`, and a task store in the test's
/// own directory (the harness refuses the real one).
fn write_flag(path: &Path, on: bool) {
    let tasks = path.with_file_name("tasks");
    let tasks = tasks.display().to_string().replace('\'', "''");
    write_owner_only(
        path,
        format!("security:\n  sanitize_input: {on}\ntasks:\n  store_dir: '{tasks}'\n"),
    )
    .expect("write");
}

struct Session {
    client: DuplexStream,
    reader: tokio::io::BufReader<DuplexStream>,
    hold: Arc<Slot>,
    task: tokio::task::JoinHandle<()>,
    next_id: u64,
}

impl Session {
    async fn start(dir: &Path, path: std::path::PathBuf) -> Self {
        let config = Config::load(Some(&path)).expect("loads");
        let gateway = Gateway::new_with_path(config, Some(path))
            .await
            .expect("valid config")
            .with_data_dir(dir.to_path_buf());
        let (hold, _) = gateway.stdio_drain_seams_for_test();
        let (client, input) = tokio::io::duplex(64 * 1024);
        let (output, reader) = tokio::io::duplex(1 << 20);
        let task =
            tokio::spawn(async move { drop(gateway.run_stdio_on(input, output, None).await) });
        let mut session = Self {
            client,
            reader: tokio::io::BufReader::new(reader),
            hold,
            task,
            next_id: 1,
        };
        let id = session
            .send(
                "initialize",
                json!({"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "adr-023", "version": "0"}}),
            )
            .await;
        session.answer(id).await;
        let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        session
            .client
            .write_all(format!("{note}\n").as_bytes())
            .await
            .expect("write");
        session
    }

    async fn send(&mut self, method: &str, params: Value) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let req = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.client
            .write_all(format!("{req}\n").as_bytes())
            .await
            .expect("write");
        id
    }

    /// The response to `id`, skipping notifications and other answers.
    async fn answer(&mut self, id: u64) -> Value {
        loop {
            let mut line = String::new();
            let n = tokio::time::timeout(Duration::from_secs(30), self.reader.read_line(&mut line))
                .await
                .expect("a response within 30 s")
                .expect("read");
            assert!(n > 0, "the gateway closed its output");
            let msg: Value = serde_json::from_str(&line).expect("json");
            if msg["id"] == json!(id) {
                return msg;
            }
        }
    }

    async fn reload(&mut self) {
        let id = self
            .send(
                "tools/call",
                json!({"name": "gateway_reload_config", "arguments": {}}),
            )
            .await;
        let reply = self.answer(id).await;
        assert!(reply.get("error").is_none(), "reload refused: {reply}");
        assert_ne!(reply["result"]["isError"], true, "reload failed: {reply}");
    }

    /// A `gateway_invoke` whose argument carries a NUL; sent, not awaited.
    async fn send_nul(&mut self) -> u64 {
        self.send(
            "tools/call",
            json!({"name": "gateway_invoke",
                   "arguments": {"server": "absent", "tool": "t", "arguments": {"cmd": NUL}}}),
        )
        .await
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Refused by the sanitiser, as opposed to failing later for another reason.
fn sanitised(reply: &Value) -> bool {
    reply.to_string().contains("null bytes")
}

/// F2: over stdio, a reload turns sanitising off and on again, each applying
/// to the next call, with no restart.
#[tokio::test]
async fn f2_stdio_sanitise_input_follows_a_reload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_flag(&path, true);
    let mut s = Session::start(dir.path(), path.clone()).await;

    let id = s.send_nul().await;
    let reply = s.answer(id).await;
    assert!(sanitised(&reply), "on at start: {reply}");

    write_flag(&path, false);
    s.reload().await;
    let id = s.send_nul().await;
    let reply = s.answer(id).await;
    assert!(!sanitised(&reply), "off after reload: {reply}");

    write_flag(&path, true);
    s.reload().await;
    let id = s.send_nul().await;
    let reply = s.answer(id).await;
    assert!(sanitised(&reply), "on after reload: {reply}");
}

/// Hold the next line's dispatch, flip the flag by a reload on another line,
/// release, and return the held line's answer.
async fn held_across_a_flip(s: &mut Session, path: &Path, to: bool) -> Value {
    let (reached, release) = s.hold.arm();
    let held = s.send_nul().await;
    crate::test_pause::within("the held line reaches the pause", reached.notified()).await;
    write_flag(path, to);
    s.reload().await;
    release.notify_one();
    s.answer(held).await
}

/// G4: a line read while sanitising is on is judged on, even when a reload
/// turns it off before the line dispatches; and the reverse.
#[tokio::test]
async fn g4_a_held_stdio_line_keeps_the_generation_it_was_read_under() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_flag(&path, true);
    let mut s = Session::start(dir.path(), path.clone()).await;

    let reply = held_across_a_flip(&mut s, &path, false).await;
    assert!(sanitised(&reply), "on then off: {reply}");

    let reply = held_across_a_flip(&mut s, &path, true).await;
    assert!(!sanitised(&reply), "off then on: {reply}");
}
