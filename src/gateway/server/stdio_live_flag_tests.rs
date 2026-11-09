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

/// Whether a session sends `notifications/initialized` after `initialize`.
#[derive(PartialEq, Eq)]
enum Announce {
    Yes,
    No,
}

struct Session {
    client: DuplexStream,
    reader: tokio::io::BufReader<DuplexStream>,
    hold: Arc<Slot>,
    /// The config this session serves and reloads.
    live: Arc<crate::config_reload::LiveConfig>,
    task: tokio::task::JoinHandle<()>,
    next_id: u64,
    /// The Meta-MCP the session serves.
    #[cfg_attr(not(feature = "firewall"), allow(dead_code))]
    meta: Arc<crate::gateway::meta_mcp::MetaMcp>,
}

impl Session {
    /// A session on `path`. `announce` sends `notifications/initialized`;
    /// a held row leaves it out, because every line but `initialize` passes
    /// the one-shot dispatch pause (`stdio_loop.rs`, `hold.pause()`), and a
    /// notification still in flight when the row arms it would take the
    /// pause in place of the row's own line.
    async fn start(dir: &Path, path: std::path::PathBuf, announce: Announce) -> Self {
        Self::start_with(dir, path, announce, |_| {}).await
    }

    /// [`Self::start`], after `setup` has seen the built gateway (a row
    /// registering a backend of its own).
    async fn start_with(
        dir: &Path,
        path: std::path::PathBuf,
        announce: Announce,
        setup: impl FnOnce(&Gateway),
    ) -> Self {
        let config = Config::load(Some(&path)).expect("loads");
        let mut gateway = Gateway::new_with_path(config, Some(path))
            .await
            .expect("valid config")
            .with_data_dir(dir.to_path_buf());
        setup(&gateway);
        let (hold, _) = gateway.stdio_drain_seams_for_test();
        let meta = gateway.stdio_meta_mcp_for_test();
        let (client, input) = tokio::io::duplex(64 * 1024);
        let (output, reader) = tokio::io::duplex(1 << 20);
        let task =
            tokio::spawn(async move { drop(gateway.run_stdio_on(input, output, None).await) });
        let meta = tokio::time::timeout(Duration::from_secs(30), meta)
            .await
            .expect("stdio built its Meta-MCP within 30 s")
            .expect("the seam reported it");
        let live = Arc::clone(
            &meta
                .reload_context()
                .expect("stdio has a reload context")
                .live_config,
        );
        let mut session = Self {
            client,
            reader: tokio::io::BufReader::new(reader),
            hold,
            live,
            task,
            next_id: 1,
            meta,
        };
        let id = session
            .send(
                "initialize",
                json!({"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "adr-023", "version": "0"}}),
            )
            .await;
        session.answer(id).await;
        if announce == Announce::Yes {
            let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
            session
                .client
                .write_all(format!("{note}\n").as_bytes())
                .await
                .expect("write");
        }
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

/// Past the sanitiser: the call went on to resolve its server, which does
/// not exist, so it failed there and not for any earlier reason.
fn reached_resolution(reply: &Value) -> bool {
    !sanitised(reply) && reply.to_string().contains("absent")
}

/// F2: over stdio, a reload turns sanitising off and on again, each applying
/// to the next call, with no restart.
#[tokio::test]
async fn f2_stdio_sanitise_input_follows_a_reload() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("gateway.yaml");
    write_flag(&path, true);
    let mut s = Session::start(dir.path(), path.clone(), Announce::Yes).await;

    let id = s.send_nul().await;
    let reply = s.answer(id).await;
    assert!(sanitised(&reply), "on at start: {reply}");

    write_flag(&path, false);
    s.reload().await;
    let id = s.send_nul().await;
    let reply = s.answer(id).await;
    assert!(reached_resolution(&reply), "off after reload: {reply}");

    write_flag(&path, true);
    s.reload().await;
    let id = s.send_nul().await;
    let reply = s.answer(id).await;
    assert!(sanitised(&reply), "on after reload: {reply}");
}

/// Hold the next line's dispatch, flip the flag by a reload sent on the same
/// session (it runs concurrently: lines other than `initialize` are spawned),
/// release, and return the held line's answer. The flag the session serves is
/// checked flipped, so a reload that never landed cannot pass the row.
async fn held_across_a_flip(s: &mut Session, path: &Path, to: bool) -> Value {
    let (reached, release) = s.hold.arm();
    let held = s.send_nul().await;
    crate::test_pause::within("the held line reaches the pause", reached.notified()).await;
    write_flag(path, to);
    s.reload().await;
    assert_eq!(
        s.live.get().security.sanitize_input,
        to,
        "the reload did not land"
    );
    release.notify_one();
    s.answer(held).await
}

/// G4: a line read while sanitising is on is judged on, even when a reload
/// turns it off before the line dispatches; and the reverse.
#[tokio::test]
async fn g4_a_held_stdio_line_keeps_the_generation_it_was_read_under() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("gateway.yaml");
    write_flag(&path, true);
    let mut s = Session::start(dir.path(), path.clone(), Announce::No).await;

    let reply = held_across_a_flip(&mut s, &path, false).await;
    assert!(sanitised(&reply), "on then off: {reply}");

    let reply = held_across_a_flip(&mut s, &path, true).await;
    assert!(reached_resolution(&reply), "off then on: {reply}");
}

/// The config with the tool policy denying `absent:t`, or not, and the task
/// store in the test's own directory.
fn write_policy(path: &Path, deny: bool) {
    let tasks = path.with_file_name("tasks");
    let tasks = tasks.display().to_string().replace('\'', "''");
    let denied = if deny { "['absent:t']" } else { "[]" };
    write_owner_only(
        path,
        format!(
            "security:\n  tool_policy:\n    enabled: true\n    deny: {denied}\n\
             tasks:\n  store_dir: '{tasks}'\n"
        ),
    )
    .expect("write");
}

/// Refused by the tool policy, as opposed to failing later for another reason.
fn policy_refused(reply: &Value) -> bool {
    !sanitised(reply) && reply.to_string().contains("policy")
}

/// Hold the next `gateway_invoke` of `absent:t`, reload the tool policy to
/// `deny`, release, and return the held line's answer. The reload is checked
/// to have landed, so a reload that never applied cannot pass the row.
async fn held_across_a_policy_flip(s: &mut Session, path: &Path, deny: bool) -> Value {
    let (reached, release) = s.hold.arm();
    let held = s
        .send(
            "tools/call",
            json!({"name": "gateway_invoke",
                   "arguments": {"server": "absent", "tool": "t", "arguments": {"cmd": "x"}}}),
        )
        .await;
    crate::test_pause::within("the held line reaches the pause", reached.notified()).await;
    write_policy(path, deny);
    s.reload().await;
    assert_eq!(
        s.live.get().security.tool_policy.deny.is_empty(),
        !deny,
        "the reload did not land"
    );
    release.notify_one();
    s.answer(held).await
}

/// The key-by-policy barrier's stdio line (ADR-029, amended, item 1): a line
/// read while the tool policy denies the call is refused, even when a reload
/// lifts the deny before the line dispatches; and a line read while it is
/// allowed goes on to resolve its server, even when a reload denies it.
#[tokio::test]
async fn a_held_stdio_line_keeps_the_tool_policy_it_was_read_under() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("gateway.yaml");
    write_policy(&path, true);
    let mut s = Session::start(dir.path(), path.clone(), Announce::No).await;

    let reply = held_across_a_policy_flip(&mut s, &path, false).await;
    assert!(policy_refused(&reply), "denied then allowed: {reply}");

    let reply = held_across_a_policy_flip(&mut s, &path, true).await;
    // Resolution's own failure, not the policy's: its refusal names the
    // server too, so `reached_resolution` alone would accept a denial.
    assert!(
        reached_resolution(&reply) && !policy_refused(&reply),
        "allowed then denied: {reply}"
    );
}

#[cfg(feature = "firewall")]
#[path = "stdio_live_collusion_tests.rs"]
mod collusion;
