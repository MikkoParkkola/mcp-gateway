// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8278 STDIONOTE: a legacy (initialize-era) stdio session is told when
//! its tool list changes, as an HTTP client is; a modern stdio client, which
//! can only be told through `subscriptions/listen` (MIK-8345), is told
//! nothing and its discovery says so. Rows drive `Gateway::run_stdio_on`
//! over in-memory pipes. Test plan: lead-decisions scratch secD-8278 t1/t2.

use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::config::Config;
use crate::gateway::Gateway;

/// Bound on every wait for a frame that must arrive.
const ARRIVAL: Duration = Duration::from_secs(20);
/// How long a frame that must not arrive is waited for.
const SILENCE: Duration = Duration::from_secs(5);
const LIST_CHANGED: &str = "notifications/tools/list_changed";
const PROBE: &str = "stdionote_probe";

/// A capability `PROBE`, served by no network call in these rows.
fn capability_yaml() -> String {
    format!(
        "fulcrum: \"1.0\"\nname: {PROBE}\ndescription: A probe capability for MIK-8278.\n\
schema:\n  input:\n    type: object\n    properties: {{}}\n\
providers:\n  primary:\n    service: rest\n    config:\n      base_url: https://example.invalid\n      path: /probe\n      method: GET\n\
auth:\n  required: false\n  type: none\n"
    )
}

pub(super) struct Serve {
    client: DuplexStream,
    lines: Lines<BufReader<DuplexStream>>,
    task: JoinHandle<crate::Result<()>>,
    dir: tempfile::TempDir,
}

impl Serve {
    pub(super) fn caps(&self) -> std::path::PathBuf {
        self.dir.path().join("caps")
    }

    pub(super) async fn send(&mut self, frame: &Value) {
        let mut line = serde_json::to_vec(frame).expect("a frame serialises");
        line.push(b'\n');
        self.client
            .write_all(&line)
            .await
            .expect("stdin accepts the frame");
    }

    /// The next frame on stdout within `limit`, or `None` on a timeout. A
    /// closed or failed stdout panics: it is not silence.
    pub(super) async fn next(&mut self, limit: Duration) -> Option<Value> {
        let line = timeout(limit, self.lines.next_line())
            .await
            .ok()?
            .expect("stdout reads")
            .expect("stdout closed while a frame was awaited");
        Some(serde_json::from_str(&line).expect("every stdout line is one JSON-RPC message"))
    }

    /// Every frame left on stdout, up to its EOF.
    pub(super) async fn rest(&mut self) -> Vec<Value> {
        let mut frames = Vec::new();
        while let Some(line) = timeout(ARRIVAL, self.lines.next_line())
            .await
            .expect("stdout reaches EOF")
            .expect("stdout reads")
        {
            frames.push(serde_json::from_str(&line).expect("one JSON-RPC message"));
        }
        frames
    }

    /// The reply to `id`, collecting every frame seen before it.
    pub(super) async fn reply(&mut self, id: u64, seen: &mut Vec<Value>) -> Value {
        loop {
            let frame = self
                .next(ARRIVAL)
                .await
                .unwrap_or_else(|| panic!("no reply for id {id} within {ARRIVAL:?}"));
            if frame["id"] == json!(id) {
                return frame;
            }
            seen.push(frame);
        }
    }

    /// Whether a `tools/list_changed` arrives within `limit`.
    pub(super) async fn list_changed_within(&mut self, limit: Duration) -> bool {
        let until = tokio::time::Instant::now() + limit;
        while let Some(frame) = self
            .next(until.saturating_duration_since(tokio::time::Instant::now()))
            .await
        {
            if frame["method"] == LIST_CHANGED {
                return true;
            }
        }
        false
    }

    /// The names `tools/list` returns.
    pub(super) async fn tool_names(&mut self, id: u64) -> Vec<String> {
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {}}))
            .await;
        let reply = self.reply(id, &mut Vec::new()).await;
        reply["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("tools/list failed: {reply}"))
            .iter()
            .filter_map(|t| t["name"].as_str().map(str::to_owned))
            .collect()
    }

    pub(super) fn add_probe(&self) {
        std::fs::write(self.caps().join(format!("{PROBE}.yaml")), capability_yaml())
            .expect("write capability");
    }

    pub(super) fn remove_probe(&self) {
        std::fs::remove_file(self.caps().join(format!("{PROBE}.yaml"))).expect("remove capability");
    }

    /// EOF on stdin; the session must end cleanly within [`ARRIVAL`].
    pub(super) async fn close(self) {
        drop(self.client);
        timeout(ARRIVAL, self.task)
            .await
            .expect("the session ends after EOF")
            .expect("the session task did not panic")
            .expect("the session returned Ok");
    }
}

/// A stdio gateway from a config file with a watched capability directory
/// and `PROBE` surfaced, so `tools/list` shows it when it is loaded.
pub(super) async fn serve(with_probe: bool) -> Serve {
    let serve = serve_with(|_| String::new()).await;
    if with_probe {
        serve.add_probe();
    }
    serve
}

/// As [`serve`], with `extra` config lines, written once the directory exists.
async fn serve_with(extra: impl FnOnce(&std::path::Path) -> String) -> Serve {
    serve_on(extra, 64 * 1024).await
}

/// As [`serve_with`], with a stdout pipe of `stdout_bytes`.
async fn serve_on(extra: impl FnOnce(&std::path::Path) -> String, stdout_bytes: usize) -> Serve {
    let dir = tempfile::tempdir().expect("tempdir");
    let caps = dir.path().join("caps");
    std::fs::create_dir(&caps).expect("capabilities directory");
    let tasks = dir.path().join("tasks");
    let yaml = format!(
        "capabilities:\n  enabled: true\n  name: capabilities\n  directories:\n    - {}\n\
meta_mcp:\n  surfaced_tools:\n    - server: capabilities\n      tool: {PROBE}\n\
tasks:\n  store_dir: {}\n",
        caps.display(),
        serde_json::to_string(&tasks.display().to_string()).expect("a JSON string")
    ) + &extra(dir.path());
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    let serve_dir = dir;
    {
        // As production starts: the startup evaluation's overlay, so an
        // `env:` key an env file supplies resolves (T13).
        let evaluated = Config::load_evaluated(Some(&path)).expect("config evaluates");
        let env = std::sync::Arc::new(crate::config::LiveEnv::new(
            evaluated.overlay,
            evaluated.env_paths,
        ));
        let gateway = Gateway::new_with_env(evaluated.config, env, Some(path))
            .await
            .expect("gateway boots")
            .with_data_dir(serve_dir.path().join("data"));
        let (client, input) = tokio::io::duplex(1 << 20);
        let (output, stdout) = tokio::io::duplex(stdout_bytes);
        let task = tokio::spawn(async move { gateway.run_stdio_on(input, output, None).await });
        Serve {
            client,
            lines: BufReader::new(stdout).lines(),
            task,
            dir: serve_dir,
        }
    }
}

/// The legacy handshake: `initialize`, then `notifications/initialized`.
/// Returns the `initialize` result.
pub(super) async fn legacy(serve: &mut Serve, initialized: bool) -> Value {
    serve
        .send(
            &json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "stdionote", "version": "0"}}}),
        )
        .await;
    let result = serve.reply(0, &mut Vec::new()).await;
    if initialized {
        serve
            .send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
    }
    result
}

/// T6: a legacy stdio session's `initialize` advertises `tools.listChanged`,
/// because the session now delivers it.
#[tokio::test]
async fn t6_stdio_initialize_advertises_list_changed() {
    let mut serve = serve(false).await;
    let init = legacy(&mut serve, true).await;
    assert_eq!(
        init["result"]["capabilities"]["tools"]["listChanged"],
        json!(true),
        "{init}"
    );
    // Only the tools list is announced on stdio; the others stay false.
    for other in ["resources", "prompts"] {
        assert_ne!(
            init["result"]["capabilities"][other]["listChanged"],
            json!(true),
            "{other}: {init}"
        );
    }
    serve.close().await;
}

/// T1, T2: a capability file added to, then removed from, the watched
/// directory is announced to an initialized legacy session; `tools/list`
/// agrees after each announcement.
#[tokio::test]
async fn t1_t2_a_watched_capability_change_is_announced() {
    let mut serve = serve(false).await;
    legacy(&mut serve, true).await;
    assert!(
        !serve.tool_names(1).await.iter().any(|n| n == PROBE),
        "premise: the probe is not listed before it is added"
    );
    serve.add_probe();
    assert!(
        serve.list_changed_within(ARRIVAL).await,
        "T1: no list_changed after a capability was added"
    );
    assert!(
        serve.tool_names(2).await.iter().any(|n| n == PROBE),
        "T1: announced, but tools/list lacks the added capability"
    );
    serve.remove_probe();
    assert!(
        serve.list_changed_within(ARRIVAL).await,
        "T2: no list_changed after a capability was removed"
    );
    assert!(
        !serve.tool_names(3).await.iter().any(|n| n == PROBE),
        "T2: announced, but tools/list still lists the removed capability"
    );
    serve.close().await;
}

/// T7 (PIN, lead ruling): a modern stdio client, which never sends
/// `initialize`, sees `tools.listChanged: false` in discovery and is sent
/// no unsolicited `list_changed` (stdio `subscriptions/listen` is MIK-8345).
#[tokio::test]
async fn t7_a_modern_stdio_client_is_told_false_and_sent_nothing() {
    let mut serve = serve(false).await;
    serve
        .send(
            &json!({"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {
            "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}}}),
        )
        .await;
    let discover = serve.reply(1, &mut Vec::new()).await;
    assert_eq!(
        discover["result"]["capabilities"]["tools"]["listChanged"],
        json!(false),
        "{discover}"
    );
    serve.add_probe();
    assert!(
        !serve.list_changed_within(ARRIVAL).await,
        "a modern stdio client was sent an unsolicited list_changed"
    );
    serve.close().await;
}

/// T8: before `notifications/initialized` a change writes nothing; once it
/// arrives the held change is told with no further change, and a change after
/// it is told too.
#[tokio::test]
async fn t8_a_change_before_initialized_is_held_and_told_after_it() {
    let mut serve = serve(false).await;
    legacy(&mut serve, false).await;
    let base = crate::gateway::server::stdio_seams::decisions();
    serve.add_probe();
    // Premise: the change was decided before `initialized`, so a dropped (not
    // held) decision would leave nothing to tell later.
    assert!(
        decided(base + 1).await,
        "premise: the change was never decided"
    );
    assert!(
        !serve.list_changed_within(SILENCE).await,
        "list_changed before notifications/initialized"
    );
    serve
        .send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;
    assert!(
        serve.list_changed_within(ARRIVAL).await,
        "the change held across notifications/initialized was not told"
    );
    // A second, named capability: a change of its own, after the gate.
    std::fs::write(
        serve.caps().join("stdionote_second.yaml"),
        capability_yaml().replace(PROBE, "stdionote_second"),
    )
    .expect("write the second capability");
    assert!(
        serve.list_changed_within(ARRIVAL).await,
        "the first change after notifications/initialized was not delivered"
    );
    serve.close().await;
}

/// Whether this thread's stdio drains have decided `count` changes within
/// [`ARRIVAL`].
async fn decided(count: usize) -> bool {
    timeout(ARRIVAL, async {
        while crate::gateway::server::stdio_seams::decisions() < count {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok()
}

/// Bound on a stopped session's drain task ending.
const DRAIN_END: Duration = Duration::from_secs(5);

/// Whether `alive` dies within [`DRAIN_END`].
async fn ends(alive: &std::sync::Weak<()>) -> bool {
    timeout(DRAIN_END, async {
        while alive.upgrade().is_some() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok()
}

/// T3 (wiring, per the seats): the session starts the capability listing
/// watch that announces an expired login, as HTTP does.
#[tokio::test]
async fn t3_the_session_starts_the_listing_watch() {
    let before = crate::capability::listing_watches_started();
    let mut serve = serve(false).await;
    legacy(&mut serve, true).await;
    assert_eq!(
        crate::capability::listing_watches_started(),
        before + 1,
        "the stdio session did not start the listing watch"
    );
    serve.close().await;
}

/// T5 (GUARD): rewriting a capability file unchanged is not a change.
#[tokio::test]
async fn t5_an_unchanged_refill_writes_nothing() {
    let mut serve = serve(false).await;
    legacy(&mut serve, true).await;
    serve.add_probe();
    assert!(
        serve.list_changed_within(ARRIVAL).await,
        "premise: adding the probe is announced"
    );
    serve.add_probe();
    assert!(
        !serve.list_changed_within(ARRIVAL).await,
        "an unchanged capability file was announced as a change"
    );
    serve.close().await;
}

/// T10: after EOF the session's drain ends; it does not outlive the session.
#[tokio::test]
async fn t10_the_drain_ends_with_the_session_at_eof() {
    let mut serve = serve(false).await;
    legacy(&mut serve, true).await;
    let alive = crate::gateway::server::stdio_seams::last_announcer()
        .expect("the session started its announcer");
    assert!(alive.upgrade().is_some(), "premise: the drain runs");
    serve.close().await;
    assert!(ends(&alive).await, "the drain outlived EOF");
}

/// T11: cancelling the serve future ends the drain too.
#[tokio::test]
async fn t11_the_drain_ends_when_the_session_is_cancelled() {
    let mut serve = serve(false).await;
    legacy(&mut serve, true).await;
    let alive = crate::gateway::server::stdio_seams::last_announcer()
        .expect("the session started its announcer");
    assert!(alive.upgrade().is_some(), "premise: the drain runs");
    serve.task.abort();
    assert!(
        (&mut serve.task).await.is_err_and(|e| e.is_cancelled()),
        "premise: the serve future was cancelled"
    );
    assert!(ends(&alive).await, "the drain outlived a cancelled session");
}

/// The key the T13 capability needs to be listed; set by no other test.
const T13_KEY: &str = "MCP_GW_MIK8278_T13_KEY";

/// T13: a reload whose env change makes a keyed capability listable is
/// announced, through the reload context the session builds once its
/// capability backend exists.
#[tokio::test]
async fn t13_a_reload_that_changes_the_listing_is_announced() {
    let mut serve = serve_with(|dir| {
        let env = dir.join(".env");
        crate::gateway::test_helpers::write_owner_only(&env, "MCP_GW_MIK8278_OTHER=1\n")
            .expect("write the env file");
        std::fs::write(
            dir.join("caps").join(format!("{PROBE}.yaml")),
            capability_yaml().replace(
                "auth:\n  required: false\n  type: none\n",
                &format!("auth:\n  required: true\n  type: bearer\n  key: \"env:{T13_KEY}\"\n"),
            ),
        )
        .expect("write the keyed capability");
        format!(
            "env_files:\n  - {}\n",
            serde_json::to_string(&env.display().to_string()).expect("a JSON string")
        )
    })
    .await;
    legacy(&mut serve, true).await;
    assert!(
        !serve.tool_names(1).await.iter().any(|n| n == PROBE),
        "premise: the keyed capability is not listed without its key"
    );
    crate::gateway::test_helpers::write_owner_only(
        serve.dir.path().join(".env"),
        format!("{T13_KEY}=x\n"),
    )
    .expect("write the key");
    serve
        .send(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "gateway_reload_config", "arguments": {}}}))
        .await;
    let mut seen = Vec::new();
    let reply = serve.reply(2, &mut seen).await;
    assert!(
        reply.get("error").is_none() && reply["result"]["isError"] != json!(true),
        "reload refused: {reply}"
    );
    assert!(
        seen.iter().any(|f| f["method"] == LIST_CHANGED)
            || serve.list_changed_within(ARRIVAL).await,
        "a reload that made the capability listable was not announced"
    );
    assert!(
        serve.tool_names(3).await.iter().any(|n| n == PROBE),
        "announced, but tools/list lacks the keyed capability"
    );
    serve.close().await;
}

/// T10b (STDIONOTE.3b): once stdin reaches EOF nothing more is announced,
/// even while an accepted request keeps the session draining.
#[tokio::test]
async fn t10b_nothing_is_announced_after_eof_while_the_session_drains() {
    let mut serve = serve(false).await;
    legacy(&mut serve, true).await;
    let pause = crate::gateway::server::stdio_seams::pause_after_commit_for_test();
    serve
        .send(&json!({"jsonrpc": "2.0", "id": 5, "method": "ping"}))
        .await;
    pause.reached().await;
    serve.client.shutdown().await.expect("stdin closes");
    serve.add_probe();
    // The absence window the other rows use, while the ping holds the drain.
    tokio::time::sleep(ARRIVAL).await;
    pause.release();
    let frames = serve.rest().await;
    assert!(
        frames.iter().any(|f| f["id"] == json!(5)),
        "premise: the held request was answered: {frames:?}"
    );
    assert!(
        !frames.iter().any(|f| f["method"] == LIST_CHANGED),
        "announced after EOF: {frames:?}"
    );
    timeout(ARRIVAL, serve.task)
        .await
        .expect("the session ends")
        .expect("no panic")
        .expect("Ok");
}

/// T14 (lead, end-to-end burst): with the session's stdout not read and its
/// writer queue full, five distinct catalogue changes are each decided while
/// stdout stays blocked (a drain that sent inline would stop at the first),
/// and once stdout is read at most two `list_changed` frames arrive (the parked
/// sender's wake plus at most one stored wake), not one per change.
#[tokio::test]
async fn t14_a_burst_while_stdout_is_full_is_decided_and_told_at_most_twice() {
    use crate::gateway::server::stdio_seams::decisions;
    const FLOOD: usize = super::super::STDOUT_QUEUE_DEPTH + 200;
    // A pipe that holds less than one frame, as in `stdio_reader_unparked`.
    let mut serve = serve_on(|_| String::new(), 64).await;
    legacy(&mut serve, true).await;
    let mut pings = Vec::new();
    for id in 1..=FLOOD as u64 {
        let line = serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": id, "method": "ping"}))
            .expect("a frame serialises");
        pings.extend_from_slice(&line);
        pings.push(b'\n');
    }
    serve
        .client
        .write_all(&pings)
        .await
        .expect("stdin accepts the flood");
    let base = decisions();
    for n in 0..5 {
        std::fs::write(
            serve.caps().join(format!("stdionote_burst{n}.yaml")),
            capability_yaml().replace(PROBE, &format!("stdionote_burst{n}")),
        )
        .expect("write a burst capability");
        assert!(
            decided(base + n + 1).await,
            "change {n} was not decided while stdout was blocked ({} of {})",
            decisions() - base,
            n + 1
        );
    }
    // The sender woke to a full queue and, with stdout unread since, is
    // still parked on it: every decision above was made while it waited.
    assert!(
        crate::gateway::server::stdio_seams::queue_full_wakes() >= 1,
        "premise: the sender never found the writer queue full"
    );
    let mut seen = Vec::new();
    while let Some(frame) = serve.next(SILENCE).await {
        seen.push(frame);
    }
    let answered = seen.iter().filter(|f| f["id"].is_u64()).count();
    let announced = seen.iter().filter(|f| f["method"] == LIST_CHANGED).count();
    assert!(
        answered >= super::super::STDOUT_QUEUE_DEPTH,
        "premise: the queue never filled ({answered} ping answers)"
    );
    assert!(
        (1..=2).contains(&announced),
        "{announced} list_changed frames for 5 changes decided while stdout was full"
    );
    serve.close().await;
}

/// gpt t4: a legacy client that sends `notifications/initialized` inside a
/// batch is announced to as one that sends it alone.
#[tokio::test]
async fn t15_initialized_inside_a_batch_starts_announcing() {
    let mut serve = serve(false).await;
    legacy(&mut serve, false).await;
    serve
        .send(&json!([{"jsonrpc": "2.0", "method": "notifications/initialized"}]))
        .await;
    serve.add_probe();
    assert!(
        serve.list_changed_within(ARRIVAL).await,
        "a batched notifications/initialized did not start announcing"
    );
    serve.close().await;
}
