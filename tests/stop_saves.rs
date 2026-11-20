// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stop with default settings loses at most the last checkpoint interval of
//! the gateway's records. The rows run the real binary with one stdio backend
//! and an API key (transitions record under the caller's key), stop it, and
//! SIGKILL it where a container's 10 s grace would: everything recorded before
//! the stop signal must be on disk, and every file must load.
//!
//! Run 1 of each row makes two calls and stops cleanly (state A on disk); run 2
//! makes the row's calls, sets up its scenario, gets SIGTERM, then the row's
//! kill. Waits are events read from the gateway's log, each under a bound set by
//! the failure it separates (10 s: Docker's grace, the claim's own window).

#![cfg(unix)]

#[path = "common/signing_gateway.rs"]
pub mod signing_gateway;
#[path = "common/yaml.rs"]
mod yaml;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use mcp_gateway::config::{ApiKeyConfig, BackendConfig, Config, TransportConfig};
use serde_json::{Value, json};
use signing_gateway::{child_command, gateway_bin};

const BACKEND: &str = "py";
const KEY: &str = "stop-rows-test-key-0123456789abcdef";
const KEY_SHA256: &str = "sha256:5525b685b8931918e1ca0cd45a7d61b76dd70bde3d57aed84d503976dc9aee3e";
/// Docker's and compose's default stop grace: the claim's window, and the bound
/// on every event wait. A stream held to the listener grace (17.1 s at the
/// default total) is still open when it runs out.
const GRACE: Duration = Duration::from_secs(10);

/// argv[1] = prompt | stubborn. `slow` marks its call, then answers once the
/// test creates `slow-gate`; `hang` marks its call and never answers;
/// `stubborn` ignores SIGTERM and stays after stdin closes.
const BACKEND_SCRIPT: &str = r#"import json, os, signal, sys, time
mode = sys.argv[1]
with open("backend.pid", "a") as f:
    f.write(f"{os.getpid()}\n")
if mode == "stubborn":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    method = msg.get("method")
    name = msg.get("params", {}).get("name")
    if method == "tools/call" and name == "hang":
        open("hang-called", "w").close()
        continue
    if method == "tools/call" and name == "slow":
        open("slow-called", "w").close()
        while not os.path.exists("slow-gate"):
            time.sleep(0.01)
    if method == "initialize":
        result = {"protocolVersion": msg["params"]["protocolVersion"], "capabilities": {"tools": {}},
                  "serverInfo": {"name": "py", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": [{"name": n, "inputSchema": {"type": "object"}, "annotations": {"readOnlyHint": True}}
                            for n in ("alpha", "beta", "slow", "hang")]}
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": "ok"}]}
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
if mode == "stubborn":
    time.sleep(300)
"#;

fn write_config(root: &Path, mode: &str) -> PathBuf {
    std::fs::write(root.join("backend.py"), BACKEND_SCRIPT).expect("backend");
    let mut config = Config::default();
    config.server.host = "127.0.0.1".to_string();
    config.server.port = gateway_bin::ANY_PORT;
    config.auth.enabled = true;
    config.auth.api_keys = vec![ApiKeyConfig {
        key_sha256: Some(KEY_SHA256.to_string()),
        name: "stop-rows".to_string(),
        backends: vec![BACKEND.to_string()],
        ..ApiKeyConfig::default()
    }];
    config.capabilities.enabled = false;
    config.cache.default_ttl = Duration::ZERO;
    config.cost_governance.enabled = true;
    config.cost_governance.default_cost = 0.01;
    config.tasks.store_dir = root.join("tasks").display().to_string();
    config.backends.insert(
        BACKEND.to_string(),
        BackendConfig {
            enabled: true,
            transport: TransportConfig::Stdio {
                command: format!("python3 -u backend.py {mode}"),
                cwd: Some(root.display().to_string()),
                protocol_version: None,
            },
            timeout: Duration::from_secs(600),
            ..BackendConfig::default()
        },
    );
    let path = root.join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &path,
        yaml::to_string(&config).expect("yaml"),
    )
    .expect("config");
    path
}

struct Gateway {
    child: gateway_bin::Reaped,
    pid: u32,
    url: String,
    log: PathBuf,
    client: reqwest::Client,
}

fn client() -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {KEY}").parse().expect("header"),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .expect("client")
}

async fn start(dir: &Path, config: &Path, tag: &str) -> Gateway {
    let log = dir.join(format!("gateway-{tag}.log"));
    let file = std::fs::File::create(&log).expect("log");
    // Reaped kills a gateway a failed row left running, before `dir` goes.
    let mut child = gateway_bin::Reaped::new(
        child_command(dir, config)
            .stdin(Stdio::null())
            .stdout(Stdio::from(file.try_clone().expect("clone")))
            .stderr(Stdio::from(file))
            .spawn()
            .expect("spawn gateway"),
    );
    let pid = child.child_mut().id().expect("pid");
    let client = client();
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(Instant::now() < deadline, "gateway did not start: {text}");
        if let Some(port) = gateway_bin::reported_port(&text) {
            let url = format!("http://127.0.0.1:{port}");
            if client
                .get(format!("{url}/health"))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                return Gateway {
                    child,
                    pid,
                    url,
                    log,
                    client,
                };
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

impl Gateway {
    async fn session(&self) -> String {
        let r = self
            .client
            .post(format!("{}/mcp", self.url))
            .json(
                &json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
                "protocolVersion": "2025-03-26", "capabilities": {},
                "clientInfo": {"name": "stop-rows", "version": "0"}}}),
            )
            .send()
            .await
            .expect("initialize");
        r.headers()
            .get("mcp-session-id")
            .expect("session")
            .to_str()
            .expect("text")
            .to_owned()
    }

    fn call_request(&self, session: &str, id: u64, tool: &str) -> reqwest::RequestBuilder {
        self.client.post(format!("{}/mcp", self.url)).header("mcp-session-id", session).json(&json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {
                "name": "gateway_invoke", "arguments": {"server": BACKEND, "tool": tool, "arguments": {}}}}))
    }

    async fn call(&self, session: &str, id: u64, tool: &str) {
        let r = self
            .call_request(session, id, tool)
            .send()
            .await
            .expect("call");
        assert!(r.status().is_success(), "call {tool}: {}", r.status());
        let body = r.text().await.unwrap_or_default();
        assert!(!body.contains("\"error\""), "call {tool} failed: {body}");
    }

    fn signal(&self, sig: &str) {
        let pid = self.pid.to_string();
        assert!(
            std::process::Command::new("kill")
                .args([sig, &pid])
                .status()
                .expect("kill")
                .success()
        );
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    async fn stop_clean(mut self) -> String {
        self.signal("-TERM");
        let status = tokio::time::timeout(Duration::from_secs(60), self.child.child_mut().wait())
            .await
            .expect("stopped within 60 s")
            .expect("status");
        assert!(
            status.success(),
            "clean stop exited {status}: {}",
            self.log_text()
        );
        self.log_text()
    }

    async fn kill(mut self) {
        self.signal("-KILL");
        let _ = self.child.child_mut().wait().await;
    }
}

/// The classes the claim covers, as one checkpoint writes them.
const CLASSES: [&str; 4] = ["usage", "transitions", "counters", "cost"];

/// Whether `log` holds a `saved` line of `pass` for every class in `classes`.
fn saved(log: &str, pass: &str, classes: &[&str]) -> bool {
    classes
        .iter()
        .all(|c| log.contains(&format!("stop checkpoint saved class={c} pass={pass}")))
}

/// What a fresh load of the data dir holds, per class.
#[derive(Debug, PartialEq)]
struct State {
    /// Uses of alpha, beta, slow, hang.
    usage: [u64; 4],
    transitions: u64,
    /// Calls per tool in counters.json: each label's day ring, summed over
    /// its buckets (count 0 of a bucket is calls), so a run crossing midnight
    /// keeps its total.
    counted: Vec<(String, u64)>,
    /// Spend per tool in costs.json, in cents, by tool name (0.01 per call).
    /// costs.json carries spend, not calls: its `call_count` is always 0.
    cost_cents: Vec<(String, u64)>,
}

fn state(dir: &Path) -> State {
    let data = dir.join(".mcp-gateway");
    let ranker = mcp_gateway::ranking::SearchRanker::new();
    ranker
        .load(&data.join("usage.json"))
        .expect("usage.json loads");
    let usage = ["alpha", "beta", "slow", "hang"].map(|t| ranker.usage_count(BACKEND, t));
    let tracker = mcp_gateway::transition::TransitionTracker::new();
    tracker
        .load(&data.join("transitions.json"))
        .expect("transitions.json loads");
    let counters: Value =
        serde_json::from_slice(&std::fs::read(data.join("counters.json")).expect("counters.json"))
            .expect("counters.json parses");
    let mut counted: Vec<(String, u64)> = counters["tool"]["labels"]
        .as_array()
        .expect("tool labels")
        .iter()
        .map(|l| {
            let calls = l[1]["day"]
                .as_array()
                .expect("a day ring")
                .iter()
                .map(|bucket| bucket[1][0].as_u64().expect("a call count"))
                .sum();
            (l[0][1].as_str().expect("a tool name").to_owned(), calls)
        })
        .collect();
    counted.sort();
    let costs = mcp_gateway::cost_accounting::persistence::load(&data.join("costs.json"))
        .expect("costs.json loads");
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "a test's spend is a few cents"
    )]
    let mut cost_cents: Vec<(String, u64)> = costs
        .tool_totals
        .iter()
        .map(|(k, v)| {
            let cents = (v.total_cost_usd * 100.0).round() as u64;
            (k.rsplit(':').next().unwrap_or(k).to_owned(), cents)
        })
        .collect();
    cost_cents.sort();
    State {
        usage,
        transitions: tracker.total_transitions(),
        counted,
        cost_cents,
    }
}

/// Kill every backend the script recorded that is still alive: a stubborn one
/// outlives a gateway ended by SIGKILL.
fn reap_backends(dir: &Path) {
    for pid in std::fs::read_to_string(dir.join("backend.pid"))
        .unwrap_or_default()
        .lines()
    {
        let _ = std::process::Command::new("kill")
            .args(["-9", pid.trim()])
            .status();
    }
}

/// Run 1: alpha and beta, a clean stop, and state A on disk (the premise every
/// row starts from).
async fn baseline(dir: &Path, config: &Path) {
    let gw = start(dir, config, "1").await;
    let s = gw.session().await;
    gw.call(&s, 1, "alpha").await;
    gw.call(&s, 2, "beta").await;
    gw.stop_clean().await;
    assert_eq!(
        state(dir),
        State {
            usage: [1, 1, 0, 0],
            transitions: 1,
            counted: vec![("alpha".into(), 1), ("beta".into(), 1)],
            cost_cents: vec![("alpha".into(), 1), ("beta".into(), 1)],
        },
        "premise: run 1's state A on disk"
    );
}

/// Wait until `done(log)` or the gateway exits, never past `deadline`.
async fn until(gw: &mut Gateway, deadline: Instant, done: impl Fn(&str) -> bool) {
    while Instant::now() < deadline {
        if done(&gw.log_text()) || gw.child.child_mut().try_wait().expect("wait").is_some() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// SIGKILL if still running (a gateway that already exited cannot be killed).
async fn kill_if_running(mut gw: Gateway) {
    if gw.child.child_mut().try_wait().expect("wait").is_none() {
        gw.kill().await;
    }
}

/// K-idle, K-stubborn, K-sse: alpha and beta in run 2, the scenario, SIGTERM,
/// then SIGKILL once pass 1 is saved for every class, never past the grace.
async fn k_simple(mode: &str, held_sse: bool) {
    let dir = tempfile::tempdir().expect("dir");
    let config = write_config(dir.path(), mode);
    baseline(dir.path(), &config).await;
    let mut gw = start(dir.path(), &config, "2").await;
    let s = gw.session().await;
    gw.call(&s, 11, "alpha").await;
    gw.call(&s, 12, "beta").await;
    let _stream = if held_sse {
        Some(
            gw.client
                .get(format!("{}/mcp", gw.url))
                .header("mcp-session-id", &s)
                .header("accept", "text/event-stream")
                .send()
                .await
                .expect("sse"),
        )
    } else {
        None
    };
    gw.signal("-TERM");
    let deadline = Instant::now() + GRACE;
    until(&mut gw, deadline, |log| saved(log, "1", &CLASSES)).await;
    kill_if_running(gw).await;
    reap_backends(dir.path());
    assert_eq!(
        state(dir.path()),
        State {
            usage: [2, 2, 0, 0],
            transitions: 2,
            counted: vec![("alpha".into(), 2), ("beta".into(), 2)],
            cost_cents: vec![("alpha".into(), 2), ("beta".into(), 2)],
        },
        "run 2's records lost by a kill inside the grace"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn k_idle_a_kill_after_the_first_checkpoint_loses_nothing() {
    k_simple("prompt", false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn k_stubborn_a_backend_that_ignores_the_stop_loses_nothing() {
    k_simple("stubborn", false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn k_sse_a_held_stream_does_not_hold_the_saves() {
    k_simple("prompt", true).await;
}

/// Wait for a marker file the backend writes, bounded by the grace.
async fn marker(dir: &Path, name: &str) {
    let until = Instant::now() + GRACE;
    while !dir.join(name).exists() {
        assert!(
            Instant::now() < until,
            "premise: the backend never received {name}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// EARLY.1: a request held by its backend keeps the listener open, and the
/// kill still finds everything recorded before the signal on disk.
#[tokio::test(flavor = "multi_thread")]
async fn k_inflight_a_held_request_does_not_hold_the_saves() {
    let dir = tempfile::tempdir().expect("dir");
    let config = write_config(dir.path(), "prompt");
    baseline(dir.path(), &config).await;
    let mut gw = start(dir.path(), &config, "2").await;
    let s = gw.session().await;
    gw.call(&s, 11, "alpha").await;
    gw.call(&s, 12, "beta").await;
    let _hang = tokio::spawn(gw.call_request(&s, 13, "hang").send());
    marker(dir.path(), "hang-called").await;
    gw.signal("-TERM");
    let deadline = Instant::now() + GRACE;
    until(&mut gw, deadline, |log| saved(log, "1", &CLASSES)).await;
    kill_if_running(gw).await;
    assert_eq!(
        state(dir.path()),
        // A transition is recorded when its call completes
        // (invoke/post_dispatch.rs, record_and_predict), and `hang` never
        // does: run 2 adds alpha to beta only.
        State {
            usage: [2, 2, 0, 1],
            transitions: 2,
            counted: vec![("alpha".into(), 2), ("beta".into(), 2)],
            cost_cents: vec![("alpha".into(), 2), ("beta".into(), 2)],
        },
        "a held request's session lost by a kill inside the grace"
    );
}

/// D5: a request that completes during the stop is saved by a later pass.
#[tokio::test(flavor = "multi_thread")]
async fn k_post_a_request_completing_during_the_stop_is_saved() {
    let dir = tempfile::tempdir().expect("dir");
    let config = write_config(dir.path(), "prompt");
    baseline(dir.path(), &config).await;
    let mut gw = start(dir.path(), &config, "2").await;
    let s = gw.session().await;
    gw.call(&s, 11, "alpha").await;
    gw.call(&s, 12, "beta").await;
    let _hang = tokio::spawn(gw.call_request(&s, 13, "hang").send());
    marker(dir.path(), "hang-called").await;
    let slow = tokio::spawn(gw.call_request(&s, 14, "slow").send());
    marker(dir.path(), "slow-called").await;
    gw.signal("-TERM");
    let deadline = Instant::now() + GRACE;
    until(&mut gw, deadline, |log| {
        saved(log, "1", &["counters", "cost"])
    })
    .await;
    std::fs::write(dir.path().join("slow-gate"), "").expect("open the gate");
    let left = deadline.saturating_duration_since(Instant::now());
    let _ = tokio::time::timeout(left, slow).await;
    let offset = gw.log_text().len();
    until(&mut gw, deadline, |log| {
        let after = log.get(offset..).unwrap_or("");
        after
            .lines()
            .filter_map(|l| l.split("stop checkpoint pass=").nth(1))
            .filter_map(|r| r.split_whitespace().next())
            .any(|n| saved(after, n, &CLASSES))
    })
    .await;
    kill_if_running(gw).await;
    assert_eq!(
        state(dir.path()),
        // `slow` completes during the stop, after `beta` (`hang` never
        // completes, so it records no transition): run 2 adds alpha to beta
        // and beta to slow.
        State {
            usage: [2, 2, 1, 1],
            transitions: 3,
            counted: vec![("alpha".into(), 2), ("beta".into(), 2), ("slow".into(), 1)],
            cost_cents: vec![("alpha".into(), 2), ("beta".into(), 2), ("slow".into(), 1)],
        },
        "a request completing during the stop was not saved before the kill"
    );
}

/// A kill inside the backend stage (a stubborn backend still stopping) loses
/// no gateway state.
#[tokio::test(flavor = "multi_thread")]
async fn k_stubborn_late_a_kill_in_the_backend_stage_loses_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let config = write_config(dir.path(), "stubborn");
    baseline(dir.path(), &config).await;
    let mut gw = start(dir.path(), &config, "2").await;
    let s = gw.session().await;
    gw.call(&s, 11, "alpha").await;
    gw.call(&s, 12, "beta").await;
    gw.signal("-TERM");
    let deadline = Instant::now() + GRACE;
    until(&mut gw, deadline, |log| {
        log.contains("Shutting down backends")
    })
    .await;
    kill_if_running(gw).await;
    reap_backends(dir.path());
    assert_eq!(
        state(dir.path()).usage,
        [2, 2, 0, 0],
        "a kill in the backend stage lost usage"
    );
}

/// W-last: the stop's last pass runs after the task drain and before the
/// backend stage, for every class.
#[tokio::test(flavor = "multi_thread")]
async fn w_last_the_last_pass_runs_between_the_drains_and_the_backends() {
    let dir = tempfile::tempdir().expect("dir");
    let config = write_config(dir.path(), "prompt");
    let gw = start(dir.path(), &config, "1").await;
    let s = gw.session().await;
    gw.call(&s, 1, "alpha").await;
    let log = gw.stop_clean().await;
    let drain = log
        .find("Draining in-flight tasks")
        .expect("the task drain is logged");
    let backends = log
        .find("Shutting down backends")
        .expect("the backend stage is logged");
    for class in CLASSES {
        let line = format!("stop checkpoint saved class={class} pass=last");
        let at = log
            .find(&line)
            .unwrap_or_else(|| panic!("no last pass for {class}"));
        assert!(
            drain < at && at < backends,
            "{class}'s last pass is not between the task drain and the backend stage"
        );
    }
}

/// S-sse-ends: an open session stream ends at the stop signal.
#[tokio::test(flavor = "multi_thread")]
async fn s_sse_a_session_stream_ends_at_the_signal() {
    let dir = tempfile::tempdir().expect("dir");
    let config = write_config(dir.path(), "prompt");
    let gw = start(dir.path(), &config, "1").await;
    let s = gw.session().await;
    let mut stream = gw
        .client
        .get(format!("{}/mcp", gw.url))
        .header("mcp-session-id", &s)
        .header("accept", "text/event-stream")
        .send()
        .await
        .expect("sse");
    gw.signal("-TERM");
    let t0 = Instant::now();
    let ended = tokio::time::timeout(GRACE, async {
        while let Ok(Some(_)) = stream.chunk().await {}
    })
    .await;
    assert!(
        ended.is_ok(),
        "the stream was still open {:?} after the stop signal",
        t0.elapsed()
    );
    let mut gw = gw;
    let _ = tokio::time::timeout(Duration::from_secs(60), gw.child.child_mut().wait()).await;
}
