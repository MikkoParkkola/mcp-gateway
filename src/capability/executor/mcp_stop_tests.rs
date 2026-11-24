// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for capability MCP children under a gateway stop. Race rows run the
//! stop on a thread with its own runtime, so a stop that blocks fails at the
//! row's own bound and never hangs it, and every pause they hold is let go
//! by a guard on whatever path the row leaves by.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::json;

use super::tests::{call, caller, gone_within, python};
use crate::backend::{Backend, BackendRegistry, Handover};
use crate::capability::definition::{McpConfig, ProcessConfig};
use crate::capability::executor::CapabilityExecutor;
use crate::capability::executor::cli_run::Workdir;
use crate::capability::{CapabilityDefinition, parse_capability};

/// The stage each stop row grants: the reaper keeps `KILL_RESERVE` back for
/// the kill and the reap, so the stage must exceed it for the graceful phase
/// to have room; a child slow to read its end of input under load still gets
/// its turn. A child that exits at once ends the stop at once.
const STAGE: Duration =
    crate::transport::KILL_RESERVE_FOR_TEST.saturating_add(Duration::from_secs(4));

fn stop_capability_yaml() -> String {
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cap_exec/fake_mcp.py")
        .display()
        .to_string();
    format!(
        r#"name: stop_probe
description: Its server must not outlive a gateway stop.
schema:
  input:
    type: object
    properties:
      operation:
        type: string
providers:
  primary:
    service: mcp
    timeout: 30
    config:
      command: '{python}'
      args: ['{script}']
      transport: stdio
      env: [CAP_EXEC_TEST_EOF_MARK, CAP_EXEC_TEST_POLL_MARK]
      tool_selector:
        param: operation
        tools:
          say: {{ tool: echo, arguments: {{ message: "hi" }} }}
          deaf: {{ tool: deaf }}
          slow:
            tool: import_binary
            arguments: {{ binary_path: "/x" }}
            wait:
              max_wait_s: 25
              interval_ms: 200
              tool: list_project_binaries
              arguments: {{ expect: "never" }}
              until:
                field: analysis_complete
                equals: true
                array: programs
                match: {{ file_path: "no-such-program" }}
"#,
        python = python(),
    )
}

/// One executor wired to one registry's stop the way the gateway wires it;
/// the env overlay tells the child where to leave its EOF mark.
struct Rig {
    _dir: tempfile::TempDir,
    mark: PathBuf,
    /// Written by the child on each poll of a wait.
    poll_mark: PathBuf,
    registry: Arc<BackendRegistry>,
    executor: CapabilityExecutor,
    cap: CapabilityDefinition,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().expect("a temp dir");
    let mark = dir.path().join("child-read-eof");
    let poll_mark = dir.path().join("child-polled");
    let file = dir.path().join(".env");
    crate::gateway::test_helpers::write_owner_only(
        &file,
        format!(
            "CAP_EXEC_TEST_EOF_MARK={}\nCAP_EXEC_TEST_POLL_MARK={}\n",
            mark.display(),
            poll_mark.display()
        ),
    )
    .expect("the env file writes");
    let overlay = Arc::new(crate::config::EnvOverlay::from_paths(&[file]));
    let env = Arc::new(crate::config::LiveEnv::new(
        overlay,
        crate::config::ResolvedEnvFiles::default(),
    ));
    let registry = Arc::new(BackendRegistry::new());
    let executor = CapabilityExecutor::new()
        .with_env(env)
        .with_stop_deadline(registry.stop_deadline());
    Rig {
        _dir: dir,
        mark,
        poll_mark,
        registry,
        executor,
        cap: parse_capability(&stop_capability_yaml()).expect("the probe parses"),
    }
}

fn mcp_config(cap: &CapabilityDefinition) -> &McpConfig {
    let Some(ProcessConfig::Mcp(config)) = cap.providers.process.get("primary") else {
        panic!("not an mcp provider");
    };
    config
}

/// Run `operation` as caller `a`; the pid its child reports.
async fn child_pid(rig: &Rig, operation: &str) -> String {
    let answer = call(
        &rig.executor,
        &rig.cap,
        json!({ "operation": operation }),
        &caller("a"),
    )
    .await
    .unwrap_or_else(|error| panic!("{operation} failed: {error}"));
    answer["pid"]
        .as_i64()
        .unwrap_or_else(|| panic!("{operation} named no pid: {answer}"))
        .to_string()
}

/// Whether some process answers to `pid` at this moment.
fn alive(pid: &str) -> bool {
    std::process::Command::new("kill")
        .args(["-0", pid])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Room past a stop's own deadline before a row calls it hung.
const HUNG: Duration = Duration::from_secs(10);

/// A stop of `rig`'s registry planned to end within `budget`; a stop still
/// running `HUNG` past that fails the row instead of hanging it.
async fn stop_within(rig: &Rig, budget: Duration, handover: Handover) {
    let stopping = rig
        .registry
        .stop_all_by(tokio::time::Instant::now() + budget, handover);
    tokio::time::timeout(budget + HUNG, stopping)
        .await
        .expect("the stop came back");
}

async fn stop(rig: &Rig, handover: Handover) {
    stop_within(rig, STAGE, handover).await;
}

/// Until the child has answered a poll of the slow call: the call is then
/// inside its wait, not still starting.
async fn polled(rig: &Rig) {
    let give_up = tokio::time::Instant::now() + Duration::from_secs(10);
    while !rig.poll_mark.exists() {
        assert!(
            tokio::time::Instant::now() < give_up,
            "the slow call never polled its child"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Stop `registry` from a thread that owns its own runtime; the receiver
/// hears once the stop is back.
fn stop_on_thread(
    registry: Arc<BackendRegistry>,
) -> (mpsc::Receiver<()>, std::thread::JoinHandle<()>) {
    let (done, returned) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a stop runtime builds");
        let ends = tokio::time::Instant::now() + STAGE;
        runtime.block_on(registry.stop_all_by(ends, Handover::AtEntry));
        let _ = done.send(());
    });
    (returned, thread)
}

/// Lets a held start continue when dropped: no failing row leaves one parked.
struct Go(mpsc::Sender<()>);

impl Go {
    fn now(&self) {
        let _ = self.0.send(());
    }
}

impl Drop for Go {
    fn drop(&mut self) {
        self.now();
    }
}

/// A start that really builds its candidate (directory, program, backend;
/// the process only comes with the first call), reports the directory, then
/// waits for the row.
fn held_start(
    cap: CapabilityDefinition,
    prepared: mpsc::Sender<PathBuf>,
    go: mpsc::Receiver<()>,
) -> impl FnOnce() -> crate::Result<(Arc<Backend>, Workdir)> + Send + 'static {
    move || {
        let lookup = |name: &str| std::env::var_os(name);
        let built = CapabilityExecutor::start_mcp(&cap, mcp_config(&cap), &lookup, &[])?;
        let _ = prepared.send(built.1.path().to_path_buf());
        // The guard dropping its sender counts as the word too.
        let _ = go.recv();
        Ok(built)
    }
}

/// `acquire` as caller `a` from a plain thread, its epoch current for as long
/// as `epoch` is set: the leased child's id, or the refusal as text.
fn acquire_on_thread(
    rig: &Rig,
    epoch: Arc<AtomicBool>,
    start: impl FnOnce() -> crate::Result<(Arc<Backend>, Workdir)> + Send + 'static,
) -> std::thread::JoinHandle<Result<u64, String>> {
    let children = Arc::clone(&rig.executor.mcp_children);
    let cap = rig.cap.clone();
    std::thread::spawn(move || {
        let config = mcp_config(&cap).clone();
        children
            .acquire(
                &cap,
                &config,
                "a",
                (7, Duration::from_secs(30)),
                |_| epoch.load(Ordering::SeqCst),
                start,
            )
            .map(|lease| lease.id)
            .map_err(|error| error.to_string())
    })
}

/// R2. The call the stdio teardown makes (hand over only once hurried), with
/// no hurry: nothing but the participant can end the child here.
#[tokio::test]
async fn r2_the_stdio_stop_ends_a_live_capability_child() {
    let rig = rig();
    let pid = child_pid(&rig, "say").await;
    stop(&rig, Handover::WhenHurried).await;
    assert!(
        gone_within(&pid, Duration::from_secs(1)).await,
        "child {pid} outlived the stdio teardown's stop"
    );
}

/// R2b. Hurried first, the way the stdio teardown's hurry branch goes: that
/// handover takes the child, so the stop called after it has an empty map,
/// and it must still not come back before the child has ended.
#[tokio::test]
async fn r2b_the_stdio_hurry_hands_the_child_over_and_the_stop_waits_for_it() {
    let rig = rig();
    let pid = child_pid(&rig, "say").await;
    let cut = tokio::time::Instant::from_std(
        rig.registry
            .stop_deadline()
            .hurry(std::time::Instant::now()),
    );
    rig.registry.hand_over_now(cut);
    let hurried = rig.registry.stop_all_by(cut, Handover::WhenHurried);
    tokio::time::timeout(STAGE + HUNG, hurried)
        .await
        .expect("the hurried stop came back");
    assert!(
        gone_within(&pid, Duration::from_millis(300)).await,
        "child {pid} was still running when the hurried stop came back"
    );
}

/// R3. Graceful: the child reads up to the end of its input and leaves its
/// mark on the way out, so it was not simply killed.
#[tokio::test]
async fn r3_the_stop_ends_the_child_by_closing_its_stdin() {
    let rig = rig();
    let pid = child_pid(&rig, "say").await;
    stop(&rig, Handover::AtEntry).await;
    assert!(
        gone_within(&pid, Duration::from_secs(1)).await,
        "{pid} still running"
    );
    assert!(rig.mark.exists(), "{pid} never read its input to the end");
}

/// R4. In flight: one call is polling its child when the stop arrives. With
/// the stop back, that process no longer exists, and the call came back as a
/// failure instead of hanging on.
#[tokio::test]
async fn r4_a_busy_child_is_ended_and_its_call_fails() {
    let rig = rig();
    let pid = child_pid(&rig, "say").await;
    let same_caller = caller("a");
    let busy = call(
        &rig.executor,
        &rig.cap,
        json!({ "operation": "slow" }),
        &same_caller,
    );
    let stopping = async {
        polled(&rig).await;
        stop(&rig, Handover::AtEntry).await;
        gone_within(&pid, Duration::from_secs(1)).await
    };
    let (answer, gone) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(busy, stopping)
    })
    .await
    .expect("neither the call nor the stop hangs");
    assert!(gone, "busy child {pid} outlived the stop");
    assert!(answer.is_err(), "the cut-off call answered {answer:?}");
}

/// R4b. The same busy call fails at once: a stopped child refuses every new
/// poll, and the wait takes that refusal as final instead of polling on for
/// the rest of its 25 s.
#[tokio::test]
async fn r4b_a_busy_call_fails_at_once_after_the_stop() {
    let rig = rig();
    child_pid(&rig, "say").await;
    let same_caller = caller("a");
    let busy = async {
        let answer = call(
            &rig.executor,
            &rig.cap,
            json!({ "operation": "slow" }),
            &same_caller,
        )
        .await;
        (answer, tokio::time::Instant::now())
    };
    let stopping = async {
        polled(&rig).await;
        stop(&rig, Handover::AtEntry).await;
        tokio::time::Instant::now()
    };
    let ((answer, answered), stopped) = tokio::time::timeout(Duration::from_secs(40), async {
        tokio::join!(busy, stopping)
    })
    .await
    .expect("the call and the stop both end");
    // The wait's own abort, not some earlier failure of the call.
    assert!(
        answer
            .as_ref()
            .is_err_and(|error| error.to_string().contains("wait aborted")),
        "the cut-off call answered {answer:?}"
    );
    let lingered = answered.saturating_duration_since(stopped);
    assert!(
        lingered < Duration::from_secs(3),
        "the busy call went on polling a stopped child for {lingered:?}"
    );
}

/// R5. Latched: any call after the stop is turned away, with no child
/// started for it.
#[tokio::test]
async fn r5_after_the_stop_a_call_is_refused_and_starts_nothing() {
    let rig = rig();
    stop(&rig, Handover::AtEntry).await;
    let refused = call(
        &rig.executor,
        &rig.cap,
        json!({ "operation": "say" }),
        &caller("a"),
    )
    .await;
    assert!(
        refused
            .as_ref()
            .is_err_and(|error| error.to_string().contains("gateway is stopping")),
        "a call made after the stop answered {refused:?}"
    );
    assert_eq!(rig.executor.mcp_children.len(), 0, "a child was started");
}

/// R6. Deaf: a server that stops reading its input and shrugs off SIGTERM.
/// Only the kill at the deadline ends it, and the stop is not back before:
/// at its return the kill has landed and the child has been reaped. The
/// budget leaves the graceful phases room beyond the kill's own reserve.
#[tokio::test]
async fn r6_the_stop_waits_for_the_kill_of_a_child_that_ignores_it() {
    let rig = rig();
    let pid = child_pid(&rig, "deaf").await;
    let budget = crate::transport::KILL_RESERVE_FOR_TEST + Duration::from_secs(2);
    stop_within(&rig, budget, Handover::AtEntry).await;
    assert!(
        rig.registry.stop_deadline().handed_all_reaped(),
        "the stop came back before deaf child {pid} was killed and reaped"
    );
    assert!(!alive(&pid), "deaf child {pid} still running at the return");
}

/// R8. An idle eviction is paused inside its locked section, the child already
/// taken out of the map. The pause lasts until the stop is back or 300 ms
/// have gone by with the stop still waiting; a stop able to come back during
/// it would have missed the child.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r8_a_stop_racing_an_eviction_still_ends_the_evicted_child() {
    let rig = rig();
    let pid = child_pid(&rig, "say").await;
    let (reached, release) = rig.executor.mcp_children.evict_holds_the_lock.arm();
    let release = crate::test_pause::Release(release);
    let children = Arc::clone(&rig.executor.mcp_children);
    let evicting = std::thread::spawn(move || children.evict(Duration::ZERO, &|_| true));
    crate::test_pause::within("the eviction's pause", reached.notified()).await;

    let (returned, stopping) = stop_on_thread(Arc::clone(&rig.registry));
    let returned_early = returned.recv_timeout(Duration::from_millis(300)).is_ok();
    let running_after_early_return = returned_early && alive(&pid);
    release.now();
    if !returned_early {
        returned
            .recv_timeout(Duration::from_secs(30))
            .expect("the stop comes back once the eviction lets go");
    }
    stopping.join().expect("the stop thread ends");
    evicting.join().expect("the eviction ends");
    assert!(
        !running_after_early_return,
        "the stop came back while evicted child {pid}, out of the map, still ran"
    );
    assert!(
        gone_within(&pid, Duration::from_millis(300)).await,
        "evicted child {pid} was still running when the stop came back"
    );
}

/// R9. The running child of a key goes stale for a call whose start then
/// fails: it must stay in the map and alive, and the next stop still ends it
/// the graceful way.
#[tokio::test]
async fn r9_a_failed_start_leaves_the_stale_child_tracked() {
    let rig = rig();
    let pid = child_pid(&rig, "say").await;
    let key = super::principal(&rig.cap, &caller("a"), false).expect("a principal");
    // A different env fingerprint is what makes the running child stale.
    let refused = rig.executor.mcp_children.acquire(
        &rig.cap,
        mcp_config(&rig.cap),
        &key,
        (7, Duration::from_secs(30)),
        |_| true,
        || Err(crate::Error::Config("this start fails".to_string())),
    );
    assert!(refused.is_err(), "a failed start produced a lease");
    assert_eq!(
        rig.executor.mcp_children.len(),
        1,
        "the stale child left the map with the failed start"
    );
    assert!(alive(&pid), "stale child {pid} was ended untracked");
    stop(&rig, Handover::AtEntry).await;
    assert!(
        gone_within(&pid, Duration::from_secs(1)).await,
        "{pid} still running"
    );
    assert!(rig.mark.exists(), "child {pid} was not ended gracefully");
}

/// R10. With one call still building its child, a stop is back at once; the
/// call is then turned away, its directory removed, and no child is kept.
#[test]
fn r10_a_stop_does_not_wait_for_a_child_being_prepared() {
    let rig = rig();
    let (prepared_tx, prepared) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel();
    let go = Go(go_tx);
    let preparing = acquire_on_thread(
        &rig,
        Arc::new(AtomicBool::new(true)),
        held_start(rig.cap.clone(), prepared_tx, go_rx),
    );
    let dir = prepared
        .recv_timeout(Duration::from_secs(10))
        .expect("the call builds its child");
    let (returned, stopping) = stop_on_thread(Arc::clone(&rig.registry));
    let prompt = returned.recv_timeout(Duration::from_secs(1)).is_ok();
    go.now();
    let outcome = preparing.join().expect("the call ends");
    stopping.join().expect("the stop ends");
    assert!(prompt, "the stop waited on a child still being built");
    assert!(
        outcome
            .as_ref()
            .is_err_and(|text| text.contains("gateway is stopping")),
        "a call built across the stop answered {outcome:?}"
    );
    assert!(!dir.exists(), "unused candidate directory {dir:?} remains");
    assert_eq!(rig.executor.mcp_children.len(), 0, "a child was kept");
}

/// R11. The capability is unloaded while a call is building its child: that
/// call is turned away and the candidate goes, directory and all.
#[test]
fn r11_an_unload_during_preparation_refuses_the_candidate() {
    let rig = rig();
    let epoch = Arc::new(AtomicBool::new(true));
    let (prepared_tx, prepared) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel();
    let go = Go(go_tx);
    let preparing = acquire_on_thread(
        &rig,
        Arc::clone(&epoch),
        held_start(rig.cap.clone(), prepared_tx, go_rx),
    );
    let dir = prepared
        .recv_timeout(Duration::from_secs(10))
        .expect("the call builds its child");
    epoch.store(false, Ordering::SeqCst);
    go.now();
    let outcome = preparing.join().expect("the call ends");
    assert!(
        outcome
            .as_ref()
            .is_err_and(|text| text.contains("changed while this call was starting")),
        "a call built across an unload answered {outcome:?}"
    );
    assert!(!dir.exists(), "refused candidate directory {dir:?} remains");
    assert_eq!(rig.executor.mcp_children.len(), 0, "a child was kept");
}

/// R12. Two calls for the same key build their children side by side; the
/// later one ends up on the child the earlier one put in, and its own
/// candidate is thrown away.
#[test]
fn r12_two_preparations_for_one_key_leave_one_child() {
    let rig = rig();
    let current = Arc::new(AtomicBool::new(true));
    let (first_tx, first_prepared) = mpsc::channel();
    let (first_go_tx, first_go_rx) = mpsc::channel();
    let first_go = Go(first_go_tx);
    let (second_tx, second_prepared) = mpsc::channel();
    let (second_go_tx, second_go_rx) = mpsc::channel();
    let second_go = Go(second_go_tx);
    let first = acquire_on_thread(
        &rig,
        Arc::clone(&current),
        held_start(rig.cap.clone(), first_tx, first_go_rx),
    );
    let first_dir = first_prepared
        .recv_timeout(Duration::from_secs(10))
        .expect("the first call builds");
    let second = acquire_on_thread(
        &rig,
        Arc::clone(&current),
        held_start(rig.cap.clone(), second_tx, second_go_rx),
    );
    let second_dir = second_prepared.recv_timeout(Duration::from_secs(5));
    first_go.now();
    let first_id = first.join().expect("the first call ends");
    second_go.now();
    let second_id = second.join().expect("the second call ends");
    let second_dir = second_dir.expect("the second call built while the first was building");
    assert!(first_id.is_ok(), "first call refused: {first_id:?}");
    assert_eq!(second_id, first_id, "one key ended up with two children");
    assert_eq!(rig.executor.mcp_children.len(), 1, "one key, one child");
    assert!(first_dir.exists(), "the leased child's directory is gone");
    assert!(
        !second_dir.exists(),
        "unused candidate directory {second_dir:?} remains"
    );
}
