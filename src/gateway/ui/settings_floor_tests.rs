// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The config floor seen from the UI: what the settings save route and the
//! manual reload routes answer while the gate is paused, certified, terminal or
//! released, and what the watcher replays afterwards. Every request goes through
//! the real handlers; the gate calls belong to production code, never to a row.

use super::test_support::{BASE, Route, client, decode, set};
use crate::gateway::authz::AdminStanding;
use crate::gateway::meta_mcp::{MetaMcpCallerContext, anonymous_caller};
use crate::gateway::restart_config_floor::seams::{AdmittedPoint, ReloadSource};
use crate::gateway::restart_config_floor::support::{
    self, Probe, WatcherFixture, config_probe, recv_bounded, reload_probe, sha256_hex, tick,
};
use crate::gateway::restart_config_floor::{AdmitKind, ConfigFloor, ConfigGate, GateState};
use crate::gateway::restart_floor::{FloorAdapter, FloorFault};
use crate::gateway::{router::AppState, routes};
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, header::RETRY_AFTER};
use axum::response::IntoResponse;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex, mpsc};
use std::time::SystemTime;
use tokio::time::Instant;

/// Every bounded wait here: `support::BOUND`'s value, spelled locally because the
/// timing gate cannot follow a `crate::` import to a const.
const BOUND: std::time::Duration = std::time::Duration::from_secs(30);

/// Design erratum E1; existing `UiRefused::Busy` status, settings.rs:494 (503 with
/// `Retry-After: 1`), whose flat `{error}` body states the reason.
const BUSY_TEXT: &str = "a restart is being prepared; retry";
/// Design table, Paused and Certified, manual reload column; the UI reload route's flat
/// `{error}` body (ui/mod.rs `reload`) carries it.
const REPLAY_MESSAGE: &str = "a restart is being prepared; the reload runs when it is decided";

/// Design table, Terminal row: the phrase and the save route's `{error, message}` code.
const RESTARTING: (&str, &str) = ("restarting", "the gateway is restarting");
/// Design table, Released row.
const STOPPING: (&str, &str) = ("stopping", "the gateway is stopping");

/// The busy refusal a paused or certified gate gives a UI write.
fn busy_refusal() -> (StatusCode, Value) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        json!({ "error": BUSY_TEXT }),
    )
}

/// The save route's `{error, message}` refusal for a terminal or released gate.
fn save_refusal((error, message): (&str, &str)) -> (StatusCode, Value) {
    (
        StatusCode::CONFLICT,
        json!({ "error": error, "message": message }),
    )
}

/// The file as it stands: bytes, mtime and inode.
type Stat = (Vec<u8>, SystemTime, u64);

#[cfg(unix)]
fn inode(meta: &std::fs::Metadata) -> u64 {
    std::os::unix::fs::MetadataExt::ino(meta)
}
#[cfg(not(unix))]
fn inode(_: &std::fs::Metadata) -> u64 {
    0
}

fn deadline() -> Instant {
    Instant::now() + BOUND
}

/// `BASE` with the `environment` key set to `value`: the key an outside edit moves.
fn with_env(value: &str) -> String {
    let text = BASE.replace("environment: \"dev\"", &format!("environment: \"{value}\""));
    assert_ne!(text, BASE, "fixture: the environment key was not rewritten");
    text
}

/// One route, one gate shared by the floor and the watcher, as production wires it.
struct Fx {
    route: Route,
    gate: ConfigGate,
    floor: ConfigFloor,
    watcher: WatcherFixture,
}

impl Fx {
    async fn new() -> Self {
        let route = Route::new(BASE).await;
        // The route's registry owns the one gate its reload context, the floor and the watcher share.
        let gate = route.state.backends.config_gate();
        let floor = support::floor_over(&route.ctx, &route.path());
        let watcher = WatcherFixture::over(&route.ctx, &route.path());
        Self {
            route,
            gate,
            floor,
            watcher,
        }
    }

    async fn paused() -> Self {
        let mut fx = Self::new().await;
        fx.floor
            .pause(deadline())
            .await
            .expect("fixture: pause answers Ok");
        fx
    }

    async fn certified() -> Self {
        let mut fx = Self::paused().await;
        fx.floor
            .checkpoint(deadline())
            .await
            .expect("fixture: checkpoint certifies");
        fx
    }

    fn stat(&self) -> Stat {
        let meta = std::fs::metadata(self.route.path()).expect("stat");
        (
            std::fs::read(self.route.path()).expect("bytes"),
            meta.modified().expect("mtime"),
            inode(&meta),
        )
    }

    /// A settings save of `environment`, the byte writer's own route.
    async fn save_answer(&self) -> (StatusCode, HeaderMap, Value) {
        let body = self
            .route
            .saved_body(&json!([set("environment", &json!("prod"))]));
        let response = self
            .route
            .response(true, &body.to_string(), client(true))
            .await;
        let headers = response.headers().clone();
        let (status, body) = decode(response).await;
        (status, headers, body)
    }

    /// A manual reload through the UI route.
    async fn reload_answer(&self) -> (StatusCode, Value) {
        let guard = super::super::guard::Guard::for_route(
            routes::UI_RELOAD,
            &Method::POST,
            Some(client(true)),
        );
        let state: Arc<AppState> = self.route.state.clone();
        decode(
            super::super::reload(State(state), guard)
                .await
                .into_response(),
        )
        .await
    }

    /// A manual reload through the `gateway_reload_config` meta-tool.
    async fn meta_reload_answer(&self) -> Value {
        let response = self
            .route
            .state
            .meta_mcp
            .handle_tools_call(
                crate::protocol::RequestId::Number(1),
                "gateway_reload_config",
                json!({}),
                None,
                MetaMcpCallerContext {
                    admin: AdminStanding::Gateway,
                    ..anonymous_caller()
                },
            )
            .await;
        serde_json::to_value(&response).expect("response is JSON")
    }

    fn running_environment(&self) -> Option<String> {
        self.route.ctx.live_config.get().environment.clone()
    }

    fn replays(&self) -> Vec<String> {
        support::reload_values(&self.gate, ReloadSource::Replay)
    }
}

/// A refused write: the exact status and body, and the Retry-After value.
fn assert_refused(
    row: &str,
    answer: (StatusCode, HeaderMap, Value),
    (want_status, want_body): (StatusCode, Value),
    retry: Option<&str>,
) {
    let (status, headers, body) = answer;
    assert_eq!(status, want_status, "{row}: refusal status, body {body}");
    assert_eq!(body, want_body, "{row}: refusal body (exact keys and text)");
    let retry_after = headers.get(RETRY_AFTER).map(|v| v.to_str().expect("ascii"));
    assert_eq!(retry_after, retry, "{row}: Retry-After header");
}

/// A manual reload that ran nothing: 409 with the flat `{error: message}` body.
fn assert_ran_nothing(row: &str, answer: (StatusCode, Value), message: &str) {
    assert_eq!(
        answer.0,
        StatusCode::CONFLICT,
        "{row}: reload status, body {}",
        answer.1
    );
    assert_eq!(answer.1, json!({ "error": message }), "{row}: reload body");
}

/// The meta-tool's refusal carries the same literal text in its error.
fn assert_meta_ran_nothing(row: &str, answer: &Value, message: &str) {
    let text = answer["error"]["message"].as_str().unwrap_or_default();
    assert!(
        text.contains(message),
        "{row}: meta-tool error {text:?} lacks {message:?}: {answer}"
    );
}

fn assert_unchanged(row: &str, fx: &Fx, before: &Stat) {
    assert_eq!(&fx.stat(), before, "{row}: file bytes, mtime and inode");
}

/// P4: while paused a save is refused with the exact body, an outside edit
/// pair is held back by the tick, and resume() replays only the last value.
#[tokio::test]
async fn p4_paused_save_refused_and_replay_once() {
    const ROW: &str = "p4";
    let mut fx = Fx::paused().await;
    let before = fx.stat();
    assert_eq!(before.0, BASE.as_bytes(), "{ROW}: fixture bytes");

    assert_refused(ROW, fx.save_answer().await, busy_refusal(), Some("1"));
    assert_unchanged(ROW, &fx, &before);

    fx.route.write(&with_env("a1"));
    fx.route.write(&with_env("a2"));
    // Plays the OS delivering one coalesced notify event for both writes.
    fx.gate.record_file_event();
    tick(&fx.watcher).await;
    assert!(
        fx.gate.reload_log().is_empty(),
        "{ROW}: a tick while paused reloaded"
    );

    fx.floor.resume();
    tick(&fx.watcher).await;
    assert_eq!(
        fx.gate.reload_log().len(),
        1,
        "{ROW}: exactly one reload after resume"
    );
    assert_eq!(
        fx.replays(),
        ["a2"],
        "{ROW}: the replay carries the last edit"
    );
    assert_eq!(
        fx.running_environment().as_deref(),
        Some("a2"),
        "{ROW}: running value after the replay"
    );
}

/// Which manual reload entry a row drives.
#[derive(Clone, Copy)]
enum Entry {
    UiRoute,
    MetaTool,
}

/// A manual reload through `entry` that must answer "ran nothing" with `message`.
async fn assert_reload_refused(row: &str, fx: &Fx, entry: Entry, message: &str) {
    match entry {
        Entry::UiRoute => assert_ran_nothing(row, fx.reload_answer().await, message),
        Entry::MetaTool => assert_meta_ran_nothing(row, &fx.meta_reload_answer().await, message),
    }
}

/// P5 body: an edit with no watcher event, a manual reload refused while
/// paused, nothing running until resume() and one tick replay it once.
async fn p5_case(row: &str, entry: Entry) {
    if matches!(entry, Entry::MetaTool) {
        // Premise: on an Open gate this caller reaches reload_config and it succeeds,
        // so a later refusal is the gate's and not an authorization refusal.
        let open = Fx::new().await.meta_reload_answer().await;
        assert!(
            open["error"].is_null(),
            "{row}: premise, Open-gate meta reload: {open}"
        );
        assert!(
            !open["result"].is_null(),
            "{row}: premise, Open-gate meta reload gave no result: {open}"
        );
    }
    let mut fx = Fx::paused().await;
    fx.route.write(&with_env("a1"));
    assert_reload_refused(row, &fx, entry, REPLAY_MESSAGE).await;
    tick(&fx.watcher).await;
    assert_eq!(
        fx.running_environment().as_deref(),
        Some("dev"),
        "{row}: running value moved"
    );
    assert!(
        fx.gate.reload_log().is_empty(),
        "{row}: reload log after the paused tick"
    );
    fx.floor.resume();
    tick(&fx.watcher).await;
    assert_eq!(
        fx.gate.reload_log().len(),
        1,
        "{row}: exactly one reload after resume"
    );
    assert_eq!(fx.replays(), ["a1"], "{row}: replay value");
    assert_eq!(
        fx.running_environment().as_deref(),
        Some("a1"),
        "{row}: running value"
    );
}

#[tokio::test]
async fn p5_ui_reload_refused_then_replayed() {
    p5_case("p5 ui route", Entry::UiRoute).await;
}

#[tokio::test]
async fn p5_meta_reload_refused_then_replayed() {
    p5_case("p5 meta tool", Entry::MetaTool).await;
}

/// The owner of backend `a`, the second key P8 writes.
fn owner_of_a(fx: &Fx) -> Option<String> {
    fx.route.ctx.live_config.get().backends["a"].owner.clone()
}

/// P8: a replay and an admitted write racing after resume() both land, by source.
#[tokio::test]
async fn p8_replay_and_admitted_write_both_land() {
    const ROW: &str = "p8";
    let mut fx = Fx::paused().await;
    fx.route.write(&with_env("a1"));
    // Plays the OS delivering the notify event for the outside edit.
    fx.gate.record_file_event();
    fx.floor.resume();
    let body = fx.route.saved_body(&json!([
        {"field": "backends.owner", "backend": "a", "value": {"set": "b1"}}
    ]));
    let (status, answer) = fx.route.raw(true, &body.to_string(), client(true)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{ROW}: the write after resume: {answer}"
    );
    for _ in 0..3 {
        tick(&fx.watcher).await;
    }
    // Each entry records the running `environment` after that reload. The write's
    // own reload reads the disk, which already holds the outside edit, so it logs
    // "a1" too; key B is asserted on the running config below.
    assert_eq!(fx.replays(), ["a1"], "{ROW}: replay entries by value");
    let writes = support::reload_values(&fx.gate, ReloadSource::Write);
    assert_eq!(writes, ["a1"], "{ROW}: write entries by value");
    assert_eq!(fx.gate.reload_log().len(), 2, "{ROW}: no other reload");
    assert_eq!(
        fx.running_environment().as_deref(),
        Some("a1"),
        "{ROW}: key A"
    );
    assert_eq!(owner_of_a(&fx).as_deref(), Some("b1"), "{ROW}: key B");
}

/// P8 subcase: the replay held after its admission counts in flight, so a
/// checkpoint started then is Pending until it is released.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p8_held_replay_blocks_the_next_checkpoint() {
    const ROW: &str = "p8 held";
    let mut fx = Fx::paused().await;
    fx.route.write(&with_env("a1"));
    // Plays the OS delivering the notify event for the outside edit.
    fx.gate.record_file_event();
    let (reached_tx, reached) = mpsc::channel();
    let (release, release_rx) = mpsc::channel::<()>();
    let (reached_tx, release_rx) = (Mutex::new(reached_tx), Mutex::new(release_rx));
    fx.gate.set_admitted_hook(Some(Arc::new(move |point| {
        if point == AdmittedPoint::WatcherAfterAdmission {
            reached_tx.lock().unwrap().send(()).ok();
            release_rx.lock().unwrap().recv_timeout(BOUND).ok();
        }
    })));
    fx.floor.resume();
    let watcher = std::mem::replace(
        &mut fx.watcher,
        WatcherFixture::over(&fx.route.ctx, &fx.route.path()),
    );
    let ticking = tokio::spawn(async move { tick(&watcher).await });
    recv_bounded(&reached, "the replay reaching WatcherAfterAdmission");
    assert_eq!(
        fx.gate.admissions_in_flight(),
        1,
        "{ROW}: replay counted in flight"
    );
    assert_eq!(
        config_probe(&fx.route.path()),
        Probe::Free,
        "{ROW}: config probe"
    );
    let reload_lock = fx.route.ctx.registry.reload_lock_handle();
    assert_eq!(
        reload_probe(&reload_lock),
        Probe::Free,
        "{ROW}: reload probe"
    );
    fx.floor.pause(deadline()).await.expect("second pause");
    let mut checkpoint = fx.floor.checkpoint(deadline());
    assert!(
        futures::poll!(&mut checkpoint).is_pending(),
        "{ROW}: checkpoint settled over a held replay"
    );
    release.send(()).expect("release the hook");
    let done = tokio::time::timeout(BOUND, checkpoint)
        .await
        .expect("checkpoint bound");
    assert!(done.is_ok(), "{ROW}: checkpoint after release: {done:?}");
    tokio::time::timeout(BOUND, ticking)
        .await
        .expect("tick bound")
        .expect("tick task");
    let hash = sha256_hex(with_env("a1").as_bytes());
    let certified = fx.floor.certification().map(|c| c.sha256.clone());
    assert_eq!(
        certified.as_deref(),
        Some(hash.as_str()),
        "{ROW}: certified hash"
    );
}

/// P9 setup assertion: the gate refused this request in state Certified(1).
fn assert_refused_in_certified(row: &str, fx: &Fx, kind: AdmitKind) {
    let last = fx.gate.decisions().last().copied();
    let seen = last.map(|d| (d.kind, d.state, d.admitted));
    let want = Some((kind, GateState::Certified(1), false));
    assert_eq!(seen, want, "{row}: last admission decision");
}

/// P9 (a): a UI write after a successful checkpoint is refused, joined before
/// resume returns, and leaves nothing to replay.
#[tokio::test]
async fn p9a_certified_write_refused_without_replay() {
    const ROW: &str = "p9a";
    let mut fx = Fx::certified().await;
    let before = fx.stat();
    assert_refused(ROW, fx.save_answer().await, busy_refusal(), Some("1"));
    assert_refused_in_certified(ROW, &fx, AdmitKind::Write);
    assert_unchanged(ROW, &fx, &before);
    assert_eq!(
        config_probe(&fx.route.path()),
        Probe::Busy,
        "{ROW}: config probe"
    );
    fx.floor.resume();
    tick(&fx.watcher).await;
    assert!(
        fx.gate.reload_log().is_empty(),
        "{ROW}: a reload followed the refused write"
    );
    assert_unchanged(ROW, &fx, &before);
    assert_eq!(
        fx.running_environment().as_deref(),
        Some("dev"),
        "{ROW}: running value"
    );
}

/// P9 (b): a manual reload after a successful checkpoint folds into the owed replay.
#[tokio::test]
async fn p9b_certified_manual_reload_owes_a_replay() {
    const ROW: &str = "p9b";
    let mut fx = Fx::certified().await;
    assert_ran_nothing(ROW, fx.reload_answer().await, REPLAY_MESSAGE);
    assert_refused_in_certified(ROW, &fx, AdmitKind::ManualReload);
    assert!(
        fx.gate.replay_owed(),
        "{ROW}: replay_owed after the refused reload"
    );
    assert_eq!(
        config_probe(&fx.route.path()),
        Probe::Busy,
        "{ROW}: config probe"
    );
    fx.floor.resume();
    tick(&fx.watcher).await;
    assert_eq!(
        fx.replays(),
        ["dev"],
        "{ROW}: one replay of the unchanged file"
    );
    assert_eq!(fx.gate.reload_log().len(), 1, "{ROW}: no other reload");
}

/// P9 (c): an outside edit with a watcher event is kept, not run, while certified.
#[tokio::test]
async fn p9c_certified_outside_edit_kept_for_replay() {
    const ROW: &str = "p9c";
    let mut fx = Fx::certified().await;
    fx.route.write(&with_env("a1"));
    // Plays the OS delivering the notify event for the outside edit.
    fx.gate.record_file_event();
    tick(&fx.watcher).await;
    assert!(
        fx.gate.reload_log().is_empty(),
        "{ROW}: reload while certified"
    );
    assert_eq!(
        fx.running_environment().as_deref(),
        Some("dev"),
        "{ROW}: running value moved"
    );
    assert!(
        fx.gate.state() == GateState::Certified(1),
        "{ROW}: gate state after the tick"
    );
    fx.floor.resume();
    tick(&fx.watcher).await;
    assert_eq!(fx.replays(), ["a1"], "{ROW}: replay value");
    assert_eq!(fx.gate.reload_log().len(), 1, "{ROW}: no other reload");
}

/// K5: after commit() the reload lock is free, the config lock stays held, and
/// a UI write is refused as restarting.
#[tokio::test]
async fn k5_committed_write_refused_restarting() {
    const ROW: &str = "k5";
    let mut fx = Fx::certified().await;
    fx.floor.commit();
    let reload_lock = fx.route.ctx.registry.reload_lock_handle();
    assert_eq!(
        reload_probe(&reload_lock),
        Probe::Free,
        "{ROW}: reload probe"
    );
    assert_eq!(
        config_probe(&fx.route.path()),
        Probe::Busy,
        "{ROW}: config probe"
    );
    assert_refused(ROW, fx.save_answer().await, save_refusal(RESTARTING), None);
}

/// How a K8 case ended the floor.
#[derive(Clone, Copy)]
enum End {
    Stop,
    Commit,
}

/// K8 body: every entry refused with the end's exact text, repeats change no state.
async fn k8_case(row: &str, end: End) {
    let (state, (error, message)) = match end {
        End::Stop => (GateState::Released, STOPPING),
        End::Commit => (GateState::Terminal, RESTARTING),
    };
    let mut fx = Fx::certified().await;
    match end {
        End::Stop => fx.floor.release_for_stop(),
        End::Commit => fx.floor.commit(),
    }
    assert_refused(
        row,
        fx.save_answer().await,
        save_refusal((error, message)),
        None,
    );
    assert_ran_nothing(row, fx.reload_answer().await, message);
    fx.route.write(&with_env("a1"));
    // Plays the OS delivering the notify event for the outside edit.
    fx.gate.record_file_event();
    tick(&fx.watcher).await;
    assert!(
        fx.gate.reload_log().is_empty(),
        "{row}: a watcher tick reloaded"
    );
    for round in 1..=2 {
        fx.floor.resume();
        fx.floor.release_for_stop();
        assert_eq!(fx.gate.state(), state, "{row}: state after repeat {round}");
        let paused = fx.floor.pause(deadline()).await;
        assert_eq!(
            paused,
            Err(FloorFault::Unavailable),
            "{row}: pause after repeat {round}"
        );
    }
}

#[tokio::test]
async fn k8_released_refuses_everything_stopping() {
    k8_case("k8 released", End::Stop).await;
}

#[tokio::test]
async fn k8_terminal_refuses_everything_restarting() {
    k8_case("k8 terminal", End::Commit).await;
}
