// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Config-timing rows (T4): over stdio the relay witness judges a line under
//! the generation the line was read under, held through its dispatch, never
//! the one published when it is checked.
//!
//! Driven through the real read loop, as `held_across_a_flip` is: a line is
//! written, the one-shot dispatch pause is armed after the handshake, a
//! reload published on the same session lands while the line is held, and the
//! line is released. A loop that read the live config again after the pause
//! would judge the held line under the new action.
//!
//! An HTTP-side caller was delivered `PROSE` from `alpha:read`, and the stdio
//! operator sends it through `alpha:send`.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::firewall::{CollusionAction, RelayCaller};

const PROSE: &str = "The orchard ledger for the north slope records seven rows of late pears, \
    the grafting dates for each rootstock, the hours the drip lines ran during the dry weeks of \
    August, and which crew pruned the older trees after the second frost. It closes with the \
    count of crates sent to the cooperative press and a note about the broken ladder by the barn.";

/// A backend `alpha` that serves every `tools/call` and `prompts/get` and
/// counts those.
struct Counting(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl crate::transport::Transport for Counting {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/list" {
            let tool = json!({"name": "send", "description": "A tool.", "inputSchema": {"type": "object"}});
            return Ok(JsonRpcResponse::success(id, json!({"tools": [tool]})));
        }
        // Only a relayed call or prompt read counts, not the gateway's own probes.
        if method == "tools/call" || method == "prompts/get" {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        let sent = json!({"content": [{"type": "text", "text": "sent"}], "isError": false});
        Ok(JsonRpcResponse::success(id, sent))
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// The config with the relay action set to `action`, a listed source and a
/// task store in the test's own directory.
fn write_action(path: &Path, action: &str) {
    let tasks = path.with_file_name("tasks");
    let tasks = tasks.display().to_string().replace('\'', "''");
    write_owner_only(
        path,
        format!(
            "security:\n  firewall:\n    enabled: true\n    collusion:\n      action: {action}\n      \
             sources: ['alpha:read']\ntasks:\n  store_dir: '{tasks}'\n"
        ),
    )
    .expect("write");
}

/// A session under `block` over a counting `alpha`, with `PROSE` delivered to
/// another caller from `alpha:read`.
async fn session(dir: &Path, path: &Path) -> (Session, Arc<AtomicUsize>) {
    let sends = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(Counting(Arc::clone(&sends))));
    let s = Session::start_with(dir, path.to_path_buf(), Announce::No, |gateway| {
        assert!(gateway.backends.register(backend));
    })
    .await;
    let firewall = s.meta.firewall_for_test().expect("stdio builds a firewall");
    let http = RelayCaller::Keyed("http-caller");
    firewall.record_delivery(
        http,
        "alpha",
        "read",
        &json!({"content": [{"type": "text", "text": PROSE}]}),
    );
    (s, sends)
}

/// Publish `action` by a reload on the session.
async fn publish(s: &mut Session, path: &Path, action: &str) {
    write_action(path, action);
    s.reload().await;
}

/// The operator's relay line is held at the dispatch pause while `to` is
/// published by a reload on the same session, then released; the answer.
async fn relay_held_across(s: &mut Session, path: &Path, to: &str) -> Value {
    let invoke = json!({"name": "gateway_invoke",
                        "arguments": {"server": "alpha", "tool": "send", "arguments": {"text": PROSE}}});
    held_across(s, path, to, ("tools/call", invoke)).await
}

/// The operator's relay line, sent and answered with no pause: judged under
/// the generation published when it is read.
async fn relay_now(s: &mut Session) -> Value {
    let invoke = json!({"name": "gateway_invoke",
                        "arguments": {"server": "alpha", "tool": "send", "arguments": {"text": PROSE}}});
    let line = s.send("tools/call", invoke).await;
    s.answer(line).await
}

/// A `-32002` relay refusal, not some other refusal under the same code.
fn assert_relay_refused(answer: &Value, row: &str) {
    assert_eq!(
        answer["error"]["code"], -32002,
        "{row}: not refused: {answer}"
    );
    let message = answer["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("Relay detection blocked"),
        "{row}: not the relay refusal: {answer}"
    );
}

/// As [`relay_held_across`], for any relaying `method` line.
async fn held_across(s: &mut Session, path: &Path, to: &str, line: (&str, Value)) -> Value {
    let (method, params) = line;
    let (reached, release) = s.hold.arm();
    let held = s.send(method, params).await;
    crate::test_pause::within("the held line reaches the pause", reached.notified()).await;
    publish(s, path, to).await;
    let want = if to == "block" {
        CollusionAction::Block
    } else {
        CollusionAction::Off
    };
    assert_eq!(
        s.live.get().security.firewall.collusion.action,
        want,
        "the reload did not land"
    );
    release.notify_one();
    s.answer(held).await
}

/// T4a: a line read under `block`, `off` published while it is held: still
/// refused with -32002, and the backend is not called. GREEN pin on base.
#[tokio::test]
async fn t4a_a_held_stdio_line_read_under_block_still_refuses() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("gateway.yaml");
    write_action(&path, "block");
    let (mut s, sends) = session(dir.path(), &path).await;
    let answer = relay_held_across(&mut s, &path, "off").await;
    assert_relay_refused(&answer, "T4a");
    assert_eq!(sends.load(Ordering::SeqCst), 0, "the backend was called");
    // A line read after the reload follows the published `off`.
    let fresh = relay_now(&mut s).await;
    assert!(
        fresh.get("error").is_none(),
        "T4a: a fresh line under off refused: {fresh}"
    );
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "the fresh line was not sent"
    );
}

/// T4b: a line read under `off`, `block` published while it is held:
/// dispatched, the backend called once. RED on base: refused under the
/// startup `block`.
#[tokio::test]
async fn t4b_a_held_stdio_line_read_under_off_still_sends() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("gateway.yaml");
    write_action(&path, "block");
    let (mut s, sends) = session(dir.path(), &path).await;
    publish(&mut s, &path, "off").await;
    let answer = relay_held_across(&mut s, &path, "block").await;
    assert!(answer.get("error").is_none(), "T4b: refused: {answer}");
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "the backend was not called"
    );
    // Control: detection is still armed; a line read under the published
    // `block` is refused.
    let fresh = relay_now(&mut s).await;
    assert_relay_refused(&fresh, "T4b control");
    assert_eq!(sends.load(Ordering::SeqCst), 1, "the fresh line was sent");
}

/// T4c: as T4a on the stdio catalogue: a `prompts/get` line carrying the read
/// text, read under `block`, `off` published while it is held: still refused
/// with -32002, and the backend is not asked for the prompt. A catalogue line
/// read after the reload follows the published `off`: dispatched once.
#[tokio::test]
async fn t4c_a_held_stdio_catalogue_line_read_under_block_still_refuses() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("gateway.yaml");
    write_action(&path, "block");
    let (mut s, sends) = session(dir.path(), &path).await;
    let read = json!({"name": "alpha/summary", "arguments": {"text": PROSE}});
    let answer = held_across(&mut s, &path, "off", ("prompts/get", read.clone())).await;
    assert_relay_refused(&answer, "T4c");
    assert_eq!(sends.load(Ordering::SeqCst), 0, "the backend was asked");
    let line = s.send("prompts/get", read).await;
    let fresh = s.answer(line).await;
    assert!(
        fresh.get("error").is_none(),
        "T4c: a fresh catalogue line under off refused: {fresh}"
    );
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "the fresh catalogue line was not dispatched exactly once"
    );
}
