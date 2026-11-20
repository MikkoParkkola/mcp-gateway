// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T4: the control session issues the fetch's credential, answers `expired`
//! only once that credential's tunnels are shut, and revokes on any other
//! line or a closed socket.

use super::super::super::control::{CONTROL_BOUNDS, ControlBounds, serve_session};
use super::{Rig, connect_bytes, open, rig, send, status};
use crate::preview_sandbox::Refusal;
use crate::preview_sandbox::control_msg::FetchStep;
use std::os::fd::AsFd as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::UnixStream;

const NPM: &str = "registry.npmjs.org:443";

/// Over the 10 s hang-guard floor; a session that waits on a line that never
/// comes fails here instead of hanging the row.
const GUARD: Duration = Duration::from_secs(15);

fn basic(secret: &str) -> String {
    use base64::Engine as _;
    let raw = format!("x:{secret}");
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(raw)
    )
}

/// The status a CONNECT under `secret` gets.
async fn status_under(rig: &Rig, secret: &str) -> u16 {
    status(&send(rig, &connect_bytes(NPM, Some(&basic(secret)))).await)
}

fn deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(60)
}

/// The credential out of the gateway's answer to `fetch_start`.
fn secret_of(line: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(line).expect("credential line");
    let secret = v["credential"]
        .as_str()
        .expect("credential field")
        .to_owned();
    assert_eq!(secret.len(), 64, "{line}");
    assert!(v["deadline_ms"].as_u64().is_some_and(|ms| ms > 0), "{line}");
    secret
}

/// T4, kills "expired is sent before the credential's tunnels are shut".
#[tokio::test(flavor = "current_thread")]
async fn s1_expired_comes_only_after_the_credentials_tunnels_are_shut() {
    let rig = rig().await;
    let (helper, gateway) = UnixStream::pair().expect("pair");
    // When the revoke starts, nothing may be waiting for the helper yet: the
    // gateway writes `expired` only after the revoke shut every tunnel.
    let probe = helper.as_fd().try_clone_to_owned().expect("dup");
    let waiting = Arc::new(Mutex::new(None));
    let seen = waiting.clone();
    rig.proxy.set_on_end(Box::new(move || {
        let queued = rustix::io::ioctl_fionread(&probe).unwrap_or(u64::MAX);
        *seen.lock().expect("lock") = Some(queued);
    }));
    let session = serve_session(gateway, &rig.proxy, deadline(), CONTROL_BOUNDS);
    let script = async {
        let (read, mut write) = helper.into_split();
        let mut read = BufReader::new(read);
        write
            .write_all(b"{\"fetch_start\":true}\n")
            .await
            .expect("write");
        let mut line = String::new();
        read.read_line(&mut line).await.expect("credential");
        let secret = secret_of(&line);
        let mut tunnel = open(&rig, &connect_bytes(NPM, Some(&basic(&secret))))
            .await
            .expect("open");
        assert_eq!(status(&tunnel.head().await), 200);
        write
            .write_all(b"{\"fetch_done\":true}\n")
            .await
            .expect("write");
        line.clear();
        read.read_line(&mut line).await.expect("expired");
        assert_eq!(line, "{\"expired\":true}\n");
        assert!(tunnel.closed().await, "the tunnel outlived `expired`");
        write.write_all(b"{\"run\":true}\n").await.expect("write");
        secret
    };
    let (served, secret) = tokio::join!(session, script);
    served.expect("the session");
    assert_eq!(
        *waiting.lock().expect("lock"),
        Some(0),
        "`expired` was queued before the revoke"
    );
    assert_eq!(status_under(&rig, &secret).await, 407);
}

/// T4, kills "an out-of-order, false or unrecognised line is accepted".
#[tokio::test(flavor = "current_thread")]
async fn s2_any_other_line_ends_the_session_and_revokes() {
    let first = [
        "{\"fetch_done\":true}",
        "{\"fetch_start\":false}",
        "{\"fetch_start\":true,\"extra\":1}",
        "not json",
    ];
    for line in first {
        let rig = rig().await;
        let (mut helper, gateway) = UnixStream::pair().expect("pair");
        helper
            .write_all(format!("{line}\n").as_bytes())
            .await
            .expect("write");
        let served = serve_session(gateway, &rig.proxy, deadline(), CONTROL_BOUNDS);
        let served = tokio::time::timeout(GUARD, served)
            .await
            .unwrap_or_else(|_| panic!("{line}: the session did not end within the guard"));
        assert!(served.is_err(), "{line}");
    }
    // After the credential: a second fetch_start, an unknown key, or a false
    // fetch_done ends the session, and the credential stops working.
    for line in [
        "{\"fetch_start\":true}",
        "{\"fetch_done\":true,\"x\":0}",
        "{\"fetch_done\":false}",
        // RF3: `refused` is the one extra key, never with another, never null,
        // and only a listed step.
        "{\"fetch_done\":true,\"refused\":\"npm-ci\",\"x\":0}",
        "{\"fetch_done\":true,\"refused\":null}",
        "{\"fetch_done\":true,\"refused\":\"deadline\"}",
    ] {
        let rig = rig().await;
        let (helper, gateway) = UnixStream::pair().expect("pair");
        let session = serve_session(gateway, &rig.proxy, deadline(), CONTROL_BOUNDS);
        let script = async {
            let (read, mut write) = helper.into_split();
            let mut read = BufReader::new(read);
            write
                .write_all(b"{\"fetch_start\":true}\n")
                .await
                .expect("write");
            let mut issued = String::new();
            read.read_line(&mut issued).await.expect("credential");
            write
                .write_all(format!("{line}\n").as_bytes())
                .await
                .expect("write");
            // The socket stays open until the session ends, so an error can
            // only be the session's refusal, never a write to a closed peer.
            (secret_of(&issued), read, write)
        };
        let (served, (secret, _read, _write)) = tokio::join!(session, script);
        assert!(served.is_err(), "{line}");
        assert_eq!(status_under(&rig, &secret).await, 407, "{line}");
    }
}

/// T4, kills "a helper that dies mid-fetch leaves its credential live".
#[tokio::test(flavor = "current_thread")]
async fn s3_a_closed_socket_mid_fetch_revokes_the_credential() {
    let rig = rig().await;
    let (helper, gateway) = UnixStream::pair().expect("pair");
    let session = serve_session(gateway, &rig.proxy, deadline(), CONTROL_BOUNDS);
    let script = async {
        let (read, mut write) = helper.into_split();
        let mut read = BufReader::new(read);
        write
            .write_all(b"{\"fetch_start\":true}\n")
            .await
            .expect("write");
        let mut issued = String::new();
        read.read_line(&mut issued).await.expect("credential");
        drop((read, write));
        secret_of(&issued)
    };
    let (served, secret) = tokio::join!(session, script);
    assert!(served.is_err());
    assert_eq!(status_under(&rig, &secret).await, 407);
}

/// T4, kills "a dropped session leaves its credential live": the session
/// future is dropped right after the credential went out.
#[tokio::test(flavor = "current_thread")]
async fn s4_a_dropped_session_revokes_the_credential() {
    let rig = rig().await;
    let (helper, gateway) = UnixStream::pair().expect("pair");
    let (read, mut write) = helper.into_split();
    let mut read = BufReader::new(read);
    let secret = {
        let session = serve_session(gateway, &rig.proxy, deadline(), CONTROL_BOUNDS);
        tokio::pin!(session);
        write
            .write_all(b"{\"fetch_start\":true}\n")
            .await
            .expect("write");
        let mut issued = String::new();
        tokio::select! {
            _ = &mut session => panic!("the session ended before the credential was read"),
            read = read.read_line(&mut issued) => { read.expect("credential"); }
        }
        secret_of(&issued)
    };
    assert_eq!(status_under(&rig, &secret).await, 407);
}

const SEC: Duration = Duration::from_secs(1);

/// R7a, kills "the setup bound is not applied to `fetch_start`": a silent
/// helper is cut off at the setup bound (the frame bound here is past the
/// guard, so only the setup bound can end it in time).
#[tokio::test(flavor = "current_thread")]
async fn r7a_a_helper_silent_through_setup_is_refused() {
    let rig = rig().await;
    let (_helper, gateway) = UnixStream::pair().expect("pair");
    let bounds = ControlBounds {
        setup: SEC,
        frame: 30 * SEC,
        ..CONTROL_BOUNDS
    };
    let served = tokio::time::timeout(
        GUARD,
        serve_session(gateway, &rig.proxy, deadline(), bounds),
    )
    .await
    .expect("the session did not end within the guard");
    assert!(served.is_err());
}

/// R7b, kills "`fetch_start` keeps the old 5 s frame bound": a helper whose
/// setup takes longer than a frame still gets its credential.
// The paused clock makes the helper's pause and the session's bounds
// virtual timers, fired in order whatever the load. The only I/O peer is the
// script future on this same thread, which writes synchronously; and the
// session's `timeout` polls its read before its timer, so a clock that
// auto-advances past a ready read still takes the read.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn r7b_a_fetch_start_after_the_frame_bound_but_within_setup_is_served() {
    let rig = rig().await;
    let (helper, gateway) = UnixStream::pair().expect("pair");
    let bounds = ControlBounds {
        setup: 10 * SEC,
        frame: SEC,
        ..CONTROL_BOUNDS
    };
    let session = serve_session(gateway, &rig.proxy, deadline(), bounds);
    let script = async {
        let (read, mut write) = helper.into_split();
        let mut read = BufReader::new(read);
        // The helper's root build, paced: the send comes after a frame bound.
        tokio::time::sleep(2 * SEC).await;
        write
            .write_all(b"{\"fetch_start\":true}\n")
            .await
            .expect("write");
        let mut issued = String::new();
        read.read_line(&mut issued).await.expect("credential");
        write
            .write_all(b"{\"fetch_done\":true}\n")
            .await
            .expect("write");
        let mut expired = String::new();
        read.read_line(&mut expired).await.expect("expired");
        write.write_all(b"{\"run\":true}\n").await.expect("write");
        (issued, expired)
    };
    let (served, (issued, expired)) =
        tokio::time::timeout(GUARD, async { tokio::join!(session, script) })
            .await
            .expect("the session did not end within the guard");
    assert!(served.is_ok(), "{served:?}");
    secret_of(&issued);
    assert_eq!(expired, "{\"expired\":true}\n");
}

/// R7c, kills "the setup bound outlives the preview's deadline": a helper
/// that never asks is cut off at the deadline, not at the setup bound (both
/// bounds here are past the guard, so only the deadline can end it in time),
/// and gets no credential.
#[tokio::test(flavor = "current_thread")]
async fn r7c_the_setup_wait_ends_at_the_preview_deadline() {
    let rig = rig().await;
    let (helper, gateway) = UnixStream::pair().expect("pair");
    let bounds = ControlBounds {
        setup: 30 * SEC,
        frame: 30 * SEC,
        ..CONTROL_BOUNDS
    };
    let soon = tokio::time::Instant::now() + SEC;
    let session = serve_session(gateway, &rig.proxy, soon, bounds);
    // Event-driven: the helper only waits for the gateway to end the session.
    let script = async {
        let mut read = BufReader::new(helper);
        let mut answer = String::new();
        let _ = read.read_line(&mut answer).await;
        answer
    };
    let (served, answer) = tokio::time::timeout(GUARD, async { tokio::join!(session, script) })
        .await
        .expect("the session did not end within the guard");
    assert!(served.is_err());
    assert_eq!(answer, "", "no credential after the deadline");
}

/// R7d, kills "the setup bound also covers the rest of `fetch_start`": a
/// partial `fetch_start` is cut off at the frame bound (the setup bound here
/// is past the guard). Passes on the red commit too: it pins that the new
/// setup bound is applied to the first byte only.
#[tokio::test(flavor = "current_thread")]
async fn r7d_a_partial_fetch_start_is_cut_off_at_the_frame_bound() {
    let rig = rig().await;
    let (mut helper, gateway) = UnixStream::pair().expect("pair");
    helper.write_all(b"{\"fetch").await.expect("write");
    let bounds = ControlBounds {
        setup: 30 * SEC,
        frame: SEC,
        ..CONTROL_BOUNDS
    };
    let served = tokio::time::timeout(
        GUARD,
        serve_session(gateway, &rig.proxy, deadline(), bounds),
    )
    .await
    .expect("the session did not end within the guard");
    assert!(served.is_err());
}

/// R7f, kills "the rest of `fetch_start` outlives the preview's deadline": a
/// `fetch_start` begun before the deadline whose rest never comes is cut off
/// at the deadline, not at the frame bound (past the guard here), and no
/// credential is issued.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn r7f_the_rest_of_fetch_start_ends_at_the_preview_deadline() {
    let rig = rig().await;
    let (helper, gateway) = UnixStream::pair().expect("pair");
    let bounds = ControlBounds {
        setup: 30 * SEC,
        frame: 30 * SEC,
        ..CONTROL_BOUNDS
    };
    let soon = tokio::time::Instant::now() + SEC;
    let session = serve_session(gateway, &rig.proxy, soon, bounds);
    let script = async {
        let (read, mut write) = helper.into_split();
        let mut read = BufReader::new(read);
        write.write_all(b"{\"fetch").await.expect("write");
        let mut answer = String::new();
        let _ = read.read_line(&mut answer).await;
        answer
    };
    let (served, answer) = tokio::time::timeout(GUARD, async { tokio::join!(session, script) })
        .await
        .expect("the session did not end within the guard");
    assert!(served.is_err());
    assert_eq!(answer, "", "no credential after the deadline");
}

/// R7g, kills "`expired` is sent after the preview's deadline": a
/// `fetch_done` whose first byte comes just before the deadline and whose
/// rest comes just after ends the session at the deadline, and the helper
/// never gets `expired`, so its target never runs.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn r7g_no_expired_after_the_preview_deadline() {
    let rig = rig().await;
    let (helper, gateway) = UnixStream::pair().expect("pair");
    let bounds = ControlBounds {
        setup: 30 * SEC,
        frame: 30 * SEC,
        ..CONTROL_BOUNDS
    };
    let soon = tokio::time::Instant::now() + 2 * SEC;
    let session = serve_session(gateway, &rig.proxy, soon, bounds);
    let script = async {
        let (read, mut write) = helper.into_split();
        let mut read = BufReader::new(read);
        write
            .write_all(b"{\"fetch_start\":true}\n")
            .await
            .expect("write");
        let mut issued = String::new();
        read.read_line(&mut issued).await.expect("credential");
        tokio::time::sleep_until(soon - Duration::from_millis(100)).await;
        write.write_all(b"{\"fetch_").await.expect("write");
        tokio::time::sleep_until(soon + Duration::from_millis(100)).await;
        let _ = write.write_all(b"done\":true}\n").await;
        let mut expired = String::new();
        let _ = read.read_line(&mut expired).await;
        (issued, expired)
    };
    let (served, (issued, expired)) =
        tokio::time::timeout(GUARD, async { tokio::join!(session, script) })
            .await
            .expect("the session did not end within the guard");
    assert!(served.is_err(), "{served:?}");
    secret_of(&issued);
    assert_eq!(expired, "", "no expired after the deadline");
}

/// R7h, kills "a `fetch_start` read after the preview's deadline gets a
/// credential" (the design's R7c case): a `fetch_start` already waiting when
/// the gateway first reads, after the deadline, is refused and no credential
/// is written.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn r7h_a_fetch_start_read_after_the_deadline_gets_no_credential() {
    let rig = rig().await;
    let (helper, gateway) = UnixStream::pair().expect("pair");
    let (read, mut write) = helper.into_split();
    write
        .write_all(b"{\"fetch_start\":true}\n")
        .await
        .expect("write");
    let passed = tokio::time::Instant::now();
    // The reactor sees the line waiting before the gateway's first read.
    tokio::time::sleep(SEC).await;
    let served = tokio::time::timeout(
        GUARD,
        serve_session(gateway, &rig.proxy, passed, CONTROL_BOUNDS),
    )
    .await
    .expect("the session did not end within the guard");
    assert!(served.is_err(), "{served:?}");
    let mut answer = String::new();
    let _ = BufReader::new(read).read_line(&mut answer).await;
    assert_eq!(answer, "", "no credential after the deadline");
}

/// R7i, kills "the rest of `fetch_done` outlives the preview's deadline": a
/// `fetch_done` whose first byte comes just before the deadline and whose rest
/// never comes ends the session at the deadline, not a frame bound after that
/// first byte: the helper finds its socket closed a second past the deadline.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn r7i_the_rest_of_fetch_done_ends_at_the_preview_deadline() {
    let rig = rig().await;
    let (helper, gateway) = UnixStream::pair().expect("pair");
    let bounds = ControlBounds {
        setup: 30 * SEC,
        frame: 30 * SEC,
        ..CONTROL_BOUNDS
    };
    let soon = tokio::time::Instant::now() + 5 * SEC;
    let session = serve_session(gateway, &rig.proxy, soon, bounds);
    let script = async {
        let (read, mut write) = helper.into_split();
        let mut read = BufReader::new(read);
        write
            .write_all(b"{\"fetch_start\":true}\n")
            .await
            .expect("write");
        let mut issued = String::new();
        read.read_line(&mut issued).await.expect("credential");
        tokio::time::sleep_until(soon - Duration::from_millis(100)).await;
        write.write_all(b"{\"fetch_").await.expect("write");
        // The write half stays open here: a close would end the session too.
        let mut rest = String::new();
        let closed = tokio::time::timeout_at(soon + SEC, read.read_line(&mut rest)).await;
        (issued, closed.is_ok())
    };
    let (served, (issued, closed)) =
        tokio::time::timeout(GUARD, async { tokio::join!(session, script) })
            .await
            .expect("the session did not end within the guard");
    assert!(served.is_err(), "{served:?}");
    secret_of(&issued);
    assert!(
        closed,
        "the session was still open a second past the deadline"
    );
}

/// RF1 (NPM.8), kills "a refused fetch is reported as a start" and "a refused
/// fetch is answered with `expired`": for every step, a `fetch_done` naming it
/// ends the session with that step's fixed words, never writes `expired`,
/// shuts the tunnel the credential opened, and the credential stops working.
#[tokio::test(flavor = "current_thread")]
async fn rf1_a_refused_fetch_ends_the_session_with_its_step() {
    for step in FetchStep::ALL {
        let rig = rig().await;
        let (helper, gateway) = UnixStream::pair().expect("pair");
        let session = serve_session(gateway, &rig.proxy, deadline(), CONTROL_BOUNDS);
        let script = async {
            let (read, mut write) = helper.into_split();
            let mut read = BufReader::new(read);
            write
                .write_all(b"{\"fetch_start\":true}\n")
                .await
                .expect("write");
            let mut line = String::new();
            read.read_line(&mut line).await.expect("credential");
            let secret = secret_of(&line);
            let mut tunnel = open(&rig, &connect_bytes(NPM, Some(&basic(&secret))))
                .await
                .expect("open");
            assert_eq!(status(&tunnel.head().await), 200);
            let done = serde_json::json!({"fetch_done": true, "refused": step});
            write
                .write_all(format!("{done}\n").as_bytes())
                .await
                .expect("write");
            line.clear();
            let _ = read.read_line(&mut line).await;
            (secret, line, tunnel.closed().await)
        };
        let (served, (secret, after, closed)) =
            tokio::time::timeout(GUARD, async { tokio::join!(session, script) })
                .await
                .expect("the session did not end within the guard");
        assert_eq!(
            served,
            Err(Refusal::Step(step.describe().into())),
            "{step:?}"
        );
        assert_eq!(
            after, "",
            "{step:?}: a line came after the refused fetch_done"
        );
        assert!(closed, "{step:?}: the tunnel outlived the refusal");
        assert_eq!(status_under(&rig, &secret).await, 407, "{step:?}");
    }
}

/// RF2 (NPM.8), kills "the refusal echoes what the sandbox sent": a
/// `refused` value outside the step set (the credential itself, a URL that
/// carries it, a path) or `null` ends the session with fixed words that hold
/// none of it, no log line holds it either, and the credential stops working.
#[tokio::test(flavor = "current_thread")]
async fn rf2_an_unlisted_step_is_refused_without_echo() {
    for kind in ["credential", "url", "path", "null"] {
        // Current-thread runtime: the session's and the proxy's tasks log here.
        let (logs, _logging) = crate::gateway::session_id::log_capture::capture_debug();
        let rig = rig().await;
        let (helper, gateway) = UnixStream::pair().expect("pair");
        let session = serve_session(gateway, &rig.proxy, deadline(), CONTROL_BOUNDS);
        let script = async {
            let (read, mut write) = helper.into_split();
            let mut read = BufReader::new(read);
            write
                .write_all(b"{\"fetch_start\":true}\n")
                .await
                .expect("write");
            let mut line = String::new();
            read.read_line(&mut line).await.expect("credential");
            let secret = secret_of(&line);
            let value = match kind {
                "credential" => serde_json::Value::from(secret.clone()),
                "url" => {
                    serde_json::Value::from(format!("https://x:{secret}@registry.npmjs.org/p"))
                }
                "path" => serde_json::Value::from("/home/runner/.npmrc"),
                _ => serde_json::Value::Null,
            };
            let done = serde_json::json!({"fetch_done": true, "refused": value});
            write
                .write_all(format!("{done}\n").as_bytes())
                .await
                .expect("write");
            secret
        };
        let (served, secret) = tokio::time::timeout(GUARD, async { tokio::join!(session, script) })
            .await
            .expect("the session did not end within the guard");
        let refusal = served.expect_err(kind);
        let text = format!("{refusal:?} {refusal}");
        for leaked in [secret.as_str(), "registry.npmjs.org/p", ".npmrc"] {
            assert!(!text.contains(leaked), "{kind}: {text}");
        }
        assert_eq!(status_under(&rig, &secret).await, 407, "{kind}");
        let logged = logs.text();
        // Positive control: the capture saw the proxy refuse the revoked credential.
        assert!(
            logged.contains("preview proxy refused a request"),
            "{kind}: {logged}"
        );
        for leaked in [secret.as_str(), "registry.npmjs.org/p", ".npmrc"] {
            assert!(
                !logged.contains(leaked),
                "{kind}: a log line holds {leaked}"
            );
        }
    }
}

/// RF7 (G1), kills "the start is reported before the helper acknowledges
/// `expired`": a helper that reads `expired` and then sends nothing, `run`
/// false, `run` of the wrong type, an extra key, the credential as the value
/// or beside `run` true, half a line, or the right line after the deadline,
/// gets no start; the session refuses at its deadline or on the line, and the
/// refusal holds neither the credential nor the line's canary.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn rf7_no_start_without_the_runs_acknowledgement() {
    const CANARY: &str = "rf7-canary-3d9e";
    let kinds = [
        "none",
        "false",
        "string",
        "extra",
        "credential",
        "credential-extra",
        "truncated",
        "late",
    ];
    for kind in kinds {
        let rig = rig().await;
        let (helper, gateway) = UnixStream::pair().expect("pair");
        let soon = tokio::time::Instant::now() + 5 * SEC;
        let session = serve_session(gateway, &rig.proxy, soon, CONTROL_BOUNDS);
        let script = async {
            let (read, mut write) = helper.into_split();
            let mut read = BufReader::new(read);
            write
                .write_all(b"{\"fetch_start\":true}\n")
                .await
                .expect("write");
            let mut line = String::new();
            read.read_line(&mut line).await.expect("credential");
            let secret = secret_of(&line);
            write
                .write_all(b"{\"fetch_done\":true}\n")
                .await
                .expect("write");
            line.clear();
            read.read_line(&mut line).await.expect("expired");
            let ack = match kind {
                "none" => String::new(),
                "false" => "{\"run\":false}\n".to_owned(),
                "string" => format!("{{\"run\":\"{CANARY}\"}}\n"),
                "extra" => format!("{{\"run\":true,\"step\":\"{CANARY}\"}}\n"),
                "credential" => format!("{{\"run\":\"{secret}\"}}\n"),
                "credential-extra" => format!("{{\"run\":true,\"x\":\"{secret}\"}}\n"),
                "truncated" => format!("{{\"run\":\"{CANARY}"),
                _ => {
                    // Past the session's 5 s deadline.
                    tokio::time::sleep(6 * SEC).await;
                    "{\"run\":true}\n".to_owned()
                }
            };
            // The session may have refused already; a failed write is fine.
            let _ = write.write_all(ack.as_bytes()).await;
            // The write half stays open: only the line, or its absence, ends it.
            let mut rest = String::new();
            let _ = read.read_line(&mut rest).await;
            (line, secret)
        };
        let (served, (expired, secret)) =
            tokio::time::timeout(GUARD, async { tokio::join!(session, script) })
                .await
                .expect("the session did not end within the guard");
        assert_eq!(expired, "{\"expired\":true}\n", "{kind}");
        let refusal = served.expect_err(kind);
        let text = format!("{refusal:?} {refusal}");
        for echoed in [secret.as_str(), CANARY] {
            assert!(
                !text.contains(echoed),
                "{kind}: the refusal echoes the line"
            );
        }
    }
}
