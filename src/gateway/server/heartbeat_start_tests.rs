// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Heartbeat rows that start a real server (test plan W1/F7, W2/F8): a
//! hardened start sends nothing, and a standard start answers at once while
//! its heartbeat is still waiting on a receiver that never answers. Here,
//! under the server module, because the start seams are the server's own.

use std::time::Duration;

use crate::heartbeat::fixtures::{Answer, Listener, nov19, test_client};
use crate::heartbeat::seam;
use crate::security::posture::SecurityPosture;

/// Wait up to 30 s of real time for `done`.
async fn until(what: &str, done: impl Fn() -> bool) {
    let r = crate::test_wait::wait_real_time(Duration::from_secs(30), done).await;
    assert!(r.is_ok(), "{what} did not happen within 30 s");
}

/// A target for a row's dir: its listener, the test client, the 19th.
fn target_for(rx: &Listener) -> seam::Target {
    seam::Target {
        url: rx.url(),
        client: test_client(),
        today: nov19,
        // limit-under-test (absorbed-by: until): only the task's check period; a slow runner checks less often before until's bound
        every: Duration::from_millis(50),
        stall: None,
    }
}

/// A target whose client has no timeout at all: against a receiver that
/// never answers, a start that awaited the heartbeat would never answer,
/// far past the 30 s the rows allow.
fn slow_target_for(rx: &Listener) -> seam::Target {
    let mut target = target_for(rx);
    target.client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("client");
    target
}

/// A running HTTP gateway and how long it took from construction to answer
/// `/livez`.
struct RunningHttp {
    trigger: tokio::sync::oneshot::Sender<()>,
    server: tokio::task::JoinHandle<crate::Result<()>>,
    status: u16,
    took: Duration,
}

/// Start the HTTP gateway on `dir` with `posture` and GET `/livez` (it
/// answers whenever the server serves; `/health` also reports backend and
/// capability health, which a hardened start may degrade); the
/// whole of it (construction, bind, answer) is bounded at 30 s.
async fn start_http(dir: &std::path::Path, posture: SecurityPosture) -> RunningHttp {
    let started = std::time::Instant::now();
    let run = async {
        let mut config = crate::config::Config::default();
        config.server.host = "127.0.0.1".to_string();
        config.server.port = 0;
        config.tasks.store_dir = dir.join("tasks").to_string_lossy().into_owned();
        config.security.posture = posture;
        // What a hardened HTTP start needs, set for both postures so the
        // posture is the only difference between a row and its control (A9):
        // a signing secret (hardened forces signing), and a caller key for the
        // anomaly detector hardened turns on (auth with a long token), whose
        // audit log then opens under the row's own dir.
        config.security.message_signing.shared_secret =
            crate::security::posture::tests::SIGNING_SECRET.to_string();
        config.auth.enabled = true;
        config.auth.bearer_token = Some("heartbeat-start-row-token-0123456789".to_string());
        config.security.transparency_log.enabled = Some(true);
        config.security.transparency_log.path = dir
            .join("audit")
            .join("log.jsonl")
            .to_string_lossy()
            .into_owned();
        let mut gateway = super::super::Gateway::new(config)
            .await
            .expect("a gateway")
            .with_data_dir(dir.to_path_buf());
        let bound = gateway.bound_port_for_test();
        let trigger = gateway.shutdown_trigger_for_test();
        let server = tokio::spawn(async move { Box::pin(gateway.run()).await });
        // A start that ends before binding says why, not just that it ended.
        let Ok(port) = bound.await else {
            panic!("the server ended before binding: {:?}", server.await);
        };
        let status = reqwest::Client::new()
            .get(format!("http://127.0.0.1:{port}/livez"))
            .send()
            .await
            .map_or(0, |r| r.status().as_u16());
        (trigger, server, status)
    };
    let (trigger, server, status) = tokio::time::timeout(Duration::from_secs(30), Box::pin(run))
        .await
        .expect("constructed, bound and answered /livez within 30 s");
    RunningHttp {
        trigger,
        server,
        status,
        took: started.elapsed(),
    }
}

impl RunningHttp {
    /// Trigger shutdown and require `run` to return Ok within 30 s.
    async fn stop(self) {
        self.trigger.send(()).expect("run holds the trigger");
        let ended = tokio::time::timeout(Duration::from_secs(30), self.server)
            .await
            .expect("run returns after the trigger")
            .expect("run does not panic");
        assert!(ended.is_ok(), "{ended:?}");
    }
}

/// W1 + F7. A hardened HTTP gateway, observed while it runs, opens no
/// connection to the receiver and creates no heartbeat state. Control: the
/// standard posture, against a receiver that never answers and a client that
/// would wait a minute, answers `/livez` within 30 s of construction and
/// connects to the receiver before it is stopped.
#[tokio::test]
async fn http_start_hardened_sends_nothing() {
    let rx = Listener::start(Answer::NoContent).await;
    let dir = crate::test_dir_keep::kept_tempdir();
    let _guard = seam::register(dir.path(), target_for(&rx));
    let hardened = Box::pin(start_http(dir.path(), SecurityPosture::Hardened)).await;
    assert_eq!(hardened.status, 200);
    // The task's first check has finished (an event, not a wait): it
    // skipped for the posture.
    until("the hardened check", || {
        seam::outcomes(dir.path()).contains(&crate::heartbeat::Outcome::Skipped(
            crate::heartbeat::Skip::Hardened,
        ))
    })
    .await;
    assert_eq!(rx.connections(), 0, "a hardened start sent");
    assert!(
        !dir.path().join("heartbeat").exists(),
        "a hardened start created state"
    );
    hardened.stop().await;

    let hang = Listener::start(Answer::Never).await;
    let control = crate::test_dir_keep::kept_tempdir();
    let _control_guard = seam::register(control.path(), slow_target_for(&hang));
    let standard = Box::pin(start_http(control.path(), SecurityPosture::Standard)).await;
    assert_eq!(standard.status, 200);
    assert!(
        standard.took < Duration::from_secs(30),
        "{:?}",
        standard.took
    );
    until("control: the standard start's heartbeat", || {
        hang.connections() == 1
    })
    .await;
    standard.stop().await;
}

/// A running stdio gateway, its pipes, and whether it answered `ping`.
struct RunningStdio {
    task: tokio::task::JoinHandle<()>,
    _pipes: (
        tokio::io::DuplexStream,
        tokio::io::Lines<tokio::io::BufReader<tokio::io::DuplexStream>>,
    ),
    answered: bool,
}

/// Start the stdio gateway on `dir` with `posture` and send `ping`; the
/// whole of it (construction, write, reply) is bounded at 30 s, and a reply
/// counts only as JSON-RPC with id 1 and a result.
async fn start_stdio(dir: &std::path::Path, posture: SecurityPosture) -> RunningStdio {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
    let run = async {
        let mut config = crate::config::Config::default();
        config.tasks.store_dir = dir.join("tasks").to_string_lossy().into_owned();
        config.security.posture = posture;
        // Hardened forces signing, which needs a secret; set for both
        // postures so the posture alone differs (A9).
        config.security.message_signing.shared_secret =
            crate::security::posture::tests::SIGNING_SECRET.to_string();
        let gateway = super::super::Gateway::new(config)
            .await
            .expect("a gateway")
            .with_data_dir(dir.to_path_buf());
        let (mut client, input) = tokio::io::duplex(64 * 1024);
        let (output, reader) = tokio::io::duplex(1 << 20);
        let task =
            tokio::spawn(async move { drop(gateway.run_stdio_on(input, output, None).await) });
        client
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n")
            .await
            .expect("write");
        let mut lines = tokio::io::BufReader::new(reader).lines();
        let line = lines.next_line().await.ok().flatten();
        let answered = line.is_some_and(|l| {
            serde_json::from_str::<serde_json::Value>(&l)
                .is_ok_and(|v| v["id"] == 1 && v.get("result").is_some())
        });
        RunningStdio {
            task,
            _pipes: (client, lines),
            answered,
        }
    };
    tokio::time::timeout(Duration::from_secs(30), Box::pin(run))
        .await
        .expect("constructed and answered ping within 30 s")
}

impl RunningStdio {
    /// Abort the server task itself and await it: cancelled or a clean end,
    /// never a panic.
    async fn stop(self) {
        self.task.abort();
        let joined = self.task.await;
        assert!(
            joined.is_ok()
                || joined
                    .as_ref()
                    .is_err_and(tokio::task::JoinError::is_cancelled),
            "{joined:?}"
        );
    }
}

/// W2 + F8. A hardened stdio gateway, observed while it runs, opens no
/// connection and creates no state. Control: the standard posture, against a
/// receiver that never answers and a client that would wait a minute,
/// answers `ping` within 30 s and connects before it is stopped.
#[tokio::test]
async fn stdio_start_hardened_sends_nothing() {
    let rx = Listener::start(Answer::NoContent).await;
    let dir = crate::test_dir_keep::kept_tempdir();
    let _guard = seam::register(dir.path(), target_for(&rx));
    let hardened = start_stdio(dir.path(), SecurityPosture::Hardened).await;
    assert!(hardened.answered, "no reply to ping");
    // The task's first check has finished (an event, not a wait): it
    // skipped for the posture.
    until("the hardened check", || {
        seam::outcomes(dir.path()).contains(&crate::heartbeat::Outcome::Skipped(
            crate::heartbeat::Skip::Hardened,
        ))
    })
    .await;
    assert_eq!(rx.connections(), 0, "a hardened stdio start sent");
    assert!(!dir.path().join("heartbeat").exists());
    hardened.stop().await;

    let hang = Listener::start(Answer::Never).await;
    let control = crate::test_dir_keep::kept_tempdir();
    let _control_guard = seam::register(control.path(), slow_target_for(&hang));
    let standard = start_stdio(control.path(), SecurityPosture::Standard).await;
    assert!(standard.answered, "ping waited on the heartbeat");
    until("control: the standard stdio start's heartbeat", || {
        hang.connections() == 1
    })
    .await;
    standard.stop().await;
}
