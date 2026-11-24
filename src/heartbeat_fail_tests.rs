// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Heartbeat rows for a failing or refused send (test plan F1-F6):
//! the check returns within its bound, follows no redirect, and the
//! production client refuses plain HTTP and an untrusted issuer. Fixtures are
//! in `heartbeat_tests.rs`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::fixtures::{Answer, Listener, nov19, release, test_client};
use super::*;

/// The bound a failing send must return within: the 3 s client timeout plus
/// slack for a loaded runner.
const SEND_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

/// F1. A closed port: the check returns within the bound, without sending.
#[tokio::test]
async fn a_closed_port_returns_within_the_bound() {
    let closed = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        format!("http://{}/v1/heartbeat", probe.local_addr().expect("addr"))
    };
    let dir = tempfile::tempdir().expect("dir");
    let started = std::time::Instant::now();
    let out = heartbeat_once(&release(), dir.path(), &test_client(), &closed, nov19).await;
    assert_eq!(out, Outcome::Failed);
    assert!(started.elapsed() < SEND_BOUND, "{:?}", started.elapsed());
    // Control (tp-r1): the same fixture and client against a live listener
    // sends, so "Failed" above came from the closed port, not a dead core.
    let rx = Listener::start(Answer::NoContent).await;
    let control = tempfile::tempdir().expect("dir");
    assert_eq!(
        heartbeat_once(&release(), control.path(), &test_client(), &rx.url(), nov19).await,
        Outcome::Sent
    );
}

/// F2. A receiver that accepts and never answers: the check returns within
/// the bound, and the receiver was reached (both sides of the 3 s bound).
#[tokio::test]
async fn a_silent_receiver_returns_within_the_bound() {
    let rx = Listener::start(Answer::Never).await;
    let dir = tempfile::tempdir().expect("dir");
    let started = std::time::Instant::now();
    let out = heartbeat_once(&release(), dir.path(), &test_client(), &rx.url(), nov19).await;
    assert_eq!(out, Outcome::Failed);
    let took = started.elapsed();
    assert!(took < SEND_BOUND, "{took:?}");
    assert!(
        took >= std::time::Duration::from_millis(2500),
        "returned before the timeout: {took:?}"
    );
    assert_eq!(rx.connections(), 1, "the receiver was never reached");
}

/// F3. A 500 is ignored: the day stays claimed and nothing is retried.
#[tokio::test]
async fn a_500_is_ignored() {
    let rx = Listener::start(Answer::Error500).await;
    let dir = tempfile::tempdir().expect("dir");
    let c = test_client();
    assert_eq!(
        heartbeat_once(&release(), dir.path(), &c, &rx.url(), nov19).await,
        Outcome::Failed
    );
    assert_eq!(
        heartbeat_once(&release(), dir.path(), &c, &rx.url(), nov19).await,
        Outcome::NoClaim
    );
    assert_eq!(rx.connections(), 1);
}

/// F4. A redirect is not followed: the second listener sees nothing; the
/// same client reaches the second listener directly (control).
#[tokio::test]
async fn a_redirect_is_not_followed() {
    let second = Listener::start(Answer::NoContent).await;
    let first = Listener::start(Answer::RedirectTo(second.url())).await;
    let dir = tempfile::tempdir().expect("dir");
    let c = test_client();
    let out = heartbeat_once(&release(), dir.path(), &c, &first.url(), nov19).await;
    assert_eq!(out, Outcome::Failed, "a redirect is not a delivery");
    assert_eq!(
        heartbeat_once(&release(), dir.path(), &c, &first.url(), nov19).await,
        Outcome::NoClaim,
        "the day stays claimed after a redirect"
    );
    assert_eq!(first.connections(), 1);
    assert_eq!(second.connections(), 0, "the redirect was followed");
    let direct = tempfile::tempdir().expect("dir");
    assert_eq!(
        heartbeat_once(
            &release(),
            direct.path(),
            &test_client(),
            &second.url(),
            nov19
        )
        .await,
        Outcome::Sent
    );
}

/// F5. The production client opens no connection to an `http://` URL; the
/// test client reaches the same listener (control).
#[tokio::test]
async fn production_client_refuses_http() {
    let rx = Listener::start(Answer::NoContent).await;
    let dir = tempfile::tempdir().expect("dir");
    let out = heartbeat_once(
        &release(),
        dir.path(),
        &production_client().expect("the release client builds"),
        &rx.url(),
        nov19,
    )
    .await;
    assert_eq!(out, Outcome::Failed);
    assert_eq!(rx.connections(), 0, "HTTPS only was not enforced");
    let control = tempfile::tempdir().expect("dir");
    assert_eq!(
        heartbeat_once(&release(), control.path(), &test_client(), &rx.url(), nov19).await,
        Outcome::Sent
    );
}

/// F6. The production client refuses a certificate whose issuer is trusted
/// nowhere, and the server receives no request; a client built the same way
/// that trusts the throwaway CA reaches it (control: the listener and its
/// certificate are good, only trust differs).
#[tokio::test]
async fn production_client_refuses_an_untrusted_certificate() {
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    let app = axum::Router::new().route(
        "/v1/heartbeat",
        axum::routing::post(move || {
            let counted = Arc::clone(&counted);
            async move {
                counted.fetch_add(1, Ordering::SeqCst);
                axum::http::StatusCode::NO_CONTENT
            }
        }),
    );
    let (base, ca_pem) = crate::test_tls::https_server(app).await;
    let url = format!("{base}/v1/heartbeat");
    let dir = tempfile::tempdir().expect("dir");
    let out = heartbeat_once(
        &release(),
        dir.path(),
        &production_target().expect("the release target builds").1,
        &url,
        nov19,
    )
    .await;
    assert_eq!(out, Outcome::Failed);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "an untrusted issuer was accepted"
    );
    let ca = reqwest::Certificate::from_pem(ca_pem.as_bytes()).expect("CA");
    // The release builder plus one root: the only difference from the client
    // that was refused (tp-r1).
    let trusting = production_builder()
        .add_root_certificate(ca)
        .build()
        .expect("client");
    let control = tempfile::tempdir().expect("dir");
    assert_eq!(
        heartbeat_once(&release(), control.path(), &trusting, &url, nov19).await,
        Outcome::Sent
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1, "control");
}

/// W3 (as behaviour, tp-r1). The release target is the literal receiver URL
/// with the release client: that client opens no connection to a plain-HTTP
/// listener, which the test client reaches (control).
#[tokio::test]
async fn production_target_is_the_literal_url_and_the_release_client() {
    let (url, client) = production_target().expect("the release target builds");
    assert_eq!(url, "https://telemetry.revaluator.ai/v1/heartbeat");
    let rx = Listener::start(Answer::NoContent).await;
    let dir = tempfile::tempdir().expect("dir");
    let out = heartbeat_once(&release(), dir.path(), &client, &rx.url(), nov19).await;
    assert_eq!(out, Outcome::Failed);
    assert_eq!(
        rx.connections(),
        0,
        "the release target's client spoke plain HTTP"
    );
    let control = tempfile::tempdir().expect("dir");
    assert_eq!(
        heartbeat_once(&release(), control.path(), &test_client(), &rx.url(), nov19).await,
        Outcome::Sent
    );
}

/// W3b (tp-r2). With no registered target, `resolve` gives the task the
/// release target: the literal URL, a client that refuses plain HTTP, and a
/// one-hour interval; a registered target is used only for its own dir.
#[tokio::test]
async fn start_resolves_the_release_target_without_a_seam() {
    let dir = tempfile::tempdir().expect("dir");
    let released = resolve(dir.path()).expect("the release target builds");
    assert!(!released.from_seam);
    assert_eq!(released.url, "https://telemetry.revaluator.ai/v1/heartbeat");
    assert_eq!(released.every, std::time::Duration::from_secs(3600));
    let rx = Listener::start(Answer::NoContent).await;
    let probe = tempfile::tempdir().expect("dir");
    let out = heartbeat_once(&release(), probe.path(), &released.client, &rx.url(), nov19).await;
    assert_eq!(out, Outcome::Failed);
    assert_eq!(
        rx.connections(),
        0,
        "the resolved release client spoke plain HTTP"
    );
    // The very client start resolves refuses an untrusted issuer too (tp-r3),
    // and the resolved clock gives a date (an always-None clock would never send).
    assert!(
        (released.today)().is_some(),
        "the resolved clock gave no date"
    );
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    let app = axum::Router::new().route(
        "/v1/heartbeat",
        axum::routing::post(move || {
            let counted = Arc::clone(&counted);
            async move {
                counted.fetch_add(1, Ordering::SeqCst);
                axum::http::StatusCode::NO_CONTENT
            }
        }),
    );
    let (base, _ca) = crate::test_tls::https_server(app).await;
    let tls = tempfile::tempdir().expect("dir");
    let tls_url = format!("{base}/v1/heartbeat");
    let out = heartbeat_once(&release(), tls.path(), &released.client, &tls_url, nov19).await;
    assert_eq!(out, Outcome::Failed);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "the resolved client accepted an untrusted issuer"
    );
    let registered = tempfile::tempdir().expect("dir");
    let _guard = seam::register(
        registered.path(),
        seam::Target {
            url: rx.url(),
            client: test_client(),
            today: nov19,
            // The release period: this target is only resolved, never run.
            every: std::time::Duration::from_secs(3600),
            stall: None,
        },
    );
    let seamed = resolve(registered.path()).expect("a registered target");
    assert!(seamed.from_seam);
    assert_eq!(seamed.url, rx.url());
    assert!(
        !resolve(dir.path())
            .expect("the release target builds")
            .from_seam,
        "a registration leaked to another dir"
    );
}

/// The heartbeat task for `dir` under the default posture, plus the sender
/// that stops it. Keep the sender: a closed channel ends the task by itself.
fn spawn_heartbeat(
    dir: &std::path::Path,
) -> (
    tokio::sync::broadcast::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let (stop, _) = tokio::sync::broadcast::channel(1);
    let task = start(
        SecurityPosture::Standard,
        dir.to_path_buf(),
        stop.subscribe(),
    );
    (stop, task)
}

/// F7. Without a release client (the case of a build with no TLS backend),
/// the started task returns at once: it neither claims a day nor swaps in a
/// client that lacks the release limits.
#[tokio::test]
async fn no_release_client_ends_the_task_without_a_check() {
    let dir = tempfile::tempdir().expect("dir");
    assert!(
        resolve(dir.path()).is_some(),
        "control: an unbroken release client resolves for this dir"
    );
    let _broken = seam::break_release_client();
    assert!(
        production_builder().build().is_err(),
        "premise: the broken builder must fail as a missing backend does"
    );
    let (stop, task) = spawn_heartbeat(dir.path());
    match tokio::time::timeout(std::time::Duration::from_secs(30), task).await {
        Ok(Ok(())) => {}
        other => panic!("the task kept going without a release client: {other:?}"),
    }
    assert!(
        !dir.path().join("heartbeat").exists(),
        "a day was claimed with no release client"
    );
    // Held open until here, so only a missing client can have ended the task.
    drop(stop);
}
