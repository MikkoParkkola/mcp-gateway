// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Heartbeat rows for a failing or refused send (test plan F1-F6):
//! the check returns within its bound, follows no redirect, and the
//! production client refuses plain HTTP and an untrusted issuer. Fixtures are
//! in `heartbeat_tests.rs`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::tests::{Answer, Listener, nov19, release, test_client};
use super::*;

/// The bound a failing send must return within: the 3 s client timeout plus
/// slack for a loaded runner.
const SEND_BOUND: std::time::Duration = std::time::Duration::from_secs(5);

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
    let _ = heartbeat_once(&release(), dir.path(), &test_client(), &first.url(), nov19).await;
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
        &production_client(),
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
    let out = heartbeat_once(&release(), dir.path(), &production_client(), &url, nov19).await;
    assert_eq!(out, Outcome::Failed);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "an untrusted issuer was accepted"
    );
    let ca = reqwest::Certificate::from_pem(ca_pem.as_bytes()).expect("CA");
    let trusting = base_builder()
        .https_only(true)
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
