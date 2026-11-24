// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8188 R2: the test roots are added beside the platform's, and nothing
//! changes when the variable is unset.
#![allow(
    clippy::disallowed_methods,
    reason = "test code: random fixtures and throwaway keys, never shipped"
)]

use super::with_roots_from;

/// A loopback HTTPS server under a fresh CA (`crate::test_tls`): its URL and
/// the CA's PEM.
async fn server() -> (String, String) {
    let app = axum::Router::new().route("/", axum::routing::get(|| async { "ok" }));
    let (base, ca) = crate::test_tls::https_server(app).await;
    (format!("{base}/"), ca)
}

/// The status of one GET through `builder`, or the error's text.
async fn get(builder: reqwest::ClientBuilder, url: &str) -> Result<u16, String> {
    let client = builder.no_proxy().build().expect("client");
    client
        .get(url)
        .send()
        .await
        .map(|r| r.status().as_u16())
        .map_err(|e| format!("{e:?}"))
}

/// R2: with the file named, the server under the test CA is reached; with no
/// file, the same server is refused, so the hook added the root and an unset
/// variable adds nothing.
#[tokio::test]
async fn the_named_roots_are_trusted_and_nothing_is_without_them() {
    let (url, ca_pem) = server().await;
    let dir = tempfile::tempdir().expect("dir");
    let file = dir.path().join("ca.pem");
    std::fs::write(&file, ca_pem).expect("write CA");

    let trusted = get(
        with_roots_from(reqwest::Client::builder(), Some(&file)),
        &url,
    )
    .await;
    assert_eq!(trusted, Ok(200), "the test root reaches the server");

    let untrusted = get(with_roots_from(reqwest::Client::builder(), None), &url).await;
    assert!(untrusted.is_err(), "no variable, no root: {untrusted:?}");
}

/// A named file that holds no certificate fails at once, never silently
/// trusting the platform roots alone.
#[test]
#[should_panic(expected = "holds no certificate")]
fn a_file_with_no_certificate_fails_loudly() {
    let dir = tempfile::tempdir().expect("dir");
    let file = dir.path().join("empty.pem");
    std::fs::write(&file, "").expect("write");
    let _ = with_roots_from(reqwest::Client::builder(), Some(&file));
}
