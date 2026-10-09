// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8188 R2: the test roots are added beside the platform's, and nothing
//! changes when the variable is unset.

use super::with_roots_from;

/// A loopback HTTPS server under a fresh CA: its URL and the CA's PEM.
async fn server() -> (String, String) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let ca_key = KeyPair::generate().expect("CA key");
    let mut ca_params = CertificateParams::new(Vec::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    // A subject of its own: a leaf named like its issuer reads as self-issued
    // to the Windows chain engine.
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "test-trust CA");
    let ca = ca_params.clone().self_signed(&ca_key).expect("CA");
    let issuer = Issuer::new(ca_params, ca_key);
    let leaf_key = KeyPair::generate().expect("leaf key");
    let mut leaf_params = CertificateParams::new(vec!["localhost".to_owned()]).expect("leaf");
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).expect("signed");
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        leaf.pem().into_bytes(),
        leaf_key.serialize_pem().into_bytes(),
    )
    .await
    .expect("tls");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("non-blocking");
    let port = listener.local_addr().expect("addr").port();
    let app = axum::Router::new().route("/", axum::routing::get(|| async { "ok" }));
    tokio::spawn(async move {
        let _ = axum_server::from_tcp_rustls(listener, tls)
            .expect("listener")
            .serve(app.into_make_service())
            .await;
    });
    (format!("https://localhost:{port}/"), ca.pem())
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
