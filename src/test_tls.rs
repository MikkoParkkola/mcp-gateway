// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A loopback HTTPS server under a fresh test CA, for rows that need a TLS
//! peer: `debug_trust_roots_tests` (the trusted-root rows) and
//! `heartbeat_tests` (the production client refuses an untrusted issuer).
#![allow(
    clippy::disallowed_methods,
    reason = "test code: random fixtures and throwaway keys, never shipped"
)]

/// Serve `app` over HTTPS on 127.0.0.1 under a fresh CA. Returns the base URL
/// (`https://localhost:<port>`) and the CA's PEM. The leaf certificate is
/// valid for `localhost` and `127.0.0.1` in every respect except that its
/// issuer is trusted nowhere.
pub(crate) async fn https_server(app: axum::Router) -> (String, String) {
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
    let mut leaf_params =
        CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()]).expect("leaf");
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
    tokio::spawn(async move {
        let _ = axum_server::from_tcp_rustls(listener, tls)
            .expect("listener")
            .serve(app.into_make_service())
            .await;
    });
    (format!("https://localhost:{port}"), ca.pem())
}
