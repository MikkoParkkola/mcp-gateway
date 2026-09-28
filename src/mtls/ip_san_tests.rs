// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1955: a server leaf issued for an IP literal verifies when dialled at that
//! address, through the listener `serve` builds, with a client certificate.

use std::sync::Arc;

use rustls::client::danger::ServerCertVerifier as _;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

use super::cert_manager::{CaParams, CertGenerator, LeafCertParams, build_tls_config};
use super::config::MtlsConfig;

fn leaf(ca: &super::GeneratedCert, cn: &str, san_dns: &[&str]) -> super::GeneratedCert {
    CertGenerator::issue_leaf(
        &LeafCertParams {
            cn,
            ou: None,
            san_dns: san_dns.iter().map(ToString::to_string).collect(),
            san_uris: vec![],
            validity_days: 1,
        },
        &ca.cert_pem,
        &ca.key_pem,
    )
    .expect("leaf")
}

fn der(pem: &str) -> CertificateDer<'static> {
    CertificateDer::from_pem_slice(pem.as_bytes()).expect("certificate PEM")
}

/// A client trusting only `ca`, presenting `client`.
fn client_config(ca: &str, client: &super::GeneratedCert) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der(ca)).expect("CA");
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            vec![der(&client.cert_pem)],
            PrivateKeyDer::from_pem_slice(client.key_pem.as_bytes()).expect("key PEM"),
        )
        .expect("client auth")
}

#[tokio::test]
async fn a_server_leaf_for_loopback_verifies_at_the_address() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = CertGenerator::init_ca(&CaParams {
        cn: "IP SAN CA",
        validity_days: 1,
    })
    .expect("CA");
    let server = leaf(&ca, "gateway", &["127.0.0.1", "::1"]);
    let client = leaf(&ca, "operator", &[]);
    CertGenerator::write_to_dir(&server, dir.path(), "server").expect("server files");
    // Through the helper, so the modes are the ones the listener accepts.
    CertGenerator::write_to_dir(&ca, dir.path(), "ca").expect("CA files");
    let path = |name: &str| dir.path().join(name).to_string_lossy().into_owned();
    let tls = build_tls_config(&MtlsConfig {
        enabled: true,
        server_cert: path("server.crt"),
        server_key: path("server.key"),
        ca_cert: path("ca.crt"),
        require_client_cert: true,
        ..Default::default()
    })
    .expect("the listener serve builds");

    // A real handshake at 127.0.0.1, the address a loopback bind is dialled at.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let accepted = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        acceptor.accept(socket).await.map(|_| ())
    });
    let connector =
        tokio_rustls::TlsConnector::from(Arc::new(client_config(&ca.cert_pem, &client)));
    let socket = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let name = ServerName::try_from("127.0.0.1").expect("IP server name");
    let dialled = connector.connect(name, socket).await;
    assert!(
        dialled.is_ok(),
        "handshake at 127.0.0.1: {:?}",
        dialled.err()
    );
    assert!(accepted.await.expect("server task").is_ok());

    // The same certificate against ::1 (no IPv6 socket needed) and against an
    // address it does not name, through the verifier the client uses.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der(&ca.cert_pem)).expect("CA");
    let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .expect("verifier");
    let end_entity = der(&server.cert_pem);
    let verify = |host: &str| {
        verifier.verify_server_cert(
            &end_entity,
            &[],
            &ServerName::try_from(host.to_string()).expect("name"),
            &[],
            UnixTime::now(),
        )
    };
    assert!(verify("::1").is_ok(), "::1: {:?}", verify("::1").err());
    assert!(
        verify("10.9.9.9").is_err(),
        "an address the leaf does not name"
    );
}
