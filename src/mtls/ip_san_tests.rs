// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1955: a server leaf issued for an IP literal verifies when dialled at that
//! address, through the listener `serve` builds, with a client certificate.

use std::io::Write as _;
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

/// A CA, a server leaf for `127.0.0.1,::1`, a client leaf, and the listener
/// config `serve` builds from them with a client certificate required.
struct Pki {
    _dir: tempfile::TempDir,
    ca: super::GeneratedCert,
    server: super::GeneratedCert,
    client: super::GeneratedCert,
    tls: Arc<rustls::ServerConfig>,
}

fn pki() -> Pki {
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
    Pki {
        _dir: dir,
        ca,
        server,
        client,
        tls: Arc::new(tls),
    }
}

/// A full handshake, client certificate included, with a listener on
/// `listener`, the client verifying the server as the address `ip`.
async fn handshake(pki: &Pki, listener: tokio::net::TcpListener, ip: &str) {
    let addr = listener.local_addr().expect("addr");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&pki.tls));
    let accepted = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        acceptor.accept(socket).await.map(|_| ())
    });
    let connector =
        tokio_rustls::TlsConnector::from(Arc::new(client_config(&pki.ca.cert_pem, &pki.client)));
    let socket = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let name = ServerName::try_from(ip.to_string()).expect("IP server name");
    let dialled = connector.connect(name, socket).await;
    assert!(dialled.is_ok(), "handshake at {ip}: {:?}", dialled.err());
    let served = accepted.await.expect("server task");
    assert!(served.is_ok(), "server side at {ip}: {:?}", served.err());
}

#[tokio::test]
async fn a_server_leaf_for_loopback_verifies_at_the_address() {
    let pki = pki();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    handshake(&pki, listener, "127.0.0.1").await;

    // An address the leaf does not name is refused by the verifier the client uses.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der(&pki.ca.cert_pem)).expect("CA");
    let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .expect("verifier");
    let refused = verifier.verify_server_cert(
        &der(&pki.server.cert_pem),
        &[],
        &ServerName::try_from("10.9.9.9").expect("name"),
        &[],
        UnixTime::now(),
    );
    assert!(refused.is_err(), "an address the leaf does not name");
}

/// The same handshake at `[::1]`. A host with no IPv6 loopback cannot run it;
/// it says so in the output rather than passing silently.
#[tokio::test]
async fn a_server_leaf_for_ipv6_loopback_verifies_at_the_address() {
    let pki = pki();
    let listener = match tokio::net::TcpListener::bind("[::1]:0").await {
        Ok(listener) => listener,
        Err(e) if no_ipv6_loopback(&e) => {
            // Straight to the stream, not `eprintln!`: the test harness
            // captures the print macros of a passing test, and this line must
            // reach the CI log so a skipped run can be told from a real one.
            let _ = writeln!(
                std::io::stderr(),
                "a_server_leaf_for_ipv6_loopback_verifies_at_the_address SKIPPED: no IPv6 loopback ({e})"
            );
            return;
        }
        Err(e) => panic!("bind [::1]: {e}"),
    };
    handshake(&pki, listener, "::1").await;
}

/// `true` for the bind errors of a host without IPv6 loopback: the address is
/// not configured, or the address family is not supported (EAFNOSUPPORT on
/// Linux, macOS and Windows).
fn no_ipv6_loopback(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::Unsupported
    ) || matches!(e.raw_os_error(), Some(97 | 47 | 10047))
}
