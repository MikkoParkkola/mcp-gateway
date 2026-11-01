// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A capability fixture's host: a NAME that is not a loopback name, so it
//! clears the capability destination checks without `allow_loopback_egress`
//! (which turns the response cache off), and that a test-only client resolves
//! to the fixture's listener on `127.0.0.1`.
//!
//! Fixtures used `localhost` for this until loopback names were refused
//! before any lookup. Test-only: production has no client that
//! resolves a name without pinning it.
//!
//! A credentialed fixture is served over https ([`serve_https`]): the
//! cleartext-credential rule counts only loopback hosts as this machine, and
//! the fixture host is not one. [`fixture_client`] trusts the fixture CA and
//! nothing else; no production client or root store sees it.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::OnceLock;
use std::time::Duration;

/// The fixture host. `.test` is reserved (RFC 2606), so it never resolves
/// anywhere but through [`fixture_client`].
pub(crate) const FIXTURE_HOST: &str = "capability-fixture.test";

/// `http://<FIXTURE_HOST>:<port>`, the base URL of a fixture listening on
/// `127.0.0.1:<port>`.
pub(crate) fn fixture_url(port: u16) -> String {
    format!("http://{FIXTURE_HOST}:{port}")
}

/// `https://<FIXTURE_HOST>:<port>`, the base URL of a fixture served by
/// [`serve_https`].
pub(crate) fn fixture_https_url(port: u16) -> String {
    format!("https://{FIXTURE_HOST}:{port}")
}

/// A client with a finite `timeout` that resolves [`FIXTURE_HOST`] to
/// `127.0.0.1` (the URL's port is kept) and pins nothing else.
pub(crate) fn fixture_client(timeout: Duration) -> reqwest::Client {
    fixture_client_builder()
        .timeout(timeout)
        .build()
        .expect("the fixture HTTP client builds")
}

/// [`fixture_client`]'s builder, for a fixture that sets more options. Its
/// only trust root is the fixture CA, and it ignores any environment proxy:
/// the fixture host is not a loopback name, so an inherited `HTTP_PROXY`
/// would otherwise carry fixture traffic off the machine. Its timeout is
/// [`crate::test_wait::HANG_BOUND`] until a caller sets its own.
pub(crate) fn fixture_client_builder() -> reqwest::ClientBuilder {
    let ca =
        reqwest::Certificate::from_pem(fixture_pki().ca.as_bytes()).expect("the fixture CA is PEM");
    reqwest::Client::builder()
        .no_proxy()
        .timeout(crate::test_wait::HANG_BOUND)
        .resolve(FIXTURE_HOST, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .tls_certs_only([ca])
}

/// Serves `router` over https on a fresh `127.0.0.1` port, with a leaf for
/// [`FIXTURE_HOST`] signed by the CA [`fixture_client`] trusts. Returns the port.
pub(crate) async fn serve_https(router: axum::Router) -> u16 {
    let pki = fixture_pki();
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        pki.leaf.clone().into_bytes(),
        pki.key.clone().into_bytes(),
    )
    .await
    .expect("the fixture leaf matches its key");
    // port-check: the listener serves on in the spawned TLS server.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback listener binds");
    listener
        .set_nonblocking(true)
        .expect("the listener goes non-blocking");
    let port = listener
        .local_addr()
        .expect("the listener has an address")
        .port();
    let server = axum_server::from_tcp_rustls(listener, tls).expect("the TLS listener starts");
    tokio::spawn(async move {
        let _ = server.serve(router.into_make_service()).await;
    });
    port
}

/// A CA and a leaf for `host`, signed by that CA, in memory.
pub(crate) struct TestPki {
    pub(crate) ca: rcgen::Certificate,
    pub(crate) leaf: rcgen::Certificate,
    pub(crate) leaf_key: rcgen::KeyPair,
}

/// A fresh [`TestPki`] for `host`, the CA named `ca_name`.
pub(crate) fn test_pki(host: &str, ca_name: &str) -> TestPki {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};

    let ca_key = KeyPair::generate().expect("fixture CA key");
    let mut ca_params = CertificateParams::new(Vec::new()).expect("fixture CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    // A subject of its own. rcgen gives the CA and the leaf the same default
    // name, and a leaf whose subject equals its issuer's reads as self-issued:
    // the Windows chain engine then fails it as TRUST_E_CERT_SIGNATURE.
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, ca_name);
    let ca = ca_params
        .clone()
        .self_signed(&ca_key)
        .expect("fixture CA self-signs");
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate().expect("fixture leaf key");
    let mut leaf_params =
        CertificateParams::new(vec![host.to_string()]).expect("fixture leaf params");
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, host);
    let leaf = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("the fixture CA signs the leaf");
    TestPki { ca, leaf, leaf_key }
}

/// The [`FIXTURE_HOST`] CA, leaf and leaf key as PEM, made once per test
/// process.
struct FixturePki {
    ca: String,
    leaf: String,
    key: String,
}

fn fixture_pki() -> &'static FixturePki {
    static PKI: OnceLock<FixturePki> = OnceLock::new();
    PKI.get_or_init(|| {
        let pki = test_pki(FIXTURE_HOST, "capability fixture CA");
        FixturePki {
            ca: pki.ca.pem(),
            leaf: pki.leaf.pem(),
            key: pki.leaf_key.serialize_pem(),
        }
    })
}
