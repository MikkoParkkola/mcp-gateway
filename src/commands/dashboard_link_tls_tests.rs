// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1832: `dashboard-link` reaches an mTLS listener. It presents the client
//! identity it is given and trusts only the CA it is given, against the
//! listener config `serve` builds (`mtls::build_tls_config`).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use mcp_gateway::mtls::{CaParams, CertGenerator, GeneratedCert, LeafCertParams, MtlsConfig};

use super::dashboard_link::{LinkTls, LinkTlsFlags, dashboard_link_base, fetch_link};

const LINK: &str = "https://127.0.0.1:1/dashboard?bootstrap=abc";

fn ca(cn: &str) -> GeneratedCert {
    CertGenerator::init_ca(&CaParams {
        cn,
        validity_days: 1,
    })
    .expect("CA")
}

fn leaf(ca: &GeneratedCert, cn: &str, san_dns: &[&str]) -> GeneratedCert {
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

/// An mTLS gateway stand-in on loopback: a server leaf for `127.0.0.1` from
/// `ca.crt`, a client leaf `client.*` from the same CA, and a client leaf
/// `stranger.*` and CA `other-ca.crt` from another. Counts every request that
/// reaches the handler.
struct Stand {
    base: String,
    dir: tempfile::TempDir,
    hits: Arc<AtomicUsize>,
}

impl Stand {
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn identity(&self, stem: &str) -> Option<(PathBuf, PathBuf)> {
        Some((
            self.path(&format!("{stem}.crt")),
            self.path(&format!("{stem}.key")),
        ))
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

async fn stand_in(require_client_cert: bool) -> Stand {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let dir = tempfile::tempdir().expect("tempdir");
    let root = ca("link CA");
    let other = ca("other CA");
    let write = |cert: &GeneratedCert, stem: &str| {
        CertGenerator::write_to_dir(cert, dir.path(), stem).expect("cert files");
    };
    write(&root, "ca");
    write(&other, "other-ca");
    write(&leaf(&root, "gateway", &["127.0.0.1"]), "server");
    write(&leaf(&root, "operator", &[]), "client");
    write(&leaf(&other, "stranger", &[]), "stranger");
    let path = |name: &str| dir.path().join(name).to_string_lossy().into_owned();
    let tls = mcp_gateway::mtls::build_tls_config(&MtlsConfig {
        enabled: true,
        server_cert: path("server.crt"),
        server_key: path("server.key"),
        ca_cert: path("ca.crt"),
        require_client_cert,
        ..Default::default()
    })
    .expect("the listener serve builds");

    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&hits);
    let app = axum::Router::new().route(
        "/ui/api/dashboard-link",
        axum::routing::post(move |headers: axum::http::HeaderMap| {
            let seen = Arc::clone(&seen);
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                let ok = headers.get("authorization").and_then(|v| v.to_str().ok())
                    == Some("Bearer tok");
                if ok {
                    Ok(axum::Json(serde_json::json!({ "link": LINK })))
                } else {
                    Err(axum::http::StatusCode::FORBIDDEN)
                }
            }
        }),
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let base = format!("https://{}", listener.local_addr().expect("addr"));
    let config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls));
    let server = axum_server::from_tcp_rustls(listener, config).expect("TLS listener");
    tokio::spawn(async move { server.serve(app.into_make_service()).await });
    Stand { base, dir, hits }
}

fn with(ca: Option<PathBuf>, identity: Option<(PathBuf, PathBuf)>) -> LinkTls {
    LinkTls { ca, identity }
}

fn missing(dir: &Path) -> PathBuf {
    dir.join("absent.pem")
}

/// Acceptance: with the listener's CA and a client identity it trusts, the
/// command gets a link from a listener that requires a client certificate.
#[tokio::test]
async fn a_client_identity_reaches_a_listener_that_requires_one() {
    let s = stand_in(true).await;
    let tls = with(Some(s.path("ca.crt")), s.identity("client"));
    assert_eq!(fetch_link(&s.base, "tok", &tls).await.as_deref(), Ok(LINK));
    assert_eq!(s.hits(), 1);
}

/// Acceptance: the same call without the identity is refused before the
/// bearer reaches the handler, and the error says what to pass.
#[tokio::test]
async fn without_an_identity_the_listener_refuses_and_the_error_says_why() {
    let s = stand_in(true).await;
    let err = fetch_link(&s.base, "tok", &with(Some(s.path("ca.crt")), None))
        .await
        .expect_err("no client certificate");
    assert!(err.contains("--client-cert"), "{err}");
    assert_eq!(s.hits(), 0, "the bearer reached the handler");
}

/// A client certificate from another CA is refused too: configuring an
/// identity does not weaken the listener's check.
#[tokio::test]
async fn an_identity_from_another_ca_is_refused() {
    let s = stand_in(true).await;
    let tls = with(Some(s.path("ca.crt")), s.identity("stranger"));
    fetch_link(&s.base, "tok", &tls)
        .await
        .expect_err("an untrusted client certificate");
    assert_eq!(s.hits(), 0);
}

/// A private CA is trusted only when given: without it the server
/// certificate fails verification, and the error names `--ca-cert`.
#[tokio::test]
async fn a_private_ca_is_trusted_only_when_given() {
    let s = stand_in(false).await;
    let err = fetch_link(&s.base, "tok", &with(None, None))
        .await
        .expect_err("the built-in roots do not know this CA");
    assert!(err.contains("--ca-cert"), "{err}");
    assert_eq!(s.hits(), 0);
    let tls = with(Some(s.path("ca.crt")), None);
    assert_eq!(fetch_link(&s.base, "tok", &tls).await.as_deref(), Ok(LINK));
}

/// The given CA is the only trust anchor: a server certificate from another
/// CA fails verification, reported as a certificate failure.
#[tokio::test]
async fn a_server_certificate_from_another_ca_fails_verification() {
    let s = stand_in(true).await;
    let tls = with(Some(s.path("other-ca.crt")), s.identity("client"));
    let err = fetch_link(&s.base, "tok", &tls)
        .await
        .expect_err("the server does not chain to the given CA");
    assert!(err.to_lowercase().contains("certificate"), "{err}");
    assert_eq!(s.hits(), 0);
}

/// Unreadable or unparsable TLS files are named in the error, and nothing is
/// sent.
#[tokio::test]
async fn a_bad_tls_file_is_named_and_nothing_is_sent() {
    let s = stand_in(true).await;
    let absent = missing(s.dir.path());
    let identity = s.identity("client");
    for tls in [
        with(Some(absent.clone()), identity.clone()),
        with(
            Some(s.path("ca.crt")),
            Some((absent.clone(), s.path("client.key"))),
        ),
        with(
            Some(s.path("ca.crt")),
            Some((s.path("client.crt"), absent.clone())),
        ),
    ] {
        let err = fetch_link(&s.base, "tok", &tls)
            .await
            .expect_err("an unreadable file");
        assert!(err.contains("absent.pem"), "{err}");
    }
    // A key file that holds no key: parsed, refused, named.
    let not_a_key = with(
        Some(s.path("ca.crt")),
        Some((s.path("client.crt"), s.path("ca.crt"))),
    );
    let err = fetch_link(&s.base, "tok", &not_a_key)
        .await
        .expect_err("no private key");
    assert!(
        err.contains("client.crt") && err.contains("ca.crt"),
        "{err}"
    );
    assert_eq!(s.hits(), 0);
}

fn mtls_config(require_client_cert: bool) -> mcp_gateway::config::Config {
    let mut config = mcp_gateway::config::Config::default();
    config.server.port = 4300;
    config.mtls.enabled = true;
    config.mtls.ca_cert = "/etc/gw/ca.crt".to_string();
    config.mtls.require_client_cert = require_client_cert;
    config
}

fn flags(cert: Option<&str>, key: Option<&str>, ca: Option<&str>) -> LinkTlsFlags {
    LinkTlsFlags {
        client_cert: cert.map(PathBuf::from),
        client_key: key.map(PathBuf::from),
        ca_cert: ca.map(PathBuf::from),
    }
}

/// A config-derived URL trusts the config's `mtls.ca_cert`; `--ca-cert`
/// replaces it; `--url` reads no config, so only `--ca-cert` applies.
#[test]
fn the_trust_anchor_comes_from_the_config_only_with_its_url() {
    let config = mtls_config(false);
    let (base, tls) = dashboard_link_base(
        None,
        flags(None, None, None),
        || Ok(config.clone()),
        None,
        None,
    )
    .expect("target");
    assert_eq!(base, "https://127.0.0.1:4300");
    assert_eq!(tls.ca, Some(PathBuf::from("/etc/gw/ca.crt")));

    let (_, tls) = dashboard_link_base(
        None,
        flags(None, None, Some("/x/ca.pem")),
        || Ok(config.clone()),
        None,
        None,
    )
    .expect("target");
    assert_eq!(tls.ca, Some(PathBuf::from("/x/ca.pem")));

    let (_, tls) = dashboard_link_base(
        Some("https://gw.example".into()),
        flags(None, None, None),
        || panic!("--url reads no config"),
        None,
        None,
    )
    .expect("target");
    assert_eq!(tls.ca, None);
}

/// A config-derived URL on a listener that requires a client certificate,
/// with no identity given, is refused before any request, naming the flags.
#[test]
fn a_required_identity_is_asked_for_up_front() {
    let err = dashboard_link_base(
        None,
        flags(None, None, None),
        || Ok(mtls_config(true)),
        None,
        None,
    )
    .expect_err("the listener would refuse the handshake");
    assert!(
        err.contains("--client-cert") && err.contains("--client-key"),
        "{err}"
    );

    let (_, tls) = dashboard_link_base(
        None,
        flags(Some("/c.crt"), Some("/c.key"), None),
        || Ok(mtls_config(true)),
        None,
        None,
    )
    .expect("target");
    assert_eq!(
        tls.identity,
        Some((PathBuf::from("/c.crt"), PathBuf::from("/c.key")))
    );
}

/// The parser refuses a certificate without its key and a key without its
/// certificate.
#[test]
fn the_certificate_and_key_flags_go_together() {
    use clap::Parser as _;
    for args in [
        ["mcp-gateway", "dashboard-link", "--client-cert", "c.crt"],
        ["mcp-gateway", "dashboard-link", "--client-key", "c.key"],
    ] {
        assert!(
            mcp_gateway::cli::Cli::try_parse_from(args).is_err(),
            "{args:?} parsed"
        );
    }
}
