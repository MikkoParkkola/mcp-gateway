// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;

use axum::http::Request;
use rcgen::string::Ia5String;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

fn spiffe_leaf_der(uri: &str) -> Vec<u8> {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "test-agent");
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::URI(Ia5String::try_from(uri).unwrap())];

    let key_pair = KeyPair::generate().expect("key generation failed");
    params
        .self_signed(&key_pair)
        .expect("cert generation failed")
        .der()
        .to_vec()
}

#[test]
fn peer_chain_identity_extracts_spiffe_svid_leaf() {
    let leaf = CertificateDer::from(spiffe_leaf_der("spiffe://example.test/agent/alpha"));
    let identity = client_identity_from_peer_chain(Some(&[leaf]))
        .expect("peer chain should parse")
        .expect("identity should be present");

    assert_eq!(identity.san_uris, vec!["spiffe://example.test/agent/alpha"]);
    assert_eq!(identity.display_name, "spiffe://example.test/agent/alpha");
}

#[test]
fn peer_chain_identity_is_absent_without_client_certificate() {
    let identity = client_identity_from_peer_chain(None).expect("missing chain is allowed");
    assert!(identity.is_none());

    let empty_identity =
        client_identity_from_peer_chain(Some(&[])).expect("empty chain is allowed");
    assert!(empty_identity.is_none());
}

#[test]
fn peer_chain_identity_rejects_malformed_certificate() {
    let malformed = CertificateDer::from(vec![0, 1, 2, 3]);

    let error = client_identity_from_peer_chain(Some(&[malformed]))
        .expect_err("malformed peer certificate must fail closed");

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn peer_cert_identity_service_inserts_identity_extension() {
    use tower::ServiceExt;

    let identity = CertIdentity {
        san_uris: vec!["spiffe://example.test/agent/alpha".to_owned()],
        display_name: "spiffe://example.test/agent/alpha".to_owned(),
        ..CertIdentity::default()
    };
    let echo = axum::Router::new().route(
        "/",
        axum::routing::get(|cert: Option<axum::Extension<CertIdentity>>| async move {
            cert.map(|axum::Extension(cert)| cert.display_name)
                .unwrap_or_default()
        }),
    );
    let app = PeerCertIdentityLayer::new(Some(identity.clone())).layer(echo);
    let response = app
        .oneshot(Request::get("/").body(axum::body::Body::empty()).unwrap())
        .await
        .expect("the router does not fail");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(bytes, identity.display_name.as_bytes());
}

/// Behind an HTTPS `public_url` in any letter case, matching the cookie's
/// `Secure` decision, the banner says where the link's code is entered (#2130).
#[test]
fn an_uppercase_https_public_url_names_the_code_page() {
    let mut config = Config::default();
    config.server.public_url = Some("HTTPS://Gateway.Example/".to_string());
    let note = dashboard_link_handoff(&config).expect("a handoff note");
    assert!(
        note.contains("HTTPS://Gateway.Example/dashboard/handoff"),
        "{note}"
    );
    config.server.public_url = Some("http://gateway.example".to_string());
    assert!(dashboard_link_handoff(&config).is_none());
}

// --- serve_tls: the mTLS listener, served end to end over loopback ---------
//
// MIK-7324.COV.3: `serve_tls` and `PeerCertIdentityAcceptor::accept` enforce
// who may connect and hand auth the certificate identity, so they carry the
// Critical floor. Nothing else serves through them: the dashboard-link TLS
// tests build their own listener.

mod mtls_listener {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use axum::Extension;

    use super::*;
    use crate::mtls::{CaParams, CertGenerator, GeneratedCert, LeafCertParams, MtlsConfig};

    /// MIK-7673: an mTLS gateway stops within `server.shutdown_timeout`
    /// through `listener::serve`, which hands its one handle to `serve_tls`.
    /// A request held open forever over TLS, with a client certificate, must
    /// not hold the shutdown past the bound.
    #[tokio::test]
    async fn an_mtls_request_that_never_ends_does_not_hold_shutdown_past_the_timeout() {
        let pki = Pki::new();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let started = std::sync::Arc::new(std::sync::Mutex::new(Some(started_tx)));
        let app = axum::Router::new().route(
            "/hang",
            axum::routing::get(move || {
                let started = started.lock().expect("slot").take();
                async move {
                    if let Some(started) = started {
                        let _ = started.send(());
                    }
                    std::future::pending::<()>().await;
                }
            }),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("addr");
        let grace = Duration::from_millis(100);
        let mut config = crate::config::Config::default();
        config.mtls = pki.config(true);
        config.server.shutdown_timeout = grace;
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            crate::gateway::server::listener::serve(app, listener, addr, &config, async move {
                let _ = stop_rx.await;
            })
            .await
        });
        let client = pki.client(Some("client"));
        let request =
            tokio::spawn(async move { client.get(format!("https://{addr}/hang")).send().await });
        tokio::time::timeout(Duration::from_secs(10), started_rx)
            .await
            .expect("the TLS request reached its handler")
            .expect("started");

        // The request never ends, so only the shutdown deadline can return
        // the server: returning inside the hang guard is the oracle (MIK-8222).
        stop_tx.send(()).expect("server is running");
        let outcome = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("the mTLS server did not return within 5 s while a request was open");
        outcome.expect("server task").expect("serve");
        request.abort();
    }

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

    /// Certificates on disk: `ca`, `server` (127.0.0.1), `client`
    /// ("operator") and `auditor` from one CA; `stranger` from another.
    struct Pki {
        dir: tempfile::TempDir,
    }

    impl Pki {
        fn new() -> Self {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            let dir = tempfile::tempdir().expect("tempdir");
            let root = ca("listener CA");
            let other = ca("other CA");
            let write = |cert: &GeneratedCert, stem: &str| {
                CertGenerator::write_to_dir(cert, dir.path(), stem).expect("cert files");
            };
            write(&root, "ca");
            write(&leaf(&root, "gateway", &["127.0.0.1"]), "server");
            write(&leaf(&root, "operator", &[]), "client");
            write(&leaf(&root, "auditor", &[]), "auditor");
            write(&leaf(&other, "stranger", &[]), "stranger");
            Self { dir }
        }

        fn path(&self, name: &str) -> String {
            self.dir.path().join(name).to_string_lossy().into_owned()
        }

        fn config(&self, require_client_cert: bool) -> MtlsConfig {
            MtlsConfig {
                enabled: true,
                server_cert: self.path("server.crt"),
                server_key: self.path("server.key"),
                ca_cert: self.path("ca.crt"),
                require_client_cert,
                ..Default::default()
            }
        }

        /// A client that trusts only this CA, presenting `stem` if given.
        fn client(&self, stem: Option<&str>) -> reqwest::Client {
            let roots = reqwest::Certificate::from_pem_bundle(
                &std::fs::read(self.path("ca.crt")).expect("ca"),
            )
            .expect("roots");
            let mut builder = reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(20))
                .tls_certs_only(roots);
            if let Some(stem) = stem {
                let mut pem = std::fs::read(self.path(&format!("{stem}.crt"))).expect("crt");
                pem.push(b'\n');
                pem.extend(std::fs::read(self.path(&format!("{stem}.key"))).expect("key"));
                builder = builder.identity(reqwest::Identity::from_pem(&pem).expect("identity"));
            }
            builder.build().expect("client")
        }
    }

    struct Served {
        url: String,
        hits: Arc<AtomicUsize>,
        handle: axum_server::Handle<SocketAddr>,
        task: tokio::task::JoinHandle<crate::Result<()>>,
    }

    /// `serve_tls` on a bound loopback listener. The handler answers with the
    /// common name of the certificate identity it was handed, or "none".
    async fn serve(config: MtlsConfig) -> Served {
        let hits = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&hits);
        let app = axum::Router::new().route(
            "/who",
            axum::routing::get(move |identity: Option<Extension<CertIdentity>>| {
                seen.fetch_add(1, Ordering::SeqCst);
                async move {
                    identity
                        .and_then(|Extension(id)| id.common_name)
                        .unwrap_or_else(|| "none".to_owned())
                }
            }),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("addr");
        let handle = axum_server::Handle::new();
        let served = handle.clone();
        let task =
            tokio::spawn(async move { serve_tls(app, listener, addr, &config, served).await });
        handle.listening().await.expect("the listener came up");
        Served {
            url: format!("https://{addr}/who"),
            hits,
            handle,
            task,
        }
    }

    /// The peer certificate's identity reaches the handler, and a graceful
    /// shutdown ends `serve_tls` with `Ok`.
    #[tokio::test]
    async fn serve_tls_hands_the_handler_the_client_certificate_identity() {
        let pki = Pki::new();
        let s = serve(pki.config(true)).await;

        let response = pki
            .client(Some("client"))
            .get(&s.url)
            .send()
            .await
            .expect("a trusted client is served");
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.expect("body"), "operator");
        // Each connection carries its own peer's identity, not the first one.
        let response = pki
            .client(Some("auditor"))
            .get(&s.url)
            .send()
            .await
            .expect("a second trusted client is served");
        assert_eq!(response.text().await.expect("body"), "auditor");
        assert_eq!(s.hits.load(Ordering::SeqCst), 2);

        s.handle.graceful_shutdown(Some(Duration::from_secs(5)));
        let ended = tokio::time::timeout(Duration::from_secs(10), s.task)
            .await
            .expect("serve_tls returns after shutdown")
            .expect("task joins");
        assert!(ended.is_ok(), "{ended:?}");
    }

    /// With a client certificate required, no certificate and one from an
    /// untrusted CA are both refused in the handshake: the handler never runs.
    #[tokio::test]
    async fn serve_tls_refuses_a_client_without_a_trusted_certificate() {
        let pki = Pki::new();
        let s = serve(pki.config(true)).await;

        for stem in [None, Some("stranger")] {
            let outcome = pki.client(stem).get(&s.url).send().await;
            assert!(
                outcome.is_err(),
                "client {stem:?} must be refused, got {:?}",
                outcome.map(|r| r.status())
            );
        }
        assert_eq!(
            s.hits.load(Ordering::SeqCst),
            0,
            "no refused client reaches the handler"
        );
        // Positive control: the same listener serves a trusted client, so the
        // refusals above are the certificate policy, not a broken listener.
        let response = pki
            .client(Some("client"))
            .get(&s.url)
            .send()
            .await
            .expect("a trusted client is served");
        assert_eq!(response.text().await.expect("body"), "operator");
        assert_eq!(s.hits.load(Ordering::SeqCst), 1);
        s.handle.shutdown();
    }

    /// Client certificates optional: an anonymous client is served, and the
    /// handler is handed no identity rather than an empty one.
    #[tokio::test]
    async fn serve_tls_serves_an_anonymous_client_with_no_identity_when_not_required() {
        let pki = Pki::new();
        let s = serve(pki.config(false)).await;

        let response = pki
            .client(None)
            .get(&s.url)
            .send()
            .await
            .expect("an anonymous client is served");
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.expect("body"), "none");
        s.handle.shutdown();
    }

    /// An unreadable server certificate fails `serve_tls` before it serves.
    #[tokio::test]
    async fn serve_tls_fails_before_serving_on_an_unreadable_server_certificate() {
        let pki = Pki::new();
        let mut config = pki.config(true);
        config.server_cert = pki.path("absent.crt");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("addr");
        let app = axum::Router::new();

        let outcome = tokio::time::timeout(
            Duration::from_secs(10),
            serve_tls(app, listener, addr, &config, axum_server::Handle::new()),
        )
        .await
        .expect("serve_tls returns instead of serving");
        assert!(outcome.is_err(), "a missing server certificate must fail");
    }
}

/// A leaf with no CN and no SAN URI, parsed by the production parser.
fn nameless_leaf() -> CertIdentity {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    let key_pair = KeyPair::generate().expect("key generation failed");
    let der = params
        .self_signed(&key_pair)
        .expect("cert generation failed")
        .der()
        .to_vec();
    CertIdentity::from_der(&der).expect("a nameless leaf still parses")
}

/// MIK-8286 R3: a client certificate that names no subject is a presented
/// identity that names nobody, so the TLS identity layer refuses it as
/// unauthenticated (401, -32000) before anything inside runs, on every path,
/// `/health` included. Mutant: the layer's refusal removed.
#[tokio::test]
async fn a_nameless_client_certificate_is_refused_before_anything_runs() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    let reached = Arc::new(AtomicUsize::new(0));
    let spy = Arc::clone(&reached);
    let inner = axum::Router::new().route(
        "/health",
        axum::routing::get(move || {
            spy.fetch_add(1, Ordering::SeqCst);
            async { "ok" }
        }),
    );
    let app = PeerCertIdentityLayer::new(Some(nameless_leaf())).layer(inner);
    let request = Request::get("/health")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    assert_eq!(body["error"]["code"], serde_json::json!(-32000), "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 0, "nothing inside ran");
}

/// MIK-8195 W2: the admin-granting dashboard link is printed only on a
/// loopback bind, with auth on and a bootstrap value; never otherwise.
#[test]
fn the_dashboard_link_is_printed_only_on_loopback_with_auth_and_a_value() {
    let bootstrap = DashboardBootstrap::new();
    let value = bootstrap.peek().expect("a fresh bootstrap holds a value");
    let mut config = Config::default();
    config.auth.enabled = true;
    config.server.host = "127.0.0.1".to_string();

    let link = dashboard_link(&config, 39400, Some(&bootstrap)).expect("loopback with auth");
    assert!(
        link.contains(&format!(
            "http://127.0.0.1:39400/dashboard?bootstrap={value}"
        )),
        "{link}"
    );
    config.mtls.enabled = true;
    let link = dashboard_link(&config, 39400, Some(&bootstrap)).expect("loopback with mTLS");
    assert!(link.contains("https://127.0.0.1:39400/"), "{link}");
    config.mtls.enabled = false;

    assert_eq!(
        dashboard_link(&config, 39400, None),
        None,
        "no value, no link"
    );
    config.server.host = "0.0.0.0".to_string();
    assert_eq!(
        dashboard_link(&config, 39400, Some(&bootstrap)),
        None,
        "a network bind never prints the admin link"
    );
    config.server.host = "127.0.0.1".to_string();
    config.auth.enabled = false;
    assert_eq!(
        dashboard_link(&config, 39400, Some(&bootstrap)),
        None,
        "with auth off there is no admin to grant"
    );
}
