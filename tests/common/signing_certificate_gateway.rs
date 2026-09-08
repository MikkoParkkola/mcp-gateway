// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Real TLS gateway fixture for the certificate leg of SIGNING.5 row 44.
//!
//! The shipped binary is started with `mtls.enabled`, so the listener is the
//! production `serve_tls` path and every identity below is a genuine X.509 leaf
//! verified at the TLS handshake. Nothing here constructs a `CertIdentity`: an
//! identity a test writes for itself proves nothing about the acceptor that is
//! supposed to derive one.
//!
//! Trust is explicit and narrow, and portable because of it. Clients are built
//! with `tls_certs_only`, which in `reqwest` 0.13 replaces the platform verifier
//! with a plain rustls root store holding exactly this fixture's CA
//! (`reqwest-0.13.4/src/async_impl/client.rs:784-788`). Nothing is bypassed —
//! signature, chain, expiry and hostname are all still verified — and no machine
//! trust store is touched, so this target needs no OS gate. `resolve` pins
//! `localhost`, the server certificate's only SAN, to the loopback address the
//! gateway bound; `no_proxy` keeps an ambient proxy variable out of it.
//!
//! Requires the parent test target to declare `signing_gateway`, whose
//! `child_command` is the one production spawn both quota suites use. This
//! fixture deliberately covers only the TLS listener; the plain-HTTP suites keep
//! using `signing_gateway::HttpGateway`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use mcp_gateway::mtls::{CaParams, CertGenerator, GeneratedCert, LeafCertParams};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::process::Child;

use crate::signing_gateway::child_command;

const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// Short-lived on purpose: a fixture CA that outlives the test run is a trust
/// anchor sitting in a temporary directory.
const VALIDITY_DAYS: u32 = 1;

/// The Common Name BOTH client leaves carry.
///
/// Neither leaf gets a SAN URI, so `CertIdentity::display_name` falls back to
/// the CN and is identical for both — which is the point. A quota keyed on the
/// display label, rather than on the verified certificate itself, collapses two
/// distinct machines into one bucket and this fixture makes that visible.
pub const CLIENT_CN: &str = "signing-quota-client";

/// A CA, a server certificate and the on-disk files the gateway loads.
pub struct CertFixture {
    directory: TempDir,
    ca: GeneratedCert,
}

impl CertFixture {
    /// Generate the CA and the server leaf, and write both where the gateway
    /// config will point.
    ///
    /// `localhost` is the server certificate's only SAN because `rcgen` leaves
    /// take DNS and URI names but not IP addresses, so a client must reach this
    /// listener by name.
    pub fn generate() -> Self {
        let ca = CertGenerator::init_ca(&CaParams {
            cn: "signing quota fixture CA",
            validity_days: VALIDITY_DAYS,
        })
        .expect("fixture CA");
        let server = CertGenerator::issue_leaf(
            &LeafCertParams {
                cn: "localhost",
                ou: None,
                san_dns: vec!["localhost".into()],
                san_uris: vec![],
                validity_days: VALIDITY_DAYS,
            },
            &ca.cert_pem,
            &ca.key_pem,
        )
        .expect("fixture server certificate");
        let directory = tempfile::tempdir().expect("certificate directory");
        std::fs::write(directory.path().join("ca.crt"), &ca.cert_pem).expect("write CA");
        std::fs::write(directory.path().join("server.crt"), &server.cert_pem)
            .expect("write server certificate");
        std::fs::write(directory.path().join("server.key"), &server.key_pem)
            .expect("write server key");
        Self { directory, ca }
    }

    /// Issue a client leaf this fixture's CA vouches for.
    ///
    /// Two calls with the same CN produce two DIFFERENT certificates: each gets
    /// a freshly generated key, so the DER the gateway sees is distinct even
    /// though every printable field matches.
    pub fn issue_client(&self, cn: &str) -> GeneratedCert {
        CertGenerator::issue_leaf(
            &LeafCertParams {
                cn,
                ou: None,
                san_dns: vec![],
                san_uris: vec![],
                validity_days: VALIDITY_DAYS,
            },
            &self.ca.cert_pem,
            &self.ca.key_pem,
        )
        .expect("fixture client certificate")
    }

    /// Point the gateway config at these files and turn the TLS listener on.
    pub fn configure(&self, config: &mut Value, require_client_cert: bool) {
        config["mtls"] = json!({
            "enabled": true,
            "server_cert": self.path("server.crt"),
            "server_key": self.path("server.key"),
            "ca_cert": self.path("ca.crt"),
            "require_client_cert": require_client_cert,
        });
    }

    /// The PEM a client must trust to reach this gateway.
    pub fn ca_pem(&self) -> &str {
        &self.ca.cert_pem
    }

    fn path(&self, name: &str) -> String {
        self.directory
            .path()
            .join(name)
            .to_str()
            .expect("fixture path is UTF-8")
            .to_owned()
    }
}

/// A client leaf signed by a CA the gateway has never heard of.
///
/// Well-formed and unexpired — the only thing wrong with it is its issuer, which
/// is what makes its refusal mean something.
pub fn untrusted_client(cn: &str) -> GeneratedCert {
    let ca = CertGenerator::init_ca(&CaParams {
        cn: "signing quota untrusted CA",
        validity_days: VALIDITY_DAYS,
    })
    .expect("untrusted CA");
    CertGenerator::issue_leaf(
        &LeafCertParams {
            cn,
            ou: None,
            san_dns: vec![],
            san_uris: vec![],
            validity_days: VALIDITY_DAYS,
        },
        &ca.cert_pem,
        &ca.key_pem,
    )
    .expect("untrusted client certificate")
}

/// Build an HTTPS client that trusts only `ca_pem` and presents `identity`.
///
/// Every case that needs a separate TLS connection builds its own client here.
/// Two clients holding the SAME leaf are two independent connections carrying
/// one certificate, which is exactly the distinction the shared-quota case rests
/// on.
pub fn https_client(ca_pem: &str, port: u16, identity: Option<&GeneratedCert>) -> reqwest::Client {
    let root = reqwest::Certificate::from_pem(ca_pem.as_bytes()).expect("fixture CA PEM");
    let mut builder = reqwest::Client::builder()
        .timeout(IO_TIMEOUT)
        .no_proxy()
        .resolve("localhost", SocketAddr::from(([127, 0, 0, 1], port)))
        .tls_certs_only([root]);
    if let Some(identity) = identity {
        let mut pem = identity.cert_pem.clone();
        pem.push_str(&identity.key_pem);
        builder = builder
            .identity(reqwest::Identity::from_pem(pem.as_bytes()).expect("client identity PEM"));
    }
    builder.build().expect("HTTPS client")
}

/// The shipped binary, serving TLS, with its log captured.
pub struct TlsGateway {
    child: Child,
    directory: TempDir,
    port: u16,
    pub url: String,
}

impl TlsGateway {
    /// Run the production CLI against `config` and wait until it answers a
    /// health probe over TLS.
    ///
    /// The probe presents `readiness`, a trusted client leaf, because
    /// `require_client_cert` refuses an anonymous handshake at every route —
    /// health included. A probe without one could not tell a listener that is
    /// still starting from a listener that is working exactly as configured.
    pub async fn start(config: Value, fixture: &CertFixture, readiness: &GeneratedCert) -> Self {
        let mut config = config;
        let directory = tempfile::tempdir().expect("gateway directory");
        let reservation = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve port");
        let port = reservation.local_addr().expect("reserved address").port();
        config["server"]["port"] = json!(port);
        let config_path = directory.path().join("gateway.yaml");
        std::fs::write(
            &config_path,
            serde_yaml::to_string(&config).expect("config YAML"),
        )
        .expect("write gateway config");
        let log = std::fs::File::create(directory.path().join("gateway.log")).expect("gateway log");
        let mut command = child_command(directory.path(), &config_path);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().expect("clone gateway log")))
            .stderr(Stdio::from(log));
        drop(reservation);
        let child = command.spawn().expect("spawn real TLS gateway");
        let mut gateway = Self {
            child,
            directory,
            port,
            url: format!("https://localhost:{port}"),
        };
        let probe = https_client(fixture.ca_pem(), port, Some(readiness));
        let deadline = tokio::time::Instant::now() + IO_TIMEOUT;
        loop {
            if let Some(status) = gateway.child.try_wait().expect("gateway process status") {
                panic!(
                    "TLS gateway startup fixture exited {status}: {}",
                    read_logs(gateway.directory.path())
                );
            }
            if probe
                .get(format!("{}/health", gateway.url))
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "TLS gateway readiness fixture timed out: {}",
                read_logs(gateway.directory.path())
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        gateway
    }

    /// A fresh HTTPS client for this listener, optionally presenting `identity`.
    pub fn client(
        &self,
        fixture: &CertFixture,
        identity: Option<&GeneratedCert>,
    ) -> reqwest::Client {
        https_client(fixture.ca_pem(), self.port, identity)
    }

    pub fn logs(&self) -> String {
        read_logs(self.directory.path())
    }
}

fn read_logs(directory: &Path) -> String {
    let path: PathBuf = directory.join("gateway.log");
    std::fs::read_to_string(path).unwrap_or_default()
}
