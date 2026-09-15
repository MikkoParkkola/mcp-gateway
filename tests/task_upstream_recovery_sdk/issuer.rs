// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An owned, temporary HTTPS OIDC issuer.
//!
//! The gateway under test authenticates its callers through the PRODUCTION path
//! — `key_server::OidcVerifier` reached from `auth::key_server_credential` —
//! which fetches the discovery document and the JWKS with a `https_only` client
//! it builds itself. Nothing here weakens that: the issuer really speaks TLS,
//! and the child is given a temporary CA through the trust mechanism its own
//! dependency chain honours (see `pins::require_supported_trust_override`).
//!
//! The tokens are real ES256 JWTs signed by the key this issuer publishes, so a
//! forged or unknown-key token is refused by the same code that accepts these.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::{Json, Router, extract::State, routing::get};
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use mcp_gateway::mtls::{CaParams, CertGenerator};
use rcgen::string::Ia5String;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, Issuer as RcgenIssuer, KeyPair, SanType,
};
use serde::Serialize;
use serde_json::{Value, json};

/// The audience every token here is minted for, and the only audience the
/// gateway is configured to accept.
pub const AUDIENCE: &str = "mcp-gateway-upstream-vertical";
const KID: &str = "upstream-vertical-es256";

#[derive(Serialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    email: String,
    iat: u64,
    exp: u64,
}

struct IssuerState {
    discovery: Value,
    jwks: Value,
}

/// A running issuer. Dropping it shuts the listener down; nothing outlives the
/// test that created it.
pub struct Issuer {
    pub url: String,
    /// PEM file holding ONLY this run's CA, handed to the gateway child.
    pub ca_file: PathBuf,
    signing: EncodingKey,
    handle: axum_server::Handle<SocketAddr>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Issuer {
    fn drop(&mut self) {
        self.handle.shutdown();
        self.server.abort();
    }
}

impl Issuer {
    /// Generate a CA and a loopback server certificate, publish a discovery
    /// document and a JWKS over HTTPS, and return once the chain verifies from
    /// this process — so a later failure in the gateway is a gateway fact.
    pub async fn start(root: &Path) -> Self {
        // One process-wide default provider; `install_default` is idempotent by
        // returning Err when one is already installed.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let ca = CertGenerator::init_ca(&CaParams {
            cn: "upstream vertical temporary CA",
            validity_days: 1,
        })
        .expect("the gateway's own CA helper generates a temporary CA");

        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("the issuer binds an ephemeral loopback port");
        listener
            .set_nonblocking(true)
            .expect("the bound listener switches to non-blocking");
        let addr: SocketAddr = listener
            .local_addr()
            .expect("the bound listener reports its address");
        let url = format!("https://{addr}");

        // `CertGenerator::issue_leaf` carries DNS and URI SANs only, and the
        // issuer must be addressed by IP so no name resolution can send the
        // child somewhere else. The CA above is still the shipped helper's.
        let leaf_key = KeyPair::generate().expect("a leaf key pair");
        let mut leaf = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "127.0.0.1");
        leaf.distinguished_name = dn;
        leaf.subject_alt_names = vec![
            SanType::IpAddress(addr.ip()),
            SanType::DnsName(Ia5String::try_from("localhost").expect("a literal DNS SAN")),
        ];
        let ca_key = KeyPair::from_pem(&ca.key_pem).expect("the CA key parses");
        let ca_issuer =
            RcgenIssuer::from_ca_cert_pem(&ca.cert_pem, ca_key).expect("the CA cert parses");
        let leaf_pem = leaf
            .signed_by(&leaf_key, &ca_issuer)
            .expect("the CA signs the issuer's certificate")
            .pem();

        // The signing key: ES256 over the P-256 pair, published as the JWK the
        // gateway will look up by `kid`.
        let signing_key = KeyPair::generate().expect("an issuer signing key pair");
        let point = signing_key.public_key_raw();
        assert_eq!(
            (point.len(), point.first().copied()),
            (65, Some(0x04)),
            "an uncompressed P-256 point is 0x04 followed by X and Y"
        );
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let state = Arc::new(IssuerState {
            discovery: json!({
                "issuer": url,
                "jwks_uri": format!("{url}/jwks.json"),
                "response_types_supported": ["id_token"],
                "id_token_signing_alg_values_supported": ["ES256"],
            }),
            jwks: json!({ "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "use": "sig",
                "alg": "ES256",
                "kid": KID,
                "x": b64.encode(&point[1..33]),
                "y": b64.encode(&point[33..65]),
            }]}),
        });

        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(|State(state): State<Arc<IssuerState>>| async move {
                    Json(state.discovery.clone())
                }),
            )
            .route(
                "/jwks.json",
                get(
                    |State(state): State<Arc<IssuerState>>| async move { Json(state.jwks.clone()) },
                ),
            )
            .with_state(state);

        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            leaf_pem.into_bytes(),
            leaf_key.serialize_pem().into_bytes(),
        )
        .await
        .expect("the generated certificate and key load into rustls");

        let handle = axum_server::Handle::new();
        let server_handle = handle.clone();
        let server = tokio::spawn(async move {
            let _ = axum_server::from_tcp_rustls(listener, tls)
                .expect("the issuer serves TLS on its own listener")
                .handle(server_handle)
                .serve(app.into_make_service())
                .await;
        });

        let ca_file = root.join("issuer-ca.pem");
        std::fs::write(&ca_file, &ca.cert_pem).expect("the CA is written inside the temp root");

        let issuer = Self {
            url,
            ca_file,
            signing: EncodingKey::from_ec_pem(signing_key.serialize_pem().as_bytes())
                .expect("the P-256 private key loads as an ES256 signing key"),
            handle,
            server,
        };
        issuer.verify_reachable().await;
        issuer
    }

    /// Fetch our own discovery document over TLS, trusting only this run's CA.
    /// A precondition, checked here so the gateway's failure would be its own.
    async fn verify_reachable(&self) {
        let ca = std::fs::read(&self.ca_file).expect("the CA file reads back");
        let client = reqwest::Client::builder()
            .timeout(crate::pins::REQUEST_BOUND)
            .tls_certs_only([reqwest::Certificate::from_pem(&ca).expect("the CA is a usable root")])
            .build()
            .expect("a client trusting only this run's CA");

        let deadline = tokio::time::Instant::now() + crate::pins::PEER_BOUND;
        loop {
            match client
                .get(format!("{}/.well-known/openid-configuration", self.url))
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => return,
                other => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "the temporary issuer never served its discovery document \
                         over TLS at {}: {other:?}",
                        self.url
                    );
                    tokio::time::sleep(crate::pins::POLL_GAP).await;
                }
            }
        }
    }

    /// A valid, freshly signed bearer for one owner. Real signature, real
    /// `kid`, real audience: the gateway verifies it through `OidcVerifier`.
    pub fn mint(&self, subject: &str, email: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after the epoch")
            .as_secs();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(KID.to_string());
        jsonwebtoken::encode(
            &header,
            &Claims {
                iss: self.url.clone(),
                sub: subject.to_string(),
                aud: AUDIENCE.to_string(),
                email: email.to_string(),
                iat: now,
                exp: now + 3_600,
            },
            &self.signing,
        )
        .expect("the issuer signs its own token")
    }
}
