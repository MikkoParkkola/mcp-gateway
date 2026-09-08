// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Ephemeral HTTPS JWKS issuer for real production-builder OIDC admission tests.
//! Linux rustls-platform-verifier consumes the child-local SSL_CERT_FILE. No
//! verifier injection, machine trust-store edit, or TLS verification bypass.

use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{Router, routing::get};
use axum_server::tls_rustls::RustlsConfig;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mcp_gateway::gateway::oauth::GatewayKeyPair;
use mcp_gateway::mtls::{CaParams, CertGenerator, LeafCertParams};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::task::JoinHandle;

pub const ISSUER: &str = "https://idp.example";
pub const AUDIENCE: &str = "sub4-gateway-client";

pub struct OidcFixture {
    pub jwks_url: String,
    pub ca_path: PathBuf,
    key: GatewayKeyPair,
    fetches: Arc<AtomicUsize>,
    task: JoinHandle<()>,
    _directory: TempDir,
}

impl OidcFixture {
    pub async fn start() -> Self {
        let ca = CertGenerator::init_ca(&CaParams {
            cn: "SUB4 ephemeral issuer CA",
            validity_days: 1,
        })
        .unwrap();
        let leaf = CertGenerator::issue_leaf(
            &LeafCertParams {
                cn: "localhost",
                ou: None,
                san_dns: vec!["localhost".into()],
                san_uris: vec![],
                validity_days: 1,
            },
            &ca.cert_pem,
            &ca.key_pem,
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let ca_path = directory.path().join("issuer-ca.pem");
        std::fs::write(&ca_path, &ca.cert_pem).unwrap();
        let tls = RustlsConfig::from_pem(leaf.cert_pem.into_bytes(), leaf.key_pem.into_bytes())
            .await
            .unwrap();
        let key = GatewayKeyPair::generate().unwrap();
        let jwks = serde_json::to_value(key.jwks()).unwrap();
        let fetches = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&fetches);
        let app = Router::new().route(
            "/jwks",
            get(move || {
                let jwks = jwks.clone();
                let observed = Arc::clone(&observed);
                async move {
                    observed.fetch_add(1, Ordering::SeqCst);
                    axum::Json(jwks)
                }
            }),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let server = axum_server::from_tcp_rustls(listener, tls).unwrap();
        let task = tokio::spawn(async move {
            server.serve(app.into_make_service()).await.unwrap();
        });
        let fixture = Self {
            jwks_url: format!("https://localhost:{port}/jwks"),
            ca_path,
            key,
            fetches,
            task,
            _directory: directory,
        };
        let client = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(reqwest::Certificate::from_pem(ca.cert_pem.as_bytes()).unwrap())
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(response) = client.get(&fixture.jwks_url).send().await {
                assert!(response.status().is_success(), "JWKS readiness status");
                let body: Value = response.json().await.expect("JWKS readiness JSON");
                assert_eq!(body["keys"].as_array().unwrap().len(), 1);
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "HTTPS JWKS readiness timeout"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Readiness is fixture traffic. Subsequent positive counts must come
        // from the production gateway, not from our own TLS probe.
        fixture.fetches.store(0, Ordering::SeqCst);
        fixture
    }

    pub fn configure(&self, config: &mut Value) {
        config["auth"] = json!({"enabled":true,"public_paths":["/health"]});
        config["key_server"] = json!({"enabled":true,"delegated_bearer":true,
            "oidc":[{"issuer":ISSUER,"jwks_uri":self.jwks_url,"auto_discover":false,"audiences":[AUDIENCE]}],
            "policies":[{"match":{"issuer":ISSUER},"scopes":{"backends":["*"],"tools":["*"],"rate_limit":0}}]
        });
    }

    pub fn token(&self, subject: &str, generation: u64) -> String {
        self.token_for_issuer(ISSUER, subject, generation)
    }

    pub fn token_for_issuer(&self, issuer: &str, subject: &str, generation: u64) -> String {
        let key = self.key.key_info();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(key.kid);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        jsonwebtoken::encode(&header, &json!({
            "iss":issuer,"aud":AUDIENCE,"sub":subject,"iat":now,"exp":now+120,
            "email":"same-display@example.test","name":"Same Display Name","jti":generation.to_string()
        }), &jsonwebtoken::EncodingKey::from_ec_pem(key.private_key_pem.as_bytes()).unwrap()).unwrap()
    }

    pub fn fetch_count(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }

    pub fn invalid_signature(&self, token: &str) -> String {
        let parts: Vec<_> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let mut signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(signature.len(), 64, "ES256 signature remains well-formed");
        signature[0] ^= 1;
        format!(
            "{}.{}.{}",
            parts[0],
            parts[1],
            URL_SAFE_NO_PAD.encode(signature)
        )
    }
}

impl Drop for OidcFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
