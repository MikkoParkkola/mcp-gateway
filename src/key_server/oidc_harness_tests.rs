// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A key server over loopback HTTP whose OIDC providers trust one local
//! ES256 key: the JWKS is served beside the real `/auth/token` routes, and
//! tokens are verified by the real [`OidcVerifier`]. Shared by tests that
//! need a real ID token or a real exchanged token.

use std::sync::Arc;

use axum::{Router, routing::get};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use crate::config::{KeyServerConfig, KeyServerOidcConfig};
use crate::gateway::oauth::{GatewayKeyPair, jwks_handler};
use crate::key_server::handler::key_server_routes;
use crate::key_server::oidc::{OidcError, VerifiedIdentity};
use crate::key_server::policy::PolicyEngine;
use crate::key_server::{InMemoryTokenStore, KeyServer, OidcVerifier};

pub(crate) const ISS_A: &str = "https://idp-a.example";
pub(crate) const ISS_B: &str = "https://idp-b.example";
pub(crate) const AUD: &str = "mcp-gateway-a9";
pub(crate) const ADMIN: &str = "a9-admin-token";

/// A running key server whose providers all trust one local signing key.
pub(crate) struct Harness {
    pub(crate) addr: std::net::SocketAddr,
    pub(crate) key: Arc<GatewayKeyPair>,
    pub(crate) ks: Arc<KeyServer>,
}

/// Parse a `key_server` YAML document, then run load-time validation.
pub(crate) fn load(yaml: &str) -> Result<KeyServerConfig, String> {
    let cfg: KeyServerConfig = crate::yaml::from_str(yaml).map_err(|e| e.to_string())?;
    cfg.validate().map_err(|e| e.to_string())?;
    Ok(cfg)
}

/// Two providers (A and B) with a shared audience, plus `extra` YAML
/// (policies, overrides) appended at the `key_server` level.
pub(crate) fn config_yaml(allowed_domains_a: &str, extra: &str) -> String {
    format!(
        "enabled: true\nadmin_token: \"{ADMIN}\"\noidc:\n  \
         - issuer: \"{ISS_A}\"\n    audiences: [\"{AUD}\"]\n    auto_discover: false\n    \
         jwks_uri: \"JWKS\"\n    allowed_domains: {allowed_domains_a}\n  \
         - issuer: \"{ISS_B}\"\n    audiences: [\"{AUD}\"]\n    auto_discover: false\n    \
         jwks_uri: \"JWKS\"\n{extra}"
    )
}

impl Harness {
    pub(crate) async fn start(yaml: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let yaml = yaml.replace("JWKS", &format!("http://{addr}/.well-known/jwks.json"));
        let config = load(&yaml).expect("harness config loads");
        let key = Arc::new(GatewayKeyPair::generate().expect("keypair"));
        let ks = Arc::new(KeyServer {
            store: Arc::new(InMemoryTokenStore::new()),
            oidc: Arc::new(OidcVerifier::with_http_client(
                config.oidc.clone(),
                reqwest::Client::new(),
            )),
            policy: Arc::new(PolicyEngine::new(config.policies.clone())),
            config,
        });
        let jwks = Router::new()
            .route("/.well-known/jwks.json", get(jwks_handler))
            .with_state(Arc::clone(&key));
        let app = key_server_routes(Arc::clone(&ks)).merge(jwks);
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        Self { addr, key, ks }
    }

    /// Sign `extra` claims (merged over iss/sub/aud/iat/exp) as an ES256 JWT.
    pub(crate) fn mint(&self, iss: &str, sub: &str, extra: &Value) -> String {
        let info = self.key.key_info();
        let now = i64::try_from(crate::clock::unix_secs().expect("a clock after the epoch"))
            .expect("seconds fit i64");
        let mut claims = json!({"iss": iss, "sub": sub, "aud": AUD, "iat": now, "exp": now + 300});
        for (k, v) in extra.as_object().expect("object") {
            claims[k] = v.clone();
        }
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(info.kid.clone());
        let enc =
            jsonwebtoken::EncodingKey::from_ec_pem(info.private_key_pem.as_bytes()).expect("pem");
        jsonwebtoken::encode(&header, &claims, &enc).expect("sign")
    }

    pub(crate) async fn verify(&self, token: &str) -> Result<VerifiedIdentity, OidcError> {
        let cfg = KeyServerOidcConfig {
            token_age: crate::key_server::TokenAgeCap::MaxIat(300),
        };
        self.ks.oidc.verify(token, &cfg).await
    }

    /// POST `/auth/token`; returns the status and the JSON body.
    pub(crate) async fn exchange(&self, token: &str) -> (u16, Value) {
        self.exchange_scoped(token, "").await
    }

    /// As [`Self::exchange`], requesting `scope` (`backends:a,b tools:x`).
    pub(crate) async fn exchange_scoped(&self, token: &str, scope: &str) -> (u16, Value) {
        let resp = reqwest::Client::new()
            .post(format!("http://{}/auth/token", self.addr))
            .form(&[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                ("subject_token", token),
                (
                    "subject_token_type",
                    "urn:ietf:params:oauth:token-type:id_token",
                ),
                ("scope", scope),
            ])
            .send()
            .await
            .expect("exchange");
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    /// DELETE `/auth/tokens?<query>` with the admin bearer.
    pub(crate) async fn revoke(&self, query: &str) -> (u16, Value) {
        let resp = reqwest::Client::new()
            .delete(format!("http://{}/auth/tokens?{query}", self.addr))
            .bearer_auth(ADMIN)
            .send()
            .await
            .expect("revoke");
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(Value::Null))
    }
}
