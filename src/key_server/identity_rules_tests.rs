// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A9: OIDC email, issuer and revocation rules.
//!
//! Tokens are signed with a real ES256 key and verified by the real
//! [`OidcVerifier`] against a JWKS served over loopback HTTP, next to the real
//! `/auth/token` routes. Configs and rules are built through serde so every
//! cell compiles against both the old and the new config shape.

use std::sync::Arc;

use axum::{Router, routing::get};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use crate::config::{KeyServerConfig, KeyServerOidcConfig, KeyServerPolicyConfig};
use crate::control_plane::ControlPlaneRoleMappingConfig;
use crate::gateway::oauth::{GatewayKeyPair, jwks_handler};
use crate::key_server::handler::key_server_routes;
use crate::key_server::oidc::{OidcError, VerifiedIdentity};
use crate::key_server::policy::{PolicyEngine, RequestedScopes};
use crate::key_server::{InMemoryTokenStore, KeyServer, OidcVerifier};

const ISS_A: &str = "https://idp-a.example";
const ISS_B: &str = "https://idp-b.example";
const AUD: &str = "mcp-gateway-a9";
const ADMIN: &str = "a9-admin-token";

/// A running key server whose providers all trust one local signing key.
struct Harness {
    addr: std::net::SocketAddr,
    key: Arc<GatewayKeyPair>,
    ks: Arc<KeyServer>,
}

/// Parse a `key_server` YAML document, then run load-time validation.
fn load(yaml: &str) -> Result<KeyServerConfig, String> {
    let cfg: KeyServerConfig = serde_yaml::from_str(yaml).map_err(|e| e.to_string())?;
    cfg.validate().map_err(|e| e.to_string())?;
    Ok(cfg)
}

/// Two providers (A and B) with a shared audience, plus `extra` YAML
/// (policies, overrides) appended at the `key_server` level.
fn config_yaml(allowed_domains_a: &str, extra: &str) -> String {
    format!(
        "enabled: true\nadmin_token: \"{ADMIN}\"\noidc:\n  \
         - issuer: \"{ISS_A}\"\n    audiences: [\"{AUD}\"]\n    auto_discover: false\n    \
         jwks_uri: \"JWKS\"\n    allowed_domains: {allowed_domains_a}\n  \
         - issuer: \"{ISS_B}\"\n    audiences: [\"{AUD}\"]\n    auto_discover: false\n    \
         jwks_uri: \"JWKS\"\n{extra}"
    )
}

impl Harness {
    async fn start(yaml: &str) -> Self {
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
    fn mint(&self, iss: &str, sub: &str, extra: &Value) -> String {
        let info = self.key.key_info();
        let now = chrono::Utc::now().timestamp();
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

    async fn verify(&self, token: &str) -> Result<VerifiedIdentity, OidcError> {
        let cfg = KeyServerOidcConfig {
            token_age: crate::key_server::TokenAgeCap::MaxIat(300),
        };
        self.ks.oidc.verify(token, &cfg).await
    }

    /// POST `/auth/token`; returns the status and the JSON body.
    async fn exchange(&self, token: &str) -> (u16, Value) {
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
                ("scope", ""),
            ])
            .send()
            .await
            .expect("exchange");
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    /// DELETE `/auth/tokens?<query>` with the admin bearer.
    async fn revoke(&self, query: &str) -> (u16, Value) {
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

fn policies(rules: &str) -> String {
    format!("policies:\n{rules}")
}

fn engine(rules: &str) -> PolicyEngine {
    let rules: Vec<KeyServerPolicyConfig> = serde_yaml::from_str(rules).expect("rules parse");
    PolicyEngine::new(rules)
}

fn identity(iss: &str, email: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "123".to_string(),
        email: email.to_string(),
        name: None,
        groups: vec![],
        issuer: iss.to_string(),
    }
}

fn matches(engine: &PolicyEngine, id: &VerifiedIdentity) -> bool {
    engine
        .resolve_scopes(id, &RequestedScopes::default())
        .is_ok()
}

const GRANT: &str = "    scopes: { backends: [\"*\"], tools: [\"*\"], rate_limit: 0 }\n";

fn rule(match_block: &str) -> String {
    format!("  - match: {match_block}\n{GRANT}")
}

// ── D1: an unverified email is dropped at the verifier ──────────────────

#[tokio::test]
async fn unverified_email_does_not_match_email_rule() {
    let rules = rule(&format!(
        "{{ issuer: \"{ISS_A}\", email: \"ceo@corp.com\" }}"
    ));
    let h = Harness::start(&config_yaml("[]", &policies(&rules))).await;
    let token = h.mint(
        ISS_A,
        "attacker",
        &json!({"email": "ceo@corp.com", "email_verified": false}),
    );
    let id = h.verify(&token).await.expect("signature is valid");
    assert!(
        h.ks.policy
            .resolve_scopes(&id, &RequestedScopes::default())
            .is_err(),
        "an unverified email must not satisfy an email rule"
    );
    let (status, _) = h.exchange(&token).await;
    assert_eq!(status, 403, "the exchange is refused");
}

#[tokio::test]
async fn missing_email_verified_is_unverified() {
    let rules = rule(&format!("{{ issuer: \"{ISS_A}\", domain: \"corp.com\" }}"));
    let h = Harness::start(&config_yaml("[]", &policies(&rules))).await;
    let token = h.mint(ISS_A, "attacker", &json!({"email": "ceo@corp.com"}));
    let id = h.verify(&token).await.expect("signature is valid");
    assert_eq!(id.email, "", "no email_verified claim means no email");
    assert!(
        h.ks.policy
            .resolve_scopes(&id, &RequestedScopes::default())
            .is_err()
    );
}

#[tokio::test]
async fn unverified_email_fails_allowed_domains() {
    let h = Harness::start(&config_yaml("[\"corp.com\"]", "")).await;
    let token = h.mint(
        ISS_A,
        "attacker",
        &json!({"email": "ceo@corp.com", "email_verified": false}),
    );
    let err = h
        .verify(&token)
        .await
        .expect_err("domain allowlist refuses");
    assert!(
        matches!(err, OidcError::DomainNotAllowed(_)),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn verified_email_matches() {
    let rules = rule(&format!(
        "{{ issuer: \"{ISS_A}\", email: \"ceo@corp.com\" }}"
    ));
    let h = Harness::start(&config_yaml("[]", &policies(&rules))).await;
    for verified in [json!(true), json!("true")] {
        let token = h.mint(
            ISS_A,
            "ceo",
            &json!({"email": "ceo@corp.com", "email_verified": verified}),
        );
        let id = h.verify(&token).await.expect("valid");
        assert_eq!(id.email, "ceo@corp.com", "email_verified={verified}");
        let (status, body) = h.exchange(&token).await;
        assert_eq!(status, 200, "email_verified={verified}: {body}");
    }
}

#[tokio::test]
async fn role_mapping_ignores_unverified_email() {
    let h = Harness::start(&config_yaml("[]", "")).await;
    let mapping: ControlPlaneRoleMappingConfig = serde_yaml::from_str(&format!(
        "rules:\n  - {{ issuer: \"{ISS_A}\", domain: \"corp.com\", role: admin }}\n"
    ))
    .expect("mapping parses");
    mapping.validate().expect("mapping is valid");
    let token = h.mint(
        ISS_A,
        "attacker",
        &json!({"email": "ceo@corp.com", "email_verified": false}),
    );
    let id = h.verify(&token).await.expect("valid");
    assert_eq!(mapping.resolve_role(&id), None);
}

// ── D2: one comparison helper ───────────────────────────────────────────

#[test]
fn email_and_domain_compare_case_insensitively() {
    let id = identity(ISS_A, "Alice@Corp.COM");
    let by_email = engine(&rule(&format!(
        "{{ issuer: \"{ISS_A}\", email: \"alice@corp.com\" }}"
    )));
    let by_domain = engine(&rule(&format!(
        "{{ issuer: \"{ISS_A}\", domain: \"corp.com\" }}"
    )));
    assert!(matches(&by_email, &id), "email rule");
    assert!(matches(&by_domain, &id), "domain rule");
}

#[test]
fn address_without_single_at_has_no_domain() {
    let by_domain = engine(&rule(&format!(
        "{{ issuer: \"{ISS_A}\", domain: \"corp.com\" }}"
    )));
    for email in ["corp.com", "a@b@corp.com", "@corp.com"] {
        assert!(!matches(&by_domain, &identity(ISS_A, email)), "{email}");
    }
}

#[tokio::test]
async fn allowed_domains_compare_case_insensitively() {
    let h = Harness::start(&config_yaml("[\"corp.com\"]", "")).await;
    let token = h.mint(
        ISS_A,
        "a",
        &json!({"email": "a@CORP.com", "email_verified": true}),
    );
    h.verify(&token).await.expect("accepted");
}

#[test]
fn role_mapping_email_domain_case_insensitive() {
    let mapping: ControlPlaneRoleMappingConfig = serde_yaml::from_str(&format!(
        "rules:\n  - {{ issuer: \"{ISS_A}\", domain: \"corp.com\", role: admin }}\n  \
         - {{ issuer: \"{ISS_B}\", email: \"a@corp.com\", role: auditor }}\n"
    ))
    .expect("mapping parses");
    assert!(
        mapping
            .resolve_role(&identity(ISS_A, "A@Corp.com"))
            .is_some()
    );
    assert!(
        mapping
            .resolve_role(&identity(ISS_B, "A@Corp.com"))
            .is_some()
    );
}

// ── D3 / D3a: every rule names a configured issuer ──────────────────────

#[test]
fn rule_without_issuer_fails_to_load() {
    let cases = [
        rule("{ email: \"x@corp.com\" }"),
        rule("{}"),
        rule("{ issuer: \"https://typo.example\" }"),
        rule("{ issuer: \"   \" }"),
        rule(&format!("{{ issuer: \"{ISS_A}\", email: \"  \" }}")),
        rule(&format!("{{ issuer: \"{ISS_A}\", domain: \"\" }}")),
        rule(&format!("{{ issuer: \"{ISS_A}\", group: \" \" }}")),
    ];
    for rules in cases {
        let err = load(&config_yaml("[]", &policies(&rules)))
            .expect_err(&format!("must not load:\n{rules}"));
        assert!(
            err.contains("issuer") || err.contains("blank"),
            "the error names the defect: {err}"
        );
    }
}

fn public_issuer_yaml(issuer: &str, match_extra: &str) -> String {
    format!(
        "enabled: true\noidc:\n  - issuer: \"{issuer}\"\n    audiences: [\"{AUD}\"]\n\
         policies:\n  - match: {{ issuer: \"{issuer}\"{match_extra} }}\n{GRANT}"
    )
}

const PUBLIC_ISSUERS: [&str; 5] = [
    "https://accounts.google.com",
    "accounts.google.com",
    "https://accounts.google.com/",
    "https://token.actions.githubusercontent.com",
    "HTTPS://Token.Actions.GithubUserContent.com",
];

#[test]
fn issuer_only_rule_on_public_issuer_fails_to_load() {
    for issuer in PUBLIC_ISSUERS {
        let err = load(&public_issuer_yaml(issuer, ""))
            .expect_err(&format!("issuer-only rule on {issuer} must not load"));
        assert!(
            err.contains("multi-tenant")
                && err.contains("policies[0]")
                && err.contains("it issues for our audience"),
            "{issuer}: {err}"
        );
    }
}

#[test]
fn issuer_rule_with_domain_on_public_issuer_loads() {
    for issuer in PUBLIC_ISSUERS {
        load(&public_issuer_yaml(issuer, ", domain: \"corp.com\""))
            .unwrap_or_else(|e| panic!("{issuer}: {e}"));
    }
}

#[tokio::test]
async fn rule_for_issuer_a_ignores_issuer_b() {
    let rules = rule(&format!("{{ issuer: \"{ISS_A}\", domain: \"corp.com\" }}"));
    let h = Harness::start(&config_yaml("[]", &policies(&rules))).await;
    let token = h.mint(
        ISS_B,
        "bob",
        &json!({"email": "bob@corp.com", "email_verified": true}),
    );
    let (status, _) = h.exchange(&token).await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn issuer_only_rule_matches_any_verified_account() {
    let rules = rule(&format!("{{ issuer: \"{ISS_A}\" }}"));
    let h = Harness::start(&config_yaml("[]", &policies(&rules))).await;
    let token = h.mint(ISS_A, "entra-user", &json!({}));
    let (status, body) = h.exchange(&token).await;
    assert_eq!(status, 200, "{body}");
}

// ── D4: identity is (issuer, sub) in the key server ─────────────────────

fn both_issuers(extra: &str) -> String {
    let rules = format!(
        "{}{}",
        rule(&format!("{{ issuer: \"{ISS_A}\" }}")),
        rule(&format!("{{ issuer: \"{ISS_B}\" }}"))
    );
    config_yaml("[]", &format!("{extra}{}", policies(&rules)))
}

#[tokio::test]
async fn revoke_is_scoped_to_issuer() {
    let h = Harness::start(&both_issuers("")).await;
    let (sa, a) = h.exchange(&h.mint(ISS_A, "123", &json!({}))).await;
    let (sb, b) = h.exchange(&h.mint(ISS_B, "123", &json!({}))).await;
    assert_eq!((sa, sb), (200, 200), "{a} {b}");
    let issuer_a: String = url::form_urlencoded::byte_serialize(ISS_A.as_bytes()).collect();
    let (status, body) = h.revoke(&format!("issuer={issuer_a}&subject=123")).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["revoked"], 1, "only (A, 123) is revoked: {body}");
    let bearer_a = a["access_token"].as_str().expect("bearer a");
    let bearer_b = b["access_token"].as_str().expect("bearer b");
    assert!(h.ks.store.get(bearer_a).await.is_none(), "(A, 123) revoked");
    assert!(
        h.ks.store.get(bearer_b).await.is_some(),
        "(B, 123) survives"
    );
}

#[tokio::test]
async fn token_cap_is_scoped_to_issuer() {
    let h = Harness::start(&both_issuers("max_tokens_per_identity: 1\n")).await;
    let (sa, a) = h.exchange(&h.mint(ISS_A, "123", &json!({}))).await;
    assert_eq!(sa, 200, "{a}");
    let (sb, b) = h.exchange(&h.mint(ISS_B, "123", &json!({}))).await;
    assert_eq!(sb, 200, "(B, 123) has its own cap: {b}");
    let (again, _) = h.exchange(&h.mint(ISS_A, "123", &json!({}))).await;
    assert_eq!(again, 429, "(A, 123) is at its cap");
}

#[tokio::test]
async fn revoke_without_issuer_is_400() {
    let h = Harness::start(&both_issuers("")).await;
    let (status, body) = h.revoke("subject=123").await;
    assert_eq!(status, 400, "{body}");
}

// ── BACKENDGRANT.1: an empty backend grant is its own refusal ───────────

#[tokio::test]
async fn empty_backend_grant_is_refused_with_its_own_code() {
    let rules = format!("  - match: {{ issuer: \"{ISS_A}\" }}\n    scopes: {{ tools: [\"*\"] }}\n");
    let h = Harness::start(&config_yaml("[]", &policies(&rules))).await;

    let token = h.mint(ISS_A, "no-backends", &json!({}));
    let (status, body) = h.exchange(&token).await;
    assert_eq!(status, 403, "no token that reaches nothing: {body}");
    assert_eq!(body["error"], "no_backends_granted", "{body}");
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("backends")),
        "the refusal names the fix: {body}"
    );

    let token = h.mint(ISS_B, "no-rule", &json!({}));
    let (status, body) = h.exchange(&token).await;
    assert_eq!(status, 403);
    assert_eq!(body["error"], "access_denied", "no matching rule: {body}");
}
