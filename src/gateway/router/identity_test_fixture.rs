// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#![cfg_attr(
    test,
    allow(
        clippy::disallowed_methods,
        reason = "test code reads the host clock (MIK-8202 AC.14)"
    )
)]
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::http::{HeaderMap, HeaderValue};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;
use telemetry_metrics::{
    Counter, CounterFn, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit,
};

use super::*;
use crate::gateway::oauth::{GatewayKeyPair, jwks_handler};
use crate::key_server::oidc::cloudflare_access_provider;
use crate::security::caller_identity::CloudflareAccessConfig;

pub(super) const TEAM: &str = "acme.cloudflareaccess.com";
pub(super) const AUD: &str = "aud-tag-1";

pub(super) fn proxy_mode() -> CallerIdentityConfig {
    CallerIdentityConfig {
        mode: CallerIdentityMode::TrustedProxy,
        trusted_proxies: vec!["10.0.0.5".parse().unwrap()],
        authority: "corp-sso".to_string(),
        ..CallerIdentityConfig::default()
    }
}

pub(super) fn access_mode() -> CallerIdentityConfig {
    CallerIdentityConfig {
        mode: CallerIdentityMode::CloudflareAccess,
        cloudflare_access: CloudflareAccessConfig {
            team_domain: TEAM.to_string(),
            audiences: vec![AUD.to_string()],
        },
        ..CallerIdentityConfig::default()
    }
}

pub(super) fn peer(addr: &str) -> SocketAddr {
    SocketAddr::new(addr.parse().unwrap(), 40000)
}

pub(super) const TRUSTED: &str = "10.0.0.5";
pub(super) const OUTSIDER: &str = "203.0.113.9";

pub(super) fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.append(*name, HeaderValue::from_str(value).unwrap());
    }
    map
}

// ── Access assertion fixture ────────────────────────────────────────────────

/// A signing key and a loopback JWKS endpoint serving its public half.
pub(super) struct AccessIdp {
    pub(super) key: Arc<GatewayKeyPair>,
    pub(super) jwks_uri: String,
}

impl AccessIdp {
    pub(super) async fn start() -> Self {
        let key = Arc::new(GatewayKeyPair::generate().unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new()
            .route("/cdn-cgi/access/certs", axum::routing::get(jwks_handler))
            .with_state(Arc::clone(&key));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            key,
            jwks_uri: format!("http://{addr}/cdn-cgi/access/certs"),
        }
    }

    /// The production provider for `access_mode()`, with only the certs URL
    /// pointed at the loopback server.
    pub(super) fn verifier(&self) -> OidcVerifier {
        let provider = crate::config::KeyServerProviderConfig {
            jwks_uri: Some(self.jwks_uri.clone()),
            ..cloudflare_access_provider(&access_mode().cloudflare_access)
        };
        OidcVerifier::with_http_client(vec![provider], reqwest::Client::new())
    }

    pub(super) fn sign(&self, claims: &serde_json::Value) -> String {
        sign_with(&self.key, &self.key.key_info().kid, claims)
    }
}

/// Sign with `key` but name `kid`, so a forged token can claim a trusted key id.
pub(super) fn sign_with(key: &GatewayKeyPair, kid: &str, claims: &serde_json::Value) -> String {
    let info = key.key_info();
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(kid.to_string());
    let encoding = EncodingKey::from_ec_pem(info.private_key_pem.as_bytes()).unwrap();
    jsonwebtoken::encode(&header, claims, &encoding).unwrap()
}

pub(super) fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

/// Access-shaped claims for `sub`, issued `iat_ago` seconds ago and expiring
/// `exp_in` seconds from now.
pub(super) fn access_claims(sub: &str, aud: &str, iat_ago: i64, exp_in: i64) -> serde_json::Value {
    json!({
        "iss": format!("https://{TEAM}"),
        "sub": sub,
        "aud": [aud],
        "email": "u@corp.example",
        "iat": now() - iat_ago,
        "exp": now() + exp_in,
    })
}

// ── Counter capture ─────────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct Hits(Arc<AtomicU64>);

impl CounterFn for Hits {
    fn increment(&self, value: u64) {
        self.0.fetch_add(value, Ordering::SeqCst);
    }
    fn absolute(&self, value: u64) {
        self.0.fetch_max(value, Ordering::SeqCst);
    }
}

/// Tallies one counter series: `name{reason=<reason>}`.
struct Watch {
    name: &'static str,
    reason: &'static str,
    hits: Hits,
}

impl Recorder for Watch {
    fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
        let reason = key
            .labels()
            .any(|l| l.key() == "reason" && l.value() == self.reason);
        if key.name() == self.name && reason {
            Counter::from_arc(Arc::new(self.hits.clone()))
        } else {
            Counter::noop()
        }
    }
    fn register_gauge(&self, _: &Key, _: &Metadata<'_>) -> Gauge {
        Gauge::noop()
    }
    fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
        Histogram::noop()
    }
}

/// Run `case` with a thread-local recorder and return how often the watched
/// series was incremented. `#[tokio::test]` is single-threaded.
pub(super) async fn count<T>(
    name: &'static str,
    reason: &'static str,
    case: impl std::future::Future<Output = T>,
) -> (T, u64) {
    let watch = Watch {
        name,
        reason,
        hits: Hits::default(),
    };
    let out = {
        let _guard = telemetry_metrics::set_default_local_recorder(&watch);
        case.await
    };
    (out, watch.hits.0.load(Ordering::SeqCst))
}
