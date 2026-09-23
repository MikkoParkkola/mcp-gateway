// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only revoke custody for router-level suites (design §11.1).
//!
//! The REAL store, `CustodyHandle` and `PersonalOAuthRefresh`; only the
//! transport is faked. `post_token` is dispatched with `oneshot` into an
//! in-process axum router whose `/revoke` records every token it receives and
//! answers a scripted status. No socket, no TLS, no new crate.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::{Form, State};
use axum::http::StatusCode;
use axum::routing::post;
use tower::ServiceExt as _;

use super::config::AccountDescriptor;
use super::provider::{
    HttpError, HttpResponse, PersonalOAuthRefresh, ProviderHttp, SecretSource, SystemClock,
};
use super::service::AccountServiceError;
use super::worker::{CustodyError, CustodyHandle};
use super::{
    AccountKey, AccountReleaseAudit, AccountRevocation, GrantRecord, GrantVersion,
    PersonalAccountStore, StoreConfig,
};

pub(crate) const ISSUER: &str = "https://accounts.fixture.test";
pub(crate) const REVOKE_URL: &str = "https://accounts.fixture.test/revoke";
const SECRET_REF: &str = "env:FIXTURE_CLIENT_SECRET";

/// What `/revoke` received, in order: `(token, token_type_hint)`.
pub(crate) type Received = Arc<Mutex<Vec<(String, String)>>>;

#[derive(Clone)]
struct Script {
    received: Received,
    status: Arc<AtomicU16>,
}

async fn revoke_endpoint(
    State(script): State<Script>,
    Form(form): Form<BTreeMap<String, String>>,
) -> StatusCode {
    let field = |name: &str| form.get(name).cloned().unwrap_or_default();
    script
        .received
        .lock()
        .unwrap()
        .push((field("token"), field("token_type_hint")));
    StatusCode::from_u16(script.status.load(Ordering::SeqCst)).unwrap()
}

/// Metadata is answered directly; credential POSTs go through the router.
pub(crate) struct FakeHttp {
    metadata: String,
    router: Router,
}

impl ProviderHttp for FakeHttp {
    fn get_metadata(
        &self,
        _url: &str,
    ) -> impl Future<Output = Result<HttpResponse, HttpError>> + Send {
        std::future::ready(Ok(HttpResponse {
            status: 200,
            body: self.metadata.clone(),
        }))
    }

    async fn post_token(
        &self,
        url: &str,
        form: &[(String, String)],
    ) -> Result<HttpResponse, HttpError> {
        let path = url.strip_prefix(ISSUER).unwrap_or(url).to_string();
        let body = serde_urlencoded::to_string(form).unwrap();
        let request = axum::http::Request::post(path)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        Ok(HttpResponse {
            status,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        })
    }
}

struct FixedSecret;

impl SecretSource for FixedSecret {
    fn resolve(&self, reference: &str) -> Option<String> {
        (reference == SECRET_REF).then(|| "fixture-client-secret".to_string())
    }
}

/// Whether the managed descriptor configures a `revocation_endpoint`.
#[derive(Clone, Copy, Debug)]
pub(crate) enum RevocationEndpoint {
    Configured,
    Absent,
}

/// A managed descriptor pinned to the fake issuer.
pub(crate) fn descriptor(resource: &str, endpoint: RevocationEndpoint) -> AccountDescriptor {
    AccountDescriptor {
        mode: super::config::DescriptorMode::PersonalManaged,
        provider: "fixture".to_string(),
        resource: Some(resource.to_string()),
        issuer: Some(ISSUER.to_string()),
        authorization_endpoint: Some(format!("{ISSUER}/authorize")),
        token_endpoint: Some(format!("{ISSUER}/token")),
        revocation_endpoint: match endpoint {
            RevocationEndpoint::Configured => Some(REVOKE_URL.to_string()),
            RevocationEndpoint::Absent => None,
        },
        client_id: Some("fixture-client".to_string()),
        client_secret_ref: Some(SECRET_REF.to_string()),
        redirect_uri: Some("https://chat.fixture.test/accounts/v1/callback".to_string()),
        scopes: Some(vec!["fixture.read".to_string()]),
        send_resource_parameter: Some(false),
        external_strategy: None,
        authorize_extra: None,
    }
}

/// The state a seeded account is left in before custody starts.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Seed {
    Connected,
    InvalidGrant,
    DescriptorFenced,
    Revoked,
}

type FixtureCustody = CustodyHandle<
    Arc<PersonalOAuthRefresh<FakeHttp, SystemClock, FixedSecret>>,
    AccountReleaseAudit,
>;

/// Running custody plus what the fake provider saw.
pub(crate) struct RevokeFixture {
    custody: Arc<FixtureCustody>,
    pub(crate) received: Received,
    status: Arc<AtomicU16>,
    _root: tempfile::TempDir,
}

fn seed(store: &PersonalAccountStore, key: &AccountKey, record: &GrantRecord, how: Seed) {
    store.commit_grant(key, record).unwrap();
    let version = GrantVersion {
        generation: record.generation.clone(),
        token_revision: record.token_revision,
        authorization_epoch: record.authorization_epoch,
        descriptor_revision: record.descriptor_revision.clone(),
    };
    match how {
        Seed::Connected => {}
        Seed::InvalidGrant => {
            store.fence_expected_version(key, &version).unwrap();
        }
        Seed::DescriptorFenced => store.mark_reconnect_required(key, &"1".repeat(64)).unwrap(),
        Seed::Revoked => store.revoke(key).unwrap(),
    }
}

/// A grant whose two tokens are distinct per `label`.
pub(crate) fn grant(label: &str) -> GrantRecord {
    GrantRecord {
        generation: "fedcba9876543210fedcba9876543210".into(),
        token_revision: 1,
        authorization_epoch: 1,
        descriptor_revision: "0".repeat(64),
        scopes: vec!["fixture.read".into()],
        access_token: format!("synthetic-{label}-access-7d1e"),
        refresh_token: Some(format!("synthetic-{label}-refresh-4b2c")),
        token_type: "Bearer".into(),
        expires_at: u64::MAX,
        provider_account_id: None,
        client_id: "fixture-client".into(),
    }
}

impl RevokeFixture {
    /// Seed the store, then start the real custody over the fake transport.
    /// The metadata advertises `/revoke` whatever `endpoint` is, so `Absent`
    /// also proves the gateway never falls back to a discovered endpoint.
    pub(crate) async fn start(
        account_id: &str,
        resource: &str,
        seeds: &[(AccountKey, GrantRecord, Seed)],
        endpoint: RevocationEndpoint,
    ) -> Self {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().canonicalize().unwrap();
        let config = StoreConfig {
            instance_id: "revoke-fixture".into(),
            store_dir: base.join("records"),
            authority_dir: base.join("authority"),
            current_key_id: "current".into(),
            keys: BTreeMap::from([("current".into(), vec![7_u8; 32])]),
            max_entries: 64,
            max_authority_bytes: 1 << 20,
        };
        let store = PersonalAccountStore::initialize(config.clone()).unwrap();
        for (key, record, how) in seeds {
            seed(&store, key, record, *how);
        }
        drop(store);
        let received = Received::default();
        let status = Arc::new(AtomicU16::new(200));
        let script = Script {
            received: Arc::clone(&received),
            status: Arc::clone(&status),
        };
        let router = Router::new()
            .route("/revoke", post(revoke_endpoint))
            .with_state(script);
        let metadata = format!(
            r#"{{"issuer":"{ISSUER}","authorization_endpoint":"{ISSUER}/authorize",
                "token_endpoint":"{ISSUER}/token","revocation_endpoint":"{REVOKE_URL}"}}"#
        );
        let descriptors =
            BTreeMap::from([(account_id.to_string(), descriptor(resource, endpoint))]);
        let http = FakeHttp { metadata, router };
        let provider = PersonalOAuthRefresh::bootstrap(descriptors, http, SystemClock, FixedSecret)
            .await
            .expect("fixture descriptor bootstraps");
        let custody =
            CustodyHandle::start(config, Arc::new(provider), AccountReleaseAudit, 4).unwrap();
        Self {
            custody: Arc::new(custody),
            received,
            status,
            _root: root,
        }
    }

    /// The handle the router is given.
    pub(crate) fn revocation(&self) -> Arc<dyn AccountRevocation> {
        Arc::clone(&self.custody) as Arc<dyn AccountRevocation>
    }

    /// Script the next `/revoke` answers.
    pub(crate) fn answer(&self, status: u16) {
        self.status.store(status, Ordering::SeqCst);
    }

    /// Durable state, read through the live custody (`resolve` never mints).
    pub(crate) async fn state(&self, key: &AccountKey) -> &'static str {
        match self.custody.resolve(key).await {
            Ok(_) => "connected",
            Err(CustodyError::Account(AccountServiceError::Revoked)) => "revoked",
            Err(CustodyError::Account(AccountServiceError::ReconnectRequired)) => "reconnect",
            Err(CustodyError::Account(AccountServiceError::ConnectOffer)) => "absent",
            Err(_) => "error",
        }
    }

    pub(crate) fn received(&self) -> Vec<(String, String)> {
        self.received.lock().unwrap().clone()
    }
}
