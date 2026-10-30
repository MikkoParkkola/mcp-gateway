// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The sign-in state of a backend: each variant from its own fixture, the
//! precedence of a wait over a held token, a read that does no I/O, and a
//! status that follows the client and outlives its transport. Token expiry
//! reads `SystemTime`, so the fixtures seed already-past expiries and no row
//! waits on a clock.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use super::authorize_tests::{BACKEND, RESOURCE, client, token_endpoint};
use super::sign_in::{SignIn, SignInStatus};
use super::*;
use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig, OAuthConfig};

/// 2100-01-01: unexpired whenever this runs.
const FAR_FUTURE: u64 = 4_102_444_800;
/// 1970-01-01 plus a second: expired whenever this runs.
const LONG_PAST: u64 = 1;

fn token(refresh: Option<&str>, expires_at: u64) -> TokenInfo {
    let mut token =
        TokenInfo::from_response("held".into(), None, refresh.map(Into::into), None, None);
    token.expires_at = Some(expires_at);
    token
}

/// The file name v3.5.1 wrote a backend's tokens to, hashed here rather than
/// through the storage under test.
fn legacy_file_name() -> String {
    let mut hasher = Sha256::new();
    hasher.update(BACKEND.as_bytes());
    hasher.update(b":");
    hasher.update(RESOURCE.as_bytes());
    format!("{}_tokens.json", hex::encode(&hasher.finalize()[..8]))
}

/// A client over a store in `dir`, publishing into a fresh cell that starts
/// at `NotYetChecked`. `resolved` is whether its issuer is known.
fn publishing(
    dir: &std::path::Path,
    issuer: &str,
    resolved: bool,
) -> (OAuthClient, Arc<SignInStatus>) {
    let cell = Arc::new(SignInStatus::new(SignIn::NotYetChecked));
    let client = client(dir, resolved.then_some(issuer)).with_sign_in_status(Arc::clone(&cell));
    (client, cell)
}

fn seed(client: &OAuthClient, token: &TokenInfo) {
    let key = client
        .credential_key()
        .expect("a resolved issuer keys the store");
    client
        .storage
        .save(&key, RESOURCE, token)
        .expect("seed saves");
}

/// A published status for a client whose store holds `held` (if any).
async fn published(held: Option<TokenInfo>, legacy: bool, resolved: bool) -> SignIn {
    let dir = tempfile::tempdir().unwrap();
    let (issuer, _forms) = token_endpoint(None).await;
    let (client, cell) = publishing(dir.path(), &issuer, resolved);
    if let Some(held) = held {
        seed(&client, &held);
    }
    if legacy {
        let record = r#"{"access_token":"legacy","token_type":"Bearer","expires_at":4102444800}"#;
        crate::gateway::test_helpers::write_owner_only(dir.path().join(legacy_file_name()), record)
            .expect("legacy file");
    }
    client.publish_sign_in();
    cell.snapshot()
}

fn oauth_backend(name: &str) -> Backend {
    oauth_backend_at(name, None)
}

/// An OAuth backend whose transport points at `url`, if given.
fn oauth_backend_at(name: &str, url: Option<&str>) -> Backend {
    let transport = url.map(|http_url| crate::config::TransportConfig::Http {
        http_url: http_url.to_owned(),
        streamable_http: Some(true),
        protocol_version: None,
    });
    let config = BackendConfig {
        transport: transport.unwrap_or_default(),
        oauth: Some(OAuthConfig {
            enabled: true,
            scopes: Vec::new(),
            client_id: None,
            client_secret: None,
            callback_host: None,
            callback_port: None,
            callback_path: None,
            token_refresh_buffer_secs: None,
            shared_account: false,
        }),
        ..BackendConfig::default()
    };
    Backend::new(
        name,
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    )
}

// S1
#[tokio::test]
async fn each_sign_in_variant_from_its_fixture() {
    let signed_in = SignIn::SignedIn {
        expires_at: Some(UNIX_EPOCH + Duration::from_secs(FAR_FUTURE)),
    };
    let refreshable = SignIn::SignedIn {
        expires_at: Some(UNIX_EPOCH + Duration::from_secs(LONG_PAST)),
    };
    let plain = Backend::new(
        "plain",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    );
    assert_eq!(plain.sign_in(), SignIn::NotOAuth, "no oauth block, no wait");
    assert_eq!(
        published(None, false, false).await,
        SignIn::NotYetChecked,
        "issuer unresolved"
    );
    assert_eq!(
        published(Some(token(Some("r"), FAR_FUTURE)), false, true).await,
        signed_in
    );
    assert_eq!(
        published(Some(token(Some("r"), LONG_PAST)), false, true).await,
        refreshable
    );
    assert_eq!(
        published(Some(token(None, LONG_PAST)), false, true).await,
        SignIn::Expired
    );
    assert_eq!(published(None, false, true).await, SignIn::NeverSignedIn);
    assert_eq!(
        published(None, true, true).await,
        SignIn::ReSignInAfterUpgrade
    );
}

// S2: a wait over a held token reads `Expired`, never `SignedIn`.
#[tokio::test]
async fn a_token_with_auth_wait_reads_expired() {
    let backend = oauth_backend("waiting");
    backend
        .sign_in
        .status
        .set(SignIn::SignedIn { expires_at: None });
    backend.shared_entry_for_test().auth_wait.set();

    assert_eq!(backend.sign_in(), SignIn::Expired);
    assert!(backend.needs_sign_in());
}

/// How many token loads and legacy-file checks `storage` has served.
fn io_counts(storage: &TokenStorage) -> (usize, usize) {
    let [loads, exists] = &storage.io_counts;
    (loads.load(Ordering::SeqCst), exists.load(Ordering::SeqCst))
}

/// A server that only counts the connections it is offered: the network
/// double for a read that must reach nothing.
async fn counting_server() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    tokio::spawn(async move {
        while listener.accept().await.is_ok() {
            counted.fetch_add(1, Ordering::SeqCst);
        }
    });
    (base, hits)
}

// S3: the issuer resolution does the one load and one legacy check; reads
// afterwards do none, and reach no network.
#[tokio::test]
async fn the_read_does_no_storage_io() {
    let dir = tempfile::tempdir().unwrap();
    let (issuer, hits) = counting_server().await;
    let backend = oauth_backend_at("quiet", Some(&issuer));
    let client =
        client(dir.path(), Some(&issuer)).with_sign_in_status(Arc::clone(&backend.sign_in.status));
    let storage = Arc::clone(&client.storage);

    client.publish_sign_in();
    let after_resolution = io_counts(&storage);
    assert_eq!(
        after_resolution,
        (1, 1),
        "one load and one legacy check at resolution"
    );

    for _ in 0..5 {
        let _ = (backend.sign_in(), backend.needs_sign_in());
    }
    assert_eq!(io_counts(&storage), after_resolution, "a read costs no I/O");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "neither discovery nor the transport was reached"
    );
}

// S4
#[tokio::test]
async fn the_status_survives_a_transport_restart() {
    let backend = oauth_backend("restarting");
    let seeded = SignIn::SignedIn {
        expires_at: Some(UNIX_EPOCH + Duration::from_secs(FAR_FUTURE)),
    };
    backend.sign_in.status.set(seeded);
    assert_eq!(backend.sign_in(), seeded, "the seeded status is read back");

    backend.stop().await.expect("the transport stops");
    backend.force_restart().await.ok();

    assert_eq!(
        backend.sign_in(),
        seeded,
        "stop and restart keep the status"
    );
}

// S6
#[tokio::test]
async fn a_non_oauth_backend_waiting_reads_waiting_elsewhere() {
    let backend = Backend::new(
        "managed",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    );
    backend.shared_entry_for_test().auth_wait.set();

    assert_eq!(backend.sign_in(), SignIn::WaitingElsewhere);
    assert!(backend.needs_sign_in());
    let wire = serde_json::to_value(backend.sign_in()).unwrap();
    assert_eq!(wire["status"], "waiting_elsewhere", "{wire}");
}

// S7: the named residual. A configured OAuth backend nobody has started reads
// `NotYetChecked`, and that raises no sign-in row.
#[tokio::test]
async fn a_never_started_oauth_backend_reads_not_yet_checked() {
    let backend = oauth_backend("dormant");

    assert_eq!(backend.sign_in(), SignIn::NotYetChecked);
    assert!(!backend.needs_sign_in(), "no sign-in row until first use");
}

fn expires_of(status: SignIn) -> Option<u64> {
    match status {
        SignIn::SignedIn { expires_at } => expires_at
            .and_then(|at| at.duration_since(UNIX_EPOCH).ok())
            .map(|since| since.as_secs()),
        other => panic!("expected SignedIn, got {other:?}"),
    }
}

// S8: wall clock, never the Tokio clock: the expiries are seeded in the past.
#[tokio::test]
async fn the_status_follows_refresh_delete_and_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let (issuer, _forms) = token_endpoint(Some("access-b")).await;
    let (client, cell) = publishing(dir.path(), &issuer, true);
    let key = client
        .credential_key()
        .expect("a resolved issuer keys the store");

    let live = token(Some("r1"), FAR_FUTURE);
    seed(&client, &live);
    *client.current_token.write() = Some(live);
    client.publish_sign_in();
    assert_eq!(expires_of(cell.snapshot()), Some(FAR_FUTURE), "seeded");

    let stale = token(Some("r1"), LONG_PAST);
    seed(&client, &stale);
    *client.current_token.write() = Some(stale);
    client.get_token().await.expect("the refresh succeeds");
    let refreshed = expires_of(cell.snapshot()).expect("a refreshed expiry");
    assert!(
        refreshed > LONG_PAST && refreshed < FAR_FUTURE,
        "refresh moved expires_at: {refreshed}"
    );

    client.storage.delete(&key, RESOURCE).expect("delete");
    *client.current_token.write() = None;
    client.publish_sign_in();
    assert_eq!(cell.snapshot(), SignIn::NeverSignedIn, "a delete");

    let spent = token(None, LONG_PAST);
    seed(&client, &spent);
    *client.current_token.write() = Some(spent);
    client.publish_sign_in();
    assert_eq!(
        cell.snapshot(),
        SignIn::Expired,
        "expiry with no refresh token"
    );
}

// L5a: `PendingGrant` exists and is not `Clone`. A `Clone` type makes the
// probe's item ambiguous, so the build fails; a missing type fails it too.
trait AmbiguousIfClone<A> {
    fn probe() {}
}
impl<T> AmbiguousIfClone<()> for T {}
impl<T: Clone> AmbiguousIfClone<u8> for T {}

const _: fn() = || {
    let _ = <super::sign_in::PendingGrant as AmbiguousIfClone<_>>::probe;
};

#[test]
fn the_pending_grant_cannot_be_cloned() {
    // The check is the `const` above, at build time.
}

// L5b: every secret field is `Zeroizing<String>`.
#[test]
fn the_pending_grant_secrets_are_zeroizing() {
    use zeroize::Zeroizing;
    fn wiped(_: &Zeroizing<String>) {}
    fn wiped_opt(_: Option<&Zeroizing<String>>) {}
    let grant = super::sign_in::PendingGrant {
        access_token: Zeroizing::new("a".into()),
        refresh_token: Some(Zeroizing::new("r".into())),
        token_type: None,
        expires_in: None,
        scope: None,
    };
    wiped(&grant.access_token);
    wiped_opt(grant.refresh_token.as_ref());
}
