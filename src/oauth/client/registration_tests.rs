// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8195 wave 1: every branch of obtaining and purging a registered
//! client id, against a loopback registration endpoint.

use std::sync::Arc;

use reqwest::Client;

use super::super::{ClientIdSource, OAuthClient, OAuthClientConfig};
use crate::oauth::metadata::AuthorizationServerMetadata;
use crate::oauth::storage::TokenStorage;

const RESOURCE: &str = "https://backend.example.com/mcp";
const REDIRECT: &str = "http://127.0.0.1:9/callback";

/// A registration endpoint on loopback answering every POST with `status`
/// and `body`. Returns its URL.
async fn registration_endpoint(status: u16, body: &'static str) -> String {
    use axum::{Router, http::StatusCode, routing::post};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/register", listener.local_addr().unwrap());
    let app = Router::new().route(
        "/register",
        post(move || async move {
            (
                StatusCode::from_u16(status).unwrap(),
                [("content-type", "application/json")],
                body,
            )
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await });
    url
}

fn metadata(registration: Option<&str>) -> AuthorizationServerMetadata {
    serde_json::from_value(serde_json::json!({
        "issuer": "https://as.example",
        "authorization_endpoint": "https://as.example/authorize",
        "token_endpoint": "https://as.example/token",
        "registration_endpoint": registration,
    }))
    .unwrap()
}

fn registering(
    dir: &std::path::Path,
    registration: Option<&str>,
) -> (OAuthClient, Arc<TokenStorage>) {
    let storage = Arc::new(TokenStorage::new(dir.to_path_buf()).unwrap());
    let mut client = OAuthClient::new(
        Client::new(),
        "reg".to_string(),
        RESOURCE.to_string(),
        vec![],
        Arc::clone(&storage),
        OAuthClientConfig::default(),
    );
    client.auth_metadata = Some(metadata(registration));
    (client, storage)
}

#[tokio::test]
async fn a_registered_client_id_is_persisted_and_marked_registered() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = registration_endpoint(201, r#"{"client_id":"reg-1"}"#).await;
    let (client, storage) = registering(dir.path(), Some(&endpoint));
    let id = client
        .ensure_client_id_with_redirect(REDIRECT)
        .await
        .unwrap();
    assert_eq!(id, "reg-1");
    assert_eq!(
        *client.client_id_source.read(),
        Some(ClientIdSource::Registered)
    );
    let key = client.credential_key().unwrap();
    assert_eq!(
        storage.load_client_id(&key, RESOURCE).as_deref(),
        Some("reg-1")
    );
}

/// A registration that cannot be persisted still serves this session, so the
/// live login proceeds; the failure is logged for the operator.
#[cfg(unix)]
#[tokio::test]
async fn a_registration_that_cannot_be_persisted_still_serves_the_session() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let endpoint = registration_endpoint(201, r#"{"client_id":"reg-2"}"#).await;
    let (client, storage) = registering(dir.path(), Some(&endpoint));
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    let id = client.ensure_client_id_with_redirect(REDIRECT).await;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(id.unwrap(), "reg-2");
    assert_eq!(
        *client.client_id_source.read(),
        Some(ClientIdSource::Registered)
    );
    let key = client.credential_key().unwrap();
    assert_eq!(
        storage.load_client_id(&key, RESOURCE),
        None,
        "nothing was written"
    );
}

#[tokio::test]
async fn a_failed_registration_falls_back_to_a_generated_id() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = registration_endpoint(500, r#"{"error":"server_error"}"#).await;
    let (client, _storage) = registering(dir.path(), Some(&endpoint));
    let id = client
        .ensure_client_id_with_redirect(REDIRECT)
        .await
        .unwrap();
    assert!(!id.is_empty() && id != "reg-1", "a generated id: {id}");
    assert_eq!(client.client_id.read().as_deref(), Some(id.as_str()));
    assert_eq!(
        *client.client_id_source.read(),
        Some(ClientIdSource::Registered)
    );
}

/// A cleartext registration endpoint off this machine is the destination
/// policy's refusal: it is returned, never walked past to a generated id.
#[tokio::test]
async fn a_refused_registration_destination_is_not_walked_past() {
    let dir = tempfile::tempdir().unwrap();
    let (client, _storage) = registering(dir.path(), Some("http://as.example/register"));
    let refused = client.ensure_client_id_with_redirect(REDIRECT).await;
    assert!(refused.is_err(), "the refusal is returned: {refused:?}");
    assert!(client.client_id.read().is_none(), "no id was adopted");
}

#[tokio::test]
async fn without_a_registration_endpoint_an_id_is_generated() {
    let dir = tempfile::tempdir().unwrap();
    let (client, _storage) = registering(dir.path(), None);
    let id = client
        .ensure_client_id_with_redirect(REDIRECT)
        .await
        .unwrap();
    assert_eq!(client.client_id.read().as_deref(), Some(id.as_str()));
}

#[tokio::test]
async fn without_discovered_metadata_there_is_no_client_id() {
    let dir = tempfile::tempdir().unwrap();
    let (mut client, _storage) = registering(dir.path(), None);
    client.auth_metadata = None;
    assert!(
        client
            .ensure_client_id_with_redirect(REDIRECT)
            .await
            .is_err()
    );
}

/// A registered id the server rejects is purged from memory even when its
/// file cannot be deleted, or cannot be located without a discovered issuer.
#[test]
fn a_purge_that_cannot_delete_or_locate_the_file_still_drops_the_id() {
    let dir = tempfile::tempdir().unwrap();
    let (client, storage) = registering(dir.path(), None);
    let key = client.credential_key().unwrap();
    std::fs::create_dir_all(storage.client_path(&key, RESOURCE)).unwrap();
    *client.client_id.write() = Some("stale".to_string());
    *client.client_id_source.write() = Some(ClientIdSource::Registered);
    client.purge_client_id_if_invalid(r#"{"error":"invalid_client"}"#);
    assert!(
        client.client_id.read().is_none(),
        "dropped although the delete failed"
    );

    let (mut unlocated, _storage) = registering(dir.path(), None);
    unlocated.auth_metadata = None;
    *unlocated.client_id.write() = Some("stale".to_string());
    *unlocated.client_id_source.write() = Some(ClientIdSource::Registered);
    unlocated.purge_client_id_if_invalid(r#"{"error":"invalid_client"}"#);
    assert!(
        unlocated.client_id.read().is_none(),
        "dropped without an issuer"
    );
}

/// A 2xx registration answer that is not a registration response is an OAuth
/// parse error, not an id.
#[tokio::test]
async fn an_unparseable_registration_answer_is_an_oauth_error() {
    let dir = tempfile::tempdir().unwrap();
    let endpoint = registration_endpoint(201, r#"{"no_client_id":true}"#).await;
    let (client, _storage) = registering(dir.path(), Some(&endpoint));

    let refused = client.register_client(&endpoint, REDIRECT).await;

    assert!(
        matches!(refused, Err(crate::Error::OAuth(ref m)) if m.starts_with("Failed to parse registration response")),
        "{refused:?}"
    );
}

/// A successful registration returns the issued id and logs it.
#[test]
fn a_successful_registration_logs_the_issued_id() {
    let dir = tempfile::tempdir().unwrap();
    let mut id = None;
    let records = crate::test_log_capture::records(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        id = Some(runtime.block_on(async {
            let endpoint = registration_endpoint(201, r#"{"client_id":"reg-logged"}"#).await;
            let (client, _storage) = registering(dir.path(), Some(&endpoint));
            client.register_client(&endpoint, REDIRECT).await
        }));
    });

    assert_eq!(id.unwrap().unwrap(), "reg-logged");
    let logged: Vec<_> = records
        .iter()
        .filter(|r| r["fields"]["message"] == "Registered OAuth client")
        .collect();
    let [one] = logged.as_slice() else {
        panic!("one registration record: {records:?}");
    };
    assert_eq!(one["fields"]["client_id"], "reg-logged");
}

/// MIK-8344: a registration that meets a corrupt stored id while another
/// process holds the repair lock stays cancellable. The lock wait used to be a
/// blocking `flock` on the async path: it pinned a runtime thread, and the
/// login's cancel (a restart, a stop) could not end it until the holder let go.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancel_ends_a_registration_waiting_on_a_held_repair_lock() {
    use tokio_util::sync::CancellationToken;
    let dir = tempfile::tempdir().unwrap();
    let endpoint = registration_endpoint(201, r#"{"client_id":"reg-held"}"#).await;
    let (client, storage) = registering(dir.path(), Some(&endpoint));
    let key = client.credential_key().unwrap();
    let final_path = storage.client_path(&key, RESOURCE);
    std::fs::write(&final_path, "not json").unwrap();
    let stem = final_path.file_stem().unwrap().to_str().unwrap();
    let lock_path = final_path.with_file_name(format!(".{stem}.lock"));
    let held = crate::fs_lock::ExclusiveFileLock::acquire(&lock_path).unwrap();
    // The counter includes the hold just taken: wait for registration's own.
    let held_attempts = crate::fs_lock::lock_attempts(&lock_path);

    let cancel = CancellationToken::new();
    let registration = tokio::spawn({
        let cancel = cancel.clone();
        async move {
            tokio::select! {
                biased;
                () = cancel.cancelled() => None,
                id = client.ensure_client_id_with_redirect(REDIRECT) => Some(id),
            }
        }
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while crate::fs_lock::lock_attempts(&lock_path) == held_attempts {
        assert!(
            std::time::Instant::now() < deadline,
            "registration never reached the repair lock"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    cancel.cancel();
    let ended = tokio::time::timeout(std::time::Duration::from_secs(20), registration).await;
    drop(held);
    let ended = ended.expect("registration ignored cancel while the repair lock was held");
    assert!(matches!(ended, Ok(None)), "the cancel ended it: {ended:?}");
    assert_eq!(
        std::fs::read_to_string(&final_path).unwrap(),
        "not json",
        "a cancelled repair leaves the final as it was"
    );
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|name| name.contains(".tmp."))
        .collect();
    assert!(
        leftovers.is_empty(),
        "a cancelled save left temp files: {leftovers:?}"
    );
}
