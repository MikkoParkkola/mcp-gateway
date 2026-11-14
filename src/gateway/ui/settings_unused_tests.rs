// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for listing unused secret entries and deleting one at a time.

use super::super::settings_unused::{
    StoreQuery, delete_no_reload, delete_unused_entry, list_unused, refusal_status,
};
#[cfg(unix)]
use super::test_support::set;
use super::test_support::{BASE, Route, client, decode, secret};
use super::{SettingsStoreForTest, route_secret_tests::recording};
#[cfg(unix)]
use crate::config::{EnvOverlay, FailsafeConfig, LiveEnv, ResolvedEnvFiles};
#[cfg(unix)]
use crate::config_reload::ReloadContext;
#[cfg(unix)]
use crate::gateway::test_helpers::write_owner_only;
#[cfg(unix)]
use crate::gateway::ui::admin_audit::AuditDetail;
use crate::gateway::ui::guard::Guard;
use crate::gateway::{auth::AuthenticatedClient, routes};
use crate::secret_store::DeleteRefused;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{Method, Request, StatusCode};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::{Arc, atomic::Ordering};
#[cfg(unix)]
use std::time::Duration;

const SHAPED: &str = "mcp-gateway.x.1.0123456789abcdef";

/// The access-table guard, from a request that carries the client extension.
fn admitted(method: &Method, path: &'static str, who: AuthenticatedClient) -> Guard {
    let mut request = Request::builder()
        .method(method.clone())
        .uri(path)
        .body(Body::empty())
        .expect("request");
    request.extensions_mut().insert(who);
    let who = request
        .extensions_mut()
        .remove::<AuthenticatedClient>()
        .expect("client extension");
    Guard::for_route(path, request.method(), Some(who))
}

fn secret_file(route: &Route, name: &str) -> PathBuf {
    route.dir.path().join("secrets").join(name)
}

fn entry_name(row: &str, route: &Route) -> String {
    let text =
        std::fs::read_to_string(route.dir.path().join("secrets-index.jsonl")).unwrap_or_default();
    let mut live = Vec::new();
    for line in text.lines() {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(name) = value["name"].as_str() else {
            continue;
        };
        if value
            .get("removed_at")
            .is_some_and(|stamp| !stamp.is_null())
        {
            live.retain(|kept: &String| kept != name);
        } else {
            live.push(name.to_owned());
        }
    }
    assert_eq!(live.len(), 1, "{row} one indexed entry {text}");
    let name = live.remove(0);
    assert!(secret_file(route, &name).is_file(), "{row} stored {name}");
    name
}

async fn named_entry(row: &str, value: &str) -> (Route, String) {
    let route = Route::new(BASE).await;
    let (status, body) = route.save(json!([secret(value)])).await;
    assert_eq!(status, StatusCode::OK, "{row} save {body}");
    let name = entry_name(row, &route);
    assert!(
        route.text().contains(&name),
        "{row} gateway.yaml names the entry"
    );
    (route, name)
}

async fn unnamed_entry(row: &str, value: &str) -> (Route, String) {
    let (route, name) = named_entry(row, value).await;
    route.write(BASE);
    assert!(!route.text().contains(&name), "{row} reference is gone");
    (route, name)
}

async fn list(route: &Route, admin: bool) -> axum::response::Response {
    list_unused(
        State(Arc::clone(&route.state)),
        admitted(&Method::GET, routes::UI_SETTINGS_UNUSED, client(admin)),
    )
    .await
}

async fn delete(route: &Route, name: &str, store: &str, admin: bool) -> axum::response::Response {
    delete_unused_entry(
        State(Arc::clone(&route.state)),
        admitted(
            &Method::DELETE,
            routes::UI_SETTINGS_UNUSED_ENTRY,
            client(admin),
        ),
        Path(name.to_owned()),
        Ok(Query(StoreQuery {
            store: store.to_owned(),
        })),
    )
    .await
}

async fn listed(row: &str, route: &Route) -> Value {
    let response = list(route, true).await;
    assert_eq!(response.status(), StatusCode::OK, "{row} list");
    decode(response).await.1
}

fn not_listed(row: &str, body: &Value, name: &str) {
    let Some(entries) = body["entries"].as_array() else {
        panic!("{row} entries {body}");
    };
    assert!(
        entries
            .iter()
            .all(|entry| entry["name"].as_str() != Some(name)),
        "{row} {name} not listed"
    );
}

fn exactly_one(row: &str, body: &Value, name: &str, value: &str) {
    let entries = body["entries"].as_array().cloned().unwrap_or_default();
    assert_eq!(entries.len(), 1, "{row} exactly one entry {body}");
    let missing = Value::Null;
    let entry = entries.first().unwrap_or(&missing);
    assert_eq!(entry["name"].as_str(), Some(name), "{row} name");
    assert_eq!(entry["store"].as_str(), Some("files"), "{row} store");
    let written = entry["written_at"].as_str().unwrap_or("");
    assert!(
        chrono::DateTime::parse_from_rfc3339(written).is_ok(),
        "{row} written_at {written}"
    );
    assert!(!body.to_string().contains(value), "{row} value absent");
}

fn abandoned(route: &Route) -> PathBuf {
    let mut name = route
        .path()
        .file_name()
        .expect("config name")
        .to_os_string();
    name.push(".abandoned");
    route.path().with_file_name(name)
}

/// A saved secret that gateway.yaml still names is absent from the list.
/// Clearing that reference lists it, with a files store and an RFC 3339 write
/// time, and the secret value is not in the body.
#[tokio::test]
async fn unused_listed_with_write_time() {
    const ROW: &str = "unused_listed_with_write_time";
    const VALUE: &str = "unused-listed-canary";
    let (route, name) = named_entry(ROW, VALUE).await;
    let named = listed(ROW, &route).await;
    not_listed(ROW, &named, &name);
    assert!(
        !named.to_string().contains(VALUE),
        "{ROW} named list has no value"
    );
    route.write(BASE);
    assert!(!route.text().contains(&name), "{ROW} reference is gone");
    let body = listed(ROW, &route).await;
    exactly_one(ROW, &body, &name, VALUE);
}

/// A save whose reload is refused, and whose rollback delete fails too, keeps
/// the entry. The list shows it with its write time.
#[tokio::test]
async fn failed_commit_entry_listed() {
    const ROW: &str = "failed_commit_entry_listed";
    const VALUE: &str = "failed-commit-canary";
    let mut route = Route::with_reload(BASE, true).await;
    let store = recording(&route, None);
    store.fail_delete.store(true, Ordering::SeqCst);
    route.store = Some(SettingsStoreForTest::Store(store.clone()));
    let (status, body) = route.save(json!([secret(VALUE)])).await;
    assert_ne!(status, StatusCode::OK, "{ROW} save refused {body}");
    let name = entry_name(ROW, &route);
    assert!(
        !route.text().contains(&name),
        "{ROW} restored config does not name it"
    );
    let listed = listed(ROW, &route).await;
    exactly_one(ROW, &listed, &name, VALUE);
}

/// Deleting the unnamed files entry removes the file and the list row.
#[cfg(unix)]
#[tokio::test]
async fn delete_route_removes_entry() {
    const ROW: &str = "delete_route_removes_entry";
    const VALUE: &str = "unused-delete-canary";
    let (route, name) = unnamed_entry(ROW, VALUE).await;
    let response = delete(&route, &name, "files", true).await;
    assert_eq!(response.status(), StatusCode::OK, "{ROW} delete");
    let (_, body) = decode(response).await;
    assert_eq!(body["deleted"], json!(name), "{ROW} deleted");
    let listed = listed(ROW, &route).await;
    assert_eq!(listed["entries"], json!([]), "{ROW} list empty");
    assert!(!secret_file(&route, &name).exists(), "{ROW} file gone");
}

/// A listed entry that gateway.yaml names after the listing is not deleted.
/// The file and the list stay.
#[cfg(unix)]
#[tokio::test]
async fn delete_refuses_named_after_listing() {
    const ROW: &str = "delete_refuses_named_after_listing";
    const VALUE: &str = "unused-named-canary";
    let (route, name) = named_entry(ROW, VALUE).await;
    let naming = route.text();
    route.write(BASE);
    let unnamed = listed(ROW, &route).await;
    exactly_one(ROW, &unnamed, &name, VALUE);
    route.write(&naming);
    let before = listed(ROW, &route).await;
    let response = delete(&route, &name, "files", true).await;
    assert_eq!(response.status(), StatusCode::CONFLICT, "{ROW} named");
    assert!(secret_file(&route, &name).is_file(), "{ROW} file remains");
    let after = listed(ROW, &route).await;
    assert_eq!(before, after, "{ROW} list unchanged");
}

/// A journal, then an abandoned file beside the config, each refuse the delete.
#[tokio::test]
async fn delete_route_refuses_pending_write() {
    const ROW: &str = "delete_route_refuses_pending_write";
    const VALUE: &str = "unused-pending-canary";
    let (route, name) = unnamed_entry(ROW, VALUE).await;
    let file = secret_file(&route, &name);
    let journal = crate::config_persistence::journal::journal_path(&route.path());
    std::fs::write(&journal, b"pending").expect("journal");
    let response = delete(&route, &name, "files", true).await;
    assert_eq!(response.status(), StatusCode::CONFLICT, "{ROW} journal");
    assert!(file.is_file(), "{ROW} file remains after journal");
    std::fs::remove_file(&journal).expect("remove journal");
    std::fs::write(abandoned(&route), b"abandoned").expect("abandoned");
    let response = delete(&route, &name, "files", true).await;
    assert_eq!(response.status(), StatusCode::CONFLICT, "{ROW} abandoned");
    assert!(file.is_file(), "{ROW} file remains after abandoned");
}

/// A bad name or a store kind outside files and keychain is 400. gateway.yaml stays.
#[tokio::test]
async fn delete_route_bad_name() {
    const ROW: &str = "delete_route_bad_name";
    let route = Route::new(BASE).await;
    let before = route.text();
    for (name, store) in [
        ("../gateway.yaml", "files"),
        ("a/b", "files"),
        ("mcp-gateway.x.1.qqqq", "files"),
        (SHAPED, "other"),
    ] {
        let response = delete(&route, name, store, true).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{ROW} {name} store={store}"
        );
    }
    assert_eq!(route.text(), before, "{ROW} gateway.yaml unchanged");
}

/// A well-shaped name that was never created is 404.
#[cfg(unix)]
#[tokio::test]
async fn delete_route_unlisted() {
    const ROW: &str = "delete_route_unlisted";
    let route = Route::new(BASE).await;
    let response = delete(&route, SHAPED, "files", true).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND, "{ROW}");
}

/// A non-admin caller is refused on list and delete, and nothing is removed.
#[tokio::test]
async fn routes_need_admin() {
    const ROW: &str = "routes_need_admin";
    const VALUE: &str = "unused-admin-canary";
    let (route, name) = named_entry(ROW, VALUE).await;
    let yaml = route.text();
    let listed = list(&route, false).await;
    assert_eq!(listed.status(), StatusCode::FORBIDDEN, "{ROW} list");
    let (_, body) = decode(listed).await;
    assert_eq!(
        body,
        json!({"error": "Admin authentication required"}),
        "{ROW} list body"
    );
    let removed = delete(&route, &name, "files", false).await;
    assert_eq!(removed.status(), StatusCode::FORBIDDEN, "{ROW} delete");
    let (_, body) = decode(removed).await;
    assert_eq!(
        body,
        json!({"error": "Admin authentication required"}),
        "{ROW} delete body"
    );
    assert!(
        secret_file(&route, &name).is_file(),
        "{ROW} nothing deleted"
    );
    assert_eq!(route.text(), yaml, "{ROW} gateway.yaml unchanged");
}

/// A successful delete's response carries the audit detail: the entry, the
/// files store, and the result. Not the secret value. A listing carries none.
#[cfg(unix)]
#[tokio::test]
async fn delete_is_audited() {
    const ROW: &str = "delete_is_audited";
    const VALUE: &str = "unused-audit-canary";
    let (route, name) = unnamed_entry(ROW, VALUE).await;
    let listing = list(&route, true).await;
    assert_eq!(listing.status(), StatusCode::OK, "{ROW} list");
    assert!(
        listing.extensions().get::<AuditDetail>().is_none(),
        "{ROW} a listing has no audit detail"
    );
    let response = delete(&route, &name, "files", true).await;
    assert_eq!(response.status(), StatusCode::OK, "{ROW} delete");
    let detail = response.extensions().get::<AuditDetail>().cloned();
    assert!(detail.is_some(), "{ROW} audit detail");
    let AuditDetail(map) = detail.unwrap_or_else(|| panic!("{ROW} audit detail"));
    assert_eq!(
        map.get("secret_entry").and_then(Value::as_str),
        Some(name.as_str()),
        "{ROW} entry"
    );
    assert_eq!(
        map.get("store").and_then(Value::as_str),
        Some("files"),
        "{ROW} store"
    );
    let result = map
        .get("result")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    assert!(!result.is_empty(), "{ROW} result");
    assert!(!result.contains(VALUE), "{ROW} result has no value");
    let rendered = serde_json::to_string(&Value::Object(map)).unwrap_or_default();
    assert!(!rendered.is_empty(), "{ROW} detail json");
    assert!(!rendered.contains(VALUE), "{ROW} detail has no value");
    let (_, body) = decode(response).await;
    assert!(!body.to_string().contains(VALUE), "{ROW} body has no value");
}

/// After a Pending and then a Named refusal, a plain settings save still
/// succeeds at once: the reload lock and the config sidecar were released.
/// (`Busy`, `TimedOut` and `Failed` release the vault lock: store rows.)
#[cfg(unix)]
#[tokio::test]
async fn locks_released_after_refusals() {
    const ROW: &str = "locks_released_after_refusals";
    const VALUE: &str = "unused-lock-canary";
    let (route, name) = named_entry(ROW, VALUE).await;
    let journal = crate::config_persistence::journal::journal_path(&route.path());
    std::fs::write(&journal, b"pending").expect("journal");
    let response = delete(&route, &name, "files", true).await;
    assert_eq!(response.status(), StatusCode::CONFLICT, "{ROW} pending");
    std::fs::remove_file(&journal).expect("remove journal");
    let response = delete(&route, &name, "files", true).await;
    assert_eq!(response.status(), StatusCode::CONFLICT, "{ROW} named");
    let (status, body) = route
        .save(json!([set("environment", &json!("prod"))]))
        .await;
    assert_eq!(status, StatusCode::OK, "{ROW} save {body}");
}

/// Each delete refusal answers its one status: 400 a bad shape, 404 not listed,
/// 409 an entry still named, pending or live in the other store, 503 a busy,
/// slow or unreadable store or source.
#[test]
fn refusal_statuses() {
    const ROW: &str = "refusal_statuses";
    for (refused, status) in [
        (DeleteRefused::BadName, StatusCode::BAD_REQUEST),
        (DeleteRefused::NotListed, StatusCode::NOT_FOUND),
        (DeleteRefused::StoreMismatch, StatusCode::CONFLICT),
        (DeleteRefused::Named, StatusCode::CONFLICT),
        (DeleteRefused::Pending, StatusCode::CONFLICT),
        (DeleteRefused::Busy, StatusCode::CONFLICT),
        (DeleteRefused::TimedOut, StatusCode::SERVICE_UNAVAILABLE),
        (
            DeleteRefused::Failed("store-canary".into()),
            StatusCode::SERVICE_UNAVAILABLE,
        ),
    ] {
        assert_eq!(refusal_status(&refused), status, "{ROW}: {refused:?}");
    }
}

/// Only a capability file under a directory the on-disk config lists names the
/// entry: the delete is refused and the file stays.
#[cfg(unix)]
#[tokio::test]
async fn delete_refuses_capability_named() {
    const ROW: &str = "delete_refuses_capability_named";
    const VALUE: &str = "unused-capability-canary";
    let (route, name) = unnamed_entry(ROW, VALUE).await;
    let caps = route.dir.path().join("caps");
    std::fs::create_dir_all(&caps).expect("caps");
    std::fs::write(caps.join("tool.yaml"), format!("auth: keychain:{name}\n")).expect("cap");
    route.write(&format!(
        "{BASE}capabilities:\n  directories:\n    - \"{}\"\n",
        caps.display()
    ));
    assert!(
        !route.text().contains(&name),
        "{ROW} config does not name it"
    );
    let response = delete(&route, &name, "files", true).await;
    assert_eq!(response.status(), StatusCode::CONFLICT, "{ROW} capability");
    assert!(secret_file(&route, &name).is_file(), "{ROW} file remains");
}

/// Only an env file the running gateway was started with names the entry: the
/// delete is refused and the file stays.
#[cfg(unix)]
#[tokio::test]
async fn delete_refuses_env_named() {
    const ROW: &str = "delete_refuses_env_named";
    const VALUE: &str = "unused-env-canary";
    let (route, name) = unnamed_entry(ROW, VALUE).await;
    let env = route.dir.path().join("gateway.env");
    write_owner_only(&env, format!("TOKEN=keychain:{name}\n")).expect("env");
    let live = Arc::new(LiveEnv::new(
        Arc::new(EnvOverlay::none()),
        ResolvedEnvFiles::new(vec![env], false),
    ));
    let ctx = ReloadContext::new(
        route.path(),
        Arc::clone(&route.ctx.live_config),
        Arc::clone(&route.state.backends),
        FailsafeConfig::default(),
        Duration::from_secs(60),
    )
    .expect("context")
    .with_env(live);
    route.state.meta_mcp.set_reload_context(Arc::new(ctx));
    let response = delete(&route, &name, "files", true).await;
    assert_eq!(response.status(), StatusCode::CONFLICT, "{ROW} env file");
    assert!(secret_file(&route, &name).is_file(), "{ROW} file remains");
}

/// Off Unix a files delete is refused before the store is touched: 503, and the file stays.
#[cfg(not(unix))]
#[tokio::test]
async fn delete_route_files_refused_off_unix() {
    const ROW: &str = "delete_route_files_refused_off_unix";
    const VALUE: &str = "unused-off-unix-canary";
    let (route, name) = unnamed_entry(ROW, VALUE).await;
    let response = delete(&route, &name, "files", true).await;
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "{ROW}: delete"
    );
    assert!(secret_file(&route, &name).is_file(), "{ROW}: file remains");
}

/// gateway.yaml is a symlink to a file in another directory, and the entry
/// file has a second name in the route directory. The delete is refused and
/// the entry stays.
#[cfg(unix)]
#[tokio::test]
async fn delete_refuses_hard_linked_entry_behind_symlinked_config() {
    const ROW: &str = "delete_refuses_hard_linked_entry_behind_symlinked_config";
    const VALUE: &str = "unused-link-canary";
    let (route, name) = unnamed_entry(ROW, VALUE).await;
    let elsewhere = tempfile::tempdir().unwrap_or_else(|error| panic!("{ROW}: dir: {error}"));
    let moved = elsewhere.path().join("gateway.yaml");
    write_owner_only(&moved, route.text()).unwrap_or_else(|error| panic!("{ROW}: yaml: {error}"));
    std::fs::remove_file(route.path())
        .unwrap_or_else(|error| panic!("{ROW}: remove config: {error}"));
    std::os::unix::fs::symlink(&moved, route.path())
        .unwrap_or_else(|error| panic!("{ROW}: symlink: {error}"));
    let entry = secret_file(&route, &name);
    std::fs::hard_link(&entry, route.dir.path().join("also"))
        .unwrap_or_else(|error| panic!("{ROW}: hard link: {error}"));
    let response = delete(&route, &name, "files", true).await;
    let (status, body) = decode(response).await;
    assert_eq!(status, StatusCode::CONFLICT, "{ROW}: hard link {body}");
    assert_eq!(body["error"], "named", "{ROW}: refused as named");
    assert!(entry.is_file(), "{ROW}: file remains");
}

/// Where the system keychain can finish a timed-out delete after the route has
/// released its locks, a keychain delete is refused before anything is touched.
#[cfg(any(target_os = "macos", windows))]
#[tokio::test]
async fn delete_route_keychain_refused_here() {
    const ROW: &str = "delete_route_keychain_refused_here";
    let route = Route::new(BASE).await;
    let before = route.text();
    let (status, body) = decode(delete(&route, SHAPED, "keychain", true).await).await;
    assert_eq!(status, StatusCode::CONFLICT, "{ROW}: {body}");
    assert_eq!(body["error"], "keychain_delete_unavailable", "{ROW}");
    assert_eq!(route.text(), before, "{ROW}: gateway.yaml unchanged");
}

/// The delete with no reload context attempted nothing: 409 (the listing, a read,
/// keeps its 503).
#[tokio::test]
async fn delete_without_reload_answers_409() {
    const ROW: &str = "delete_without_reload_answers_409";
    let (status, body) = decode(delete_no_reload()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{ROW}: {body}");
    assert_eq!(
        body,
        json!({"error": "Config reload is not enabled on this gateway"}),
        "{ROW}"
    );
}
