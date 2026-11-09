// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Secret, stale, no-op and removal route rows.
use super::{SettingsStoreForTest, test_support::*};
use crate::secret_store::{FilesStore, SecretStore, StoreError, StoreKind};
use axum::http::StatusCode;
use serde_json::json;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Clone, Default)]
struct LogSink(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log sink").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Capture the calling thread, runtime workers and blocking pool for the whole save.
fn capture_runtime<T>(run: impl std::future::Future<Output = T>) -> (T, String) {
    crate::test_log_capture::keep_interest_open();
    let sink = LogSink::default();
    let writer = sink.clone();
    let capture = tracing::Dispatch::new(
        tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish(),
    );
    let on_start = capture.clone();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .on_thread_start(move || std::mem::forget(tracing::dispatcher::set_default(&on_start)))
        .build()
        .expect("runtime");
    let result = tracing::dispatcher::with_default(&capture, || {
        runtime.block_on(async {
            let caller = std::thread::current().id();
            tokio::spawn(async move {
                assert_ne!(std::thread::current().id(), caller);
                tracing::trace!("capture worker control");
            })
            .await
            .expect("worker control");
            tokio::task::spawn_blocking(move || {
                assert_ne!(std::thread::current().id(), caller);
                tracing::trace!("capture blocking control");
            })
            .await
            .expect("blocking control");
            run.await
        })
    });
    runtime.shutdown_timeout(std::time::Duration::from_secs(5));
    let logs = String::from_utf8(sink.0.lock().expect("log sink").clone()).expect("UTF-8 logs");
    assert!(
        logs.contains("capture worker control"),
        "worker capture missing"
    );
    assert!(
        logs.contains("capture blocking control"),
        "blocking capture missing"
    );
    (result, logs)
}

pub(super) struct Recording {
    inner: FilesStore,
    calls: AtomicUsize,
    creates: AtomicUsize,
    values: Mutex<Vec<(String, Vec<u8>)>>,
    fail: Option<bool>,
}
impl Recording {
    pub(super) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}
impl SecretStore for Recording {
    fn kind(&self) -> StoreKind {
        self.inner.kind()
    }
    fn limit(&self) -> usize {
        self.inner.limit()
    }
    fn probe(&self) -> Result<(), StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.probe()
    }
    fn exists(&self, name: &str) -> Result<bool, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.exists(name)
    }
    fn create(&self, name: &str, value: &[u8]) -> Result<String, StoreError> {
        self.creates.fetch_add(1, Ordering::SeqCst);
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(operational) = self.fail {
            return Err(if operational {
                StoreError::Failed("store-error-canary".into())
            } else {
                StoreError::Unavailable("store-error-canary".into())
            });
        }
        let reference = self.inner.create(name, value)?;
        self.values
            .lock()
            .expect("values")
            .push((reference.clone(), value.to_vec()));
        Ok(reference)
    }
    fn delete(&self, name: &str) -> Result<(), StoreError> {
        self.inner.delete(name)
    }
}
pub(super) fn recording(route: &Route, fail: Option<bool>) -> Arc<Recording> {
    Arc::new(Recording {
        inner: FilesStore::new(route.dir.path()),
        calls: AtomicUsize::new(0),
        creates: AtomicUsize::new(0),
        values: Mutex::new(Vec::new()),
        fail,
    })
}

/// S18: red oracle is a successful reload, stored bytes, a file reference, and no response/log leak.
#[test]
fn s18_secret_save() {
    let ((route, store, result), logs) = capture_runtime(async {
        let mut route = Route::new(BASE).await;
        let store = recording(&route, None);
        route.store = Some(SettingsStoreForTest::Store(store.clone()));
        let result = async {
            let request = route.saved_body(&json!([secret("secret-save-canary")]));
            let response = route
                .response(true, &request.to_string(), client(true))
                .await;
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .expect("body");
            assert!(
                !bytes
                    .windows(b"secret-save-canary".len())
                    .any(|window| window == b"secret-save-canary")
            );
            let body: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON answer");
            (status, body)
        }
        .await;
        (route, store, result)
    });
    let (status, body) = result;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["revision"], route.revision());
    assert_eq!(body["changed"], true);
    assert_eq!(body["comments"], "kept");
    assert!(body["reload"]["changes"].is_string());
    assert!(
        body["reload"]["pending_restart_fields"]
            .as_array()
            .expect("pending restart fields")
            .contains(&json!("auth"))
    );
    assert_eq!(body["restart_required"], json!(["auth.bearer_token"]));
    let values = store.values.lock().expect("values");
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].1, b"secret-save-canary");
    let stored_path = values[0].0.strip_prefix("file:").expect("files reference");
    // The files store pads one `\n`, which the `file:` reader drops, so the
    // value reads back byte for byte (src/secret_store/files.rs).
    assert_eq!(
        std::fs::read(stored_path).expect("stored bytes"),
        b"secret-save-canary\n"
    );
    let written = crate::config::Config::load_literal(Some(&route.path())).expect("written config");
    assert_eq!(written.auth.bearer_token.as_ref(), Some(&values[0].0));
    // The reload names the changed secret input by its store reference, never
    // by the secret itself.
    let pending = body["reload"]["pending_restart_fields"]
        .as_array()
        .expect("pending restart fields");
    assert!(pending.contains(&json!(values[0].0)), "{pending:?}");
    assert!(
        pending
            .iter()
            .all(|p| !p.to_string().contains("secret-save-canary")),
        "{pending:?}"
    );
    assert!(!route.text().contains("secret-save-canary"));
    assert!(!body.to_string().contains("secret-save-canary"));
    assert!(!logs.contains("secret-save-canary"));
}

/// S19: red oracle is an unprovable patch with `set_secret` and no value, before any create.
#[tokio::test]
async fn s19_secret_patch() {
    let text = BASE.replace("environment: \"dev\"", "environment: &env \"dev\"");
    let mut route = Route::new(&text).await;
    let store = recording(&route, None);
    route.store = Some(SettingsStoreForTest::Store(store.clone()));
    let body = refused(
        route
            .save(json!([
                set("environment", &json!("prod")),
                secret("patch-secret-canary")
            ]))
            .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "not_in_place",
    );
    assert_eq!(
        body["patch"],
        json!([
            {"op":"set","path":"environment","value":"\"prod\"","code":"anchor","reason":"the value has an anchor, a tag or an alias"},
            {"op":"set_secret","path":"auth.bearer_token","code":"anchor","reason":"the value has an anchor, a tag or an alias"}
        ])
    );
    assert!(!body.to_string().contains("patch-secret-canary"));
    assert!(store.values.lock().expect("values").is_empty());
    assert_eq!(route.text(), text);
    assert_eq!(store.creates.load(Ordering::SeqCst), 0);
}

/// S20: red oracle is a fresh masked stale preview with zero secret creations.
#[tokio::test]
async fn s20_stale_secret() {
    let mut route = Route::new(BASE).await;
    let store = recording(&route, None);
    route.store = Some(SettingsStoreForTest::Store(store.clone()));
    let body = route.saved_body(&json!([secret("stale-secret-canary")]));
    let outside = BASE.replace("\"dev\"", "\"outside\"");
    route.write(&outside);
    let body = refused(
        route.raw(true, &body.to_string(), client(true)).await,
        StatusCode::CONFLICT,
        "stale",
    );
    assert_eq!(body["current"], route.revision());
    assert!(
        body["diff"]
            .as_str()
            .expect("fresh diff")
            .contains("<new secret>")
    );
    assert!(!body.to_string().contains("stale-secret-canary"));
    assert!(store.values.lock().expect("values").is_empty());
    assert_eq!(route.text(), outside);
    assert_eq!(store.creates.load(Ordering::SeqCst), 0);
}

/// S21: red oracle is changed:false while the reload publishes an unreloaded outside owner edit.
#[tokio::test]
async fn s21_noop_reloads_outside_edit() {
    let route = Route::new(BASE).await;
    let outside = BASE.replace("owner: \"team\"", "owner: \"outside\"");
    route.write(&outside);
    let (status, body) = route.save(json!([set("environment", &json!("dev"))])).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"revision":route.revision(), "changed":false,
        "reload":{"changes":"owner changed: [a]", "restart_required":false},
        "restart_required":[],"comments":"kept"})
    );
    assert_eq!(
        route.ctx.live_config.get().backends["a"].owner.as_deref(),
        Some("outside")
    );
    assert_eq!(route.text(), outside);
}

/// S22: red oracle is no restart field for saving its current running value.
#[tokio::test]
async fn s22_unchanged_restart_field() {
    let route = Route::new(BASE).await;
    let (status, body) = route
        .save(json!([set("auth.enabled", &json!(false))]))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["changed"], false);
    assert_eq!(body["revision"], route.revision());
    assert_eq!(body["restart_required"], json!([]));
    assert_eq!(body["reload"]["restart_required"], false);
    assert_eq!(route.text(), BASE);
}

/// S23: red oracle is no pending restart after reverting a published Restart field to its running value.
#[tokio::test]
async fn s23_reverted_restart_field() {
    let mut route = Route::new(BASE).await;
    route.audit();
    route.write(&BASE.replace("enabled: false", "enabled: true"));
    let reload = route
        .ctx
        .reload_outcome()
        .await
        .expect("publish pending auth");
    assert!(reload.pending_restart_fields.iter().any(|id| id == "auth"));
    let (status, body) = route
        .save(json!([set("auth.enabled", &json!(false))]))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["changed"], true);
    assert_eq!(body["restart_required"], json!([]));
    assert_eq!(body["reload"]["restart_required"], false);
    assert_eq!(route.text(), BASE);
}

/// S24: red oracle is a successful explicit owner removal changing only its line.
#[tokio::test]
async fn s24_remove_owner() {
    let route = Route::new(BASE).await;
    let (status, body) = route
        .save(json!([{"field":"backends.owner","backend":"a","value":{"remove":true}}]))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(route.text(), BASE.replace("    owner: \"team\"\n", ""));
    assert_eq!(body["revision"], route.revision());
    assert_eq!(body["changed"], true);
    assert_eq!(body["comments"], "kept");
}

/// S25: red oracle is 200 when the required backend parameter names a plain key.
#[tokio::test]
async fn s25_backend_present() {
    let route = Route::new(BASE).await;
    let (status, body) = route
        .save(json!([{"field":"backends.owner","backend":"a","value":{"set":"new-team"}}]))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        route.text(),
        BASE.replace("owner: \"team\"", "owner: \"new-team\"")
    );
}

/// S25: red oracle is fixed `bad_param` when backend is absent.
#[tokio::test]
async fn s25_backend_missing() {
    let route = Route::new(BASE).await;
    let body = refused(
        route
            .save(json!([set("backends.owner", &json!("new-team"))]))
            .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "bad_param",
    );
    assert_eq!(body["field"], "backends.owner");
    assert_eq!(body["reason"], "needs a backend");
    assert_eq!(route.text(), BASE);
}

/// S25: red oracle is a `not_plain_key` patch for an existing quoted backend key.
#[tokio::test]
async fn s25_backend_nonplain() {
    let text = BASE.replace("  a:\n", "  \"a\":\n");
    let route = Route::new(&text).await;
    let body = refused(
        route
            .save(json!([{"field":"backends.owner","backend":"a","value":{"set":"new-team"}}]))
            .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "not_in_place",
    );
    assert_eq!(
        body["patch"],
        json!([{"op":"set","path":"backends.a.owner","value":"\"new-team\"",
        "code":"not_plain_key","reason":"a key on the path is not a plain key"}])
    );
    assert_eq!(route.text(), text);
}

fn assert_config_preview(case: &str, body: &serde_json::Value, config_mark: &str) {
    let mut reasons = body.clone();
    if case == "stale" {
        assert!(
            reasons["diff"]
                .as_str()
                .expect("preview")
                .contains(config_mark)
        );
        reasons.as_object_mut().expect("object").remove("diff");
    }
    if case == "unprovable" {
        let patch = reasons["patch"].as_array_mut().expect("patch");
        assert!(patch.iter().any(|step| {
            step["op"] == "set"
                && step["value"]
                    .as_str()
                    .is_some_and(|v| v.contains(config_mark))
        }));
        for step in patch {
            if step["op"] == "set" {
                step.as_object_mut().expect("step").remove("value");
            }
        }
    }
    assert!(
        !reasons.to_string().contains(config_mark),
        "config value outside preview"
    );
}

// Each canary case is a separate test so a stub cannot hide later cases.
fn canary_case(case: &str) {
    let ((route, store, before, result, secret_mark, backend_mark, id_mark, config_mark), logs) =
        capture_runtime(async {
            use rand::RngExt as _;
            let nonce: u64 = rand::rng().random();
            let secret_mark = format!("secret-{nonce:x}");
            let backend_mark = format!("backend-{nonce:x}");
            let id_mark = format!("unknown-{nonce:x}");
            let config_mark = format!("config-{nonce:x}");
            let text = if case == "unprovable" {
                BASE.replace("environment: \"dev\"", "environment: &env \"dev\"")
            } else {
                BASE.into()
            };
            let mut route = Route::new(&text).await;
            let store = recording(&route, if case == "store" { Some(false) } else { None });
            route.store = Some(SettingsStoreForTest::Store(store.clone()));
            let fields = match case {
                "bad_param" => {
                    json!([{"field":"backends.owner","backend":backend_mark,"value":{"set":config_mark}}])
                }
                "unknown" => json!([set(&id_mark, &json!(config_mark))]),
                _ => json!([
                    set("environment", &json!(config_mark)),
                    secret(&secret_mark)
                ]),
            };
            let mut body = route.saved_body(&fields);
            if case == "stale" {
                route.write(&text.replace("\"dev\"", "\"outside\""));
            }
            if case == "posture" {
                route.write(&format!(
                    "{text}server:\n  public_url: https://{config_mark}.example.test\n"
                ));
                body["base_revision"] = json!(route.revision());
            }
            if case == "invalid" {
                route.write(&format!("{text}server:\n  port: {config_mark}\n"));
                body["base_revision"] = json!(route.revision());
            }
            let before = route.text();
            let result = route.raw(true, &body.to_string(), client(true)).await;
            (
                route,
                store,
                before,
                result,
                secret_mark,
                backend_mark,
                id_mark,
                config_mark,
            )
        });
    let (status, code) = match case {
        "stale" => (StatusCode::CONFLICT, "stale"),
        "posture" => (StatusCode::CONFLICT, "posture_refused"),
        "unprovable" => (StatusCode::UNPROCESSABLE_ENTITY, "not_in_place"),
        "bad_param" => (StatusCode::UNPROCESSABLE_ENTITY, "bad_param"),
        "unknown" => (StatusCode::UNPROCESSABLE_ENTITY, "unknown_field"),
        "invalid" => (StatusCode::UNPROCESSABLE_ENTITY, "invalid"),
        "store" => (StatusCode::UNPROCESSABLE_ENTITY, ""),
        _ => unreachable!("test case"),
    };
    let body = if case == "store" {
        assert_eq!(result.0, status, "{}", result.1);
        assert_eq!(
            result.1,
            json!({"error": "the secret store refused the value"})
        );
        result.1
    } else {
        refused(result, status, code)
    };
    assert_eq!(route.text(), before);
    for marker in [
        &secret_mark,
        &backend_mark,
        &id_mark,
        &"store-error-canary".to_owned(),
    ] {
        assert!(
            !body.to_string().contains(marker),
            "private marker in {body}"
        );
        assert!(!logs.contains(marker), "private marker in logs");
    }
    assert!(!logs.contains(&config_mark), "config value logged");
    assert_config_preview(case, &body, &config_mark);
    assert!(store.values.lock().expect("values").is_empty());
}

/// S26: red oracle is invalid without leaking any canary through body or logs.
#[test]
fn s26_invalid() {
    canary_case("invalid");
}
/// S26: red oracle is `posture_refused` without exposing the publication value.
#[test]
fn s26_posture() {
    canary_case("posture");
}
/// S26: red oracle allows the non-secret canary only in the fresh stale diff.
#[test]
fn s26_stale() {
    canary_case("stale");
}
/// S26: red oracle allows the non-secret canary only in a patch set value.
#[test]
fn s26_unprovable() {
    canary_case("unprovable");
}
/// S26: red oracle is `bad_param` without the backend-name marker.
#[test]
fn s26_bad_param() {
    canary_case("bad_param");
}
/// S26: red oracle is `unknown_field` without the submitted id marker.
#[test]
fn s26_unknown() {
    canary_case("unknown");
}
/// S26: red oracle is a store refusal with no store detail, secret, or config marker.
#[test]
fn s26_store() {
    canary_case("store");
}

/// S27: red oracle is `invalid_body` after an escaped secret was accepted and a later member fails.
#[tokio::test]
async fn s27_escaped_then_malformed() {
    let mut route = Route::new(BASE).await;
    let store = recording(&route, None);
    route.store = Some(SettingsStoreForTest::Store(store.clone()));
    let body = format!(
        r#"{{"base_revision":"{}","fields":[{{"field":"auth.bearer_token","value":{{"secret":"escaped-\u0063anary"}}}},{{"field":"environment","value":{{"set": "broken"}} "missing-comma":true}}]}}"#,
        route.revision()
    );
    let wipes = crate::wiped_bytes::wipes_for_test();
    assert_eq!(
        refused(
            route.raw(true, &body, client(true)).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_body"
        ),
        json!({"error":"invalid_body"})
    );
    assert_eq!(store.calls(), 0);
    assert_eq!(route.text(), BASE);
    assert_eq!(
        crate::wiped_bytes::wipes_for_test(),
        wipes + 1,
        "accepted secret wiped on parse rejection"
    );
}

/// S27: red oracle is `invalid_body` for duplicate secret members, with no store access.
#[tokio::test]
async fn s27_duplicate_secret() {
    let mut route = Route::new(BASE).await;
    let store = recording(&route, None);
    route.store = Some(SettingsStoreForTest::Store(store.clone()));
    let body = format!(
        r#"{{"base_revision":"{}","fields":[{{"field":"auth.bearer_token","value":{{"secret":"first-canary","secret":"second-canary"}}}}]}}"#,
        route.revision()
    );
    let wipes = crate::wiped_bytes::wipes_for_test();
    assert_eq!(
        refused(
            route.raw(true, &body, client(true)).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_body"
        ),
        json!({"error":"invalid_body"})
    );
    assert_eq!(store.calls(), 0);
    assert_eq!(route.text(), BASE);
    assert_eq!(
        crate::wiped_bytes::wipes_for_test(),
        wipes + 1,
        "accepted secret wiped on parse rejection"
    );
}

/// S28: red oracle is 500 failed when an opened store's create fails, with no file change.
#[tokio::test]
async fn s28_create_failure() {
    let mut route = Route::new(BASE).await;
    let store = recording(&route, Some(true));
    route.store = Some(SettingsStoreForTest::Store(store.clone()));
    let body = refused(
        route.save(json!([secret("create-secret-canary")])).await,
        StatusCode::INTERNAL_SERVER_ERROR,
        "failed",
    );
    assert_eq!(
        body,
        json!({"error":"failed", "message":"the save did not complete; gateway.yaml may have changed, so preview it again before retrying"})
    );
    assert_eq!(store.creates.load(Ordering::SeqCst), 1);
    assert!(store.values.lock().expect("values").is_empty());
    assert_eq!(route.text(), BASE);
}
