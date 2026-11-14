// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! gateway.yaml deleted while an adopt stores its secret: the answer is the
//! shared 409, every entry made is discarded, and the audit log holds the
//! adopt's intent followed by the request's own record of the 409.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::gateway::test_helpers::ConfigFiles;
use crate::secret_store::{FilesStore, SecretStore, StoreKind};

/// A files store that counts creates and deletes, and on its first create
/// deletes `config`.
struct Deleting {
    inner: FilesStore,
    config: std::path::PathBuf,
    creates: Arc<AtomicUsize>,
    deletes: Arc<AtomicUsize>,
}

impl SecretStore for Deleting {
    fn kind(&self) -> StoreKind {
        self.inner.kind()
    }
    fn limit(&self) -> usize {
        self.inner.limit()
    }
    fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe()
    }
    fn exists(&self, name: &str) -> Result<bool, StoreError> {
        self.inner.exists(name)
    }
    fn create(&self, name: &str, value: &[u8]) -> Result<String, StoreError> {
        if self.creates.fetch_add(1, Ordering::SeqCst) == 0 {
            assert!(self.config.exists(), "premise: gateway.yaml is there");
            std::fs::remove_file(&self.config).expect("delete during the fill");
        }
        self.inner.create(name, value)
    }
    fn delete(&self, name: &str) -> Result<(), StoreError> {
        self.deletes.fetch_add(1, Ordering::SeqCst);
        self.inner.delete(name)
    }
}

/// An audit log in a directory of its own that the log keeps.
fn audit_log() -> Arc<crate::security::TransparencyLogger> {
    let dir = crate::test_dir_keep::kept_tempdir();
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::transparency_log::TransparencyLogConfig {
                enabled: true,
                path: dir
                    .path()
                    .join("audit.jsonl")
                    .to_string_lossy()
                    .into_owned(),
                key_id: "adopt-deleted".to_string(),
                ..Default::default()
            },
        ))
        .expect("open log"),
    );
    log.keep_test_dir(dir);
    log
}

#[tokio::test]
async fn a_config_deleted_while_the_adopt_stores_a_value_answers_no_config_file() {
    use tower::ServiceExt as _;
    let mut route = Route::new(
        EMPTY,
        vec![stdio("tool", "npx tool", &[("API_KEY", CANARY)])],
    )
    .await;
    let log = audit_log();
    Arc::get_mut(&mut route.state)
        .expect("state is unique")
        .transparency_log = Some(Arc::clone(&log));
    let (id, revision) = route.listed("tool").await;
    let (creates, deletes) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let store: Store = Arc::new(Deleting {
        inner: FilesStore::new(route.dir.path()),
        config: route.config(),
        creates: Arc::clone(&creates),
        deletes: Arc::clone(&deletes),
    });
    let router = crate::gateway::ui::admin_audit::behind_admin_layer_for_test(
        super::super::super::discovery_router_with(Arc::clone(&route.cache)),
        &route.state,
    )
    .with_state(Arc::clone(&route.state));
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(crate::gateway::routes::UI_DISCOVERY_ADOPT)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::json!({"find_id": id, "revision": revision}).to_string(),
        ))
        .expect("a request");
    request.extensions_mut().insert(client(true));
    request
        .extensions_mut()
        .insert(super::super::AdoptStoreForTest(store));

    let response = router.oneshot(request).await.expect("a response");
    let status = response.status();
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1 << 16).await.expect("body"))
            .unwrap_or(Value::Null);

    assert_eq!(
        (status, &body["error"]),
        (StatusCode::CONFLICT, &Value::from("no_config_file")),
        "{body}"
    );
    assert_eq!(
        (
            creates.load(Ordering::SeqCst),
            deletes.load(Ordering::SeqCst)
        ),
        (1, 1),
        "(creates, deletes): one entry made, then discarded"
    );
    ConfigFiles::assert_absent(&route.config(), "the adopt on a deleted config");
    let records: Vec<Value> = std::fs::read_to_string(log.path())
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| {
            matches!(
                entry["event"].as_str(),
                Some("config_adopt_intent" | "admin_action")
            )
        })
        .collect();
    let events: Vec<_> = records.iter().map(|r| r["event"].clone()).collect();
    assert_eq!(
        events,
        [
            Value::from("config_adopt_intent"),
            Value::from("admin_action")
        ],
        "the intent, then the request's own record: {records:#?}"
    );
    let record = &records[1];
    assert_eq!(
        record["route"],
        crate::gateway::routes::UI_DISCOVERY_ADOPT,
        "{record}"
    );
    assert_eq!(record["http_status"], 409, "{record}");
    assert_eq!(record["outcome"], "error", "{record}");
    assert!(
        !log_text(&log).contains(CANARY),
        "the value reached the audit log"
    );
}

fn log_text(log: &crate::security::TransparencyLogger) -> String {
    std::fs::read_to_string(log.path()).unwrap_or_default()
}

/// The store seam exists only in test builds: every line of the adopt route
/// that names it sits under `#[cfg(test)]`.
#[test]
fn the_adopt_store_seam_is_absent_from_non_test_builds() {
    let source = include_str!("discovery_adopt.rs");
    let lines: Vec<&str> = source.lines().collect();
    let mut seen = 0;
    for (n, line) in lines.iter().enumerate() {
        if !line.contains("AdoptStoreForTest") || line.trim_start().starts_with("//") {
            continue;
        }
        seen += 1;
        let gated = line.contains("#[cfg(test)]")
            || lines[..n]
                .iter()
                .rev()
                .take(4)
                .any(|l| l.trim() == "#[cfg(test)]");
        assert!(gated, "line {}: the seam outside cfg(test): {line}", n + 1);
    }
    assert!(seen >= 3, "premise: the seam is named ({seen} sites)");
}
