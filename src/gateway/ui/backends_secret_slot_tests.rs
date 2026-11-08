// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The panel's backend add and update store each literal env or header value
//! in the secret store and write only its reference to gateway.yaml; a
//! literal beside a template is refused by field, never shown; a refused
//! save opens no store and leaves no entry.

use std::sync::Arc;
use std::time::Duration;

use axum::body::to_bytes;
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::{Value, json};

use super::slotting::BackendStoreForTest;
use super::*;
use crate::config::{AuthConfig, Config, FailsafeConfig};
use crate::config_reload::{LiveConfig, ReloadContext};
use crate::gateway::test_helpers::write_owner_only;
use crate::secret_store::{FilesStore, SecretStore, StoreError, StoreKind};

/// A config whose secrets go to the files store beside it, with backend `a`.
const START: &str = "secrets:\n  store: files\nbackends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n    env:\n      PLAIN: old-plain-value\n";

/// A distinctive secret: its bytes must appear nowhere in gateway.yaml or in
/// any answer. Quote, backslash and newline-free so a raw search is exact.
const TOKEN: &str = "sk-panel-canary-7f3a9c";

struct Panel {
    dir: Arc<tempfile::TempDir>,
    _store: crate::gateway::router::tests::FixtureDir,
    state: Arc<AppState>,
}

/// Whether the fixture's reloads accept the new bytes.
#[derive(Clone, Copy)]
enum Reloads {
    Accept,
    Refuse,
}

impl Panel {
    async fn new() -> Self {
        Self::with(START, Reloads::Accept).await
    }

    async fn with(text: &str, reloads: Reloads) -> Self {
        let dir = Arc::new(tempfile::tempdir().expect("dir"));
        let path = dir.path().join("gateway.yaml");
        write_owner_only(&path, text).expect("write config");
        let (mut state, store) = crate::gateway::router::tests::audience_state(
            &AuthConfig::default(),
            (None, None),
            |m| m,
        )
        .await;
        Arc::get_mut(&mut state)
            .expect("state is unique")
            .config_path = Some(path.clone());
        let running = Config::load(Some(&path)).expect("config loads");
        let ctx = ReloadContext::new(
            path,
            Arc::new(LiveConfig::new(running)),
            Arc::clone(&state.backends),
            FailsafeConfig::default(),
            Duration::from_secs(60),
        )
        .expect("the registry pairs with the config");
        let ctx = Arc::new(match reloads {
            Reloads::Accept => ctx,
            Reloads::Refuse => ctx.refusing_reloads_for_test(),
        });
        state.meta_mcp.set_reload_context(ctx);
        Self {
            dir,
            _store: store,
            state,
        }
    }

    fn path(&self) -> std::path::PathBuf {
        self.dir.path().join("gateway.yaml")
    }

    fn text(&self) -> String {
        std::fs::read_to_string(self.path()).expect("config reads")
    }

    /// The files store's entries, by file name.
    fn entries(&self) -> Vec<String> {
        let Ok(dir) = std::fs::read_dir(self.dir.path().join("secrets")) else {
            return Vec::new();
        };
        let mut names: Vec<String> = dir
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !n.starts_with('.'))
            .collect();
        names.sort();
        names
    }

    fn guard(route: &str, method: &axum::http::Method) -> Guard {
        Guard::for_route(route, method, Some(admin()))
    }

    async fn add(&self, body: Value) -> (StatusCode, Value) {
        self.add_seamed(body, None).await
    }

    async fn add_into(
        &self,
        body: Value,
        store: Option<Arc<dyn SecretStore + Send + Sync>>,
    ) -> (StatusCode, Value) {
        let seam = BackendStoreForTest {
            store,
            after_precheck: None,
        };
        self.add_seamed(body, Some(seam)).await
    }

    async fn add_seamed(
        &self,
        body: Value,
        seam: Option<BackendStoreForTest>,
    ) -> (StatusCode, Value) {
        let req: AddBackendRequest = serde_json::from_value(body).expect("add body");
        let guard = Self::guard(routes::UI_BACKENDS, &axum::http::Method::POST);
        read(
            add_backend(
                State(Arc::clone(&self.state)),
                seam.map(axum::Extension),
                guard,
                Json(req),
            )
            .await
            .into_response(),
        )
        .await
    }

    async fn update(&self, name: &str, body: Value) -> (StatusCode, Value) {
        self.update_seamed(name, body, None).await
    }

    async fn update_seamed(
        &self,
        name: &str,
        body: Value,
        seam: Option<BackendStoreForTest>,
    ) -> (StatusCode, Value) {
        let req: UpdateBackendRequest = serde_json::from_value(body).expect("update body");
        let guard = Self::guard(routes::UI_BACKEND, &axum::http::Method::PATCH);
        read(
            update_backend(
                State(Arc::clone(&self.state)),
                seam.map(axum::Extension),
                guard,
                AxumPath(name.to_owned()),
                Json(req),
            )
            .await
            .into_response(),
        )
        .await
    }
}

fn admin() -> crate::gateway::auth::AuthenticatedClient {
    crate::gateway::auth::AuthenticatedClient {
        name: "backend-secrets".to_owned(),
        rate_limit: 0,
        backends: vec!["*".to_owned()],
        allowed_tools: None,
        denied_tools: None,
        admin: true,
        principal: crate::gateway::auth::principal_of("backend-secrets-secret"),
        quota_principal: None,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    }
}

async fn read(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 16).await.expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

impl Panel {
    /// Backend `name` as the loader reads it back from gateway.yaml (values as
    /// written, references unresolved).
    fn written(&self, name: &str) -> crate::config::BackendConfig {
        let (config, _) = Config::load_literal_with_text(&self.path()).expect("gateway.yaml loads");
        config
            .backends
            .get(name)
            .cloned()
            .expect("the backend is in gateway.yaml")
    }
}

/// No submitted value in an answer, in its decoded strings or its raw form.
fn no_value(body: &Value, value: &str) {
    assert!(
        !body.to_string().contains(value),
        "an answer showed a submitted value: {body}"
    );
}

/// A store whose create answers `TimedOut`, or that holds less than a value.
struct Limited {
    inner: FilesStore,
    limit: usize,
    time_out: bool,
    /// The create (counting from 1) that fails, if any.
    fail_create: Option<usize>,
    creates: std::sync::atomic::AtomicUsize,
    /// Every call made on this store, of any kind: a refused save must make none.
    touched: std::sync::atomic::AtomicUsize,
}

impl Limited {
    fn new(dir: &std::path::Path) -> Self {
        Self {
            inner: FilesStore::new(dir),
            limit: 4096,
            time_out: false,
            fail_create: None,
            creates: std::sync::atomic::AtomicUsize::new(0),
            touched: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn touch(&self) {
        self.touched
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn calls(&self) -> usize {
        self.touched.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl SecretStore for Limited {
    fn kind(&self) -> StoreKind {
        self.touch();
        self.inner.kind()
    }
    fn limit(&self) -> usize {
        self.touch();
        self.limit
    }
    fn probe(&self) -> Result<(), StoreError> {
        self.touch();
        self.inner.probe()
    }
    fn exists(&self, name: &str) -> Result<bool, StoreError> {
        self.touch();
        self.inner.exists(name)
    }
    fn create(&self, name: &str, value: &[u8]) -> Result<String, StoreError> {
        self.touch();
        if self.time_out {
            return Err(StoreError::TimedOut);
        }
        let n = self
            .creates
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        if self.fail_create == Some(n) {
            return Err(StoreError::Failed("the second create fails".to_owned()));
        }
        self.inner.create(name, value)
    }
    fn delete(&self, name: &str) -> Result<(), StoreError> {
        self.touch();
        self.inner.delete(name)
    }
}

fn literal_add(name: &str) -> Value {
    json!({"name": name, "url": "http://127.0.0.1:9/mcp", "env": {"API_KEY": TOKEN}})
}

/// T1: a literal env value goes to the store; gateway.yaml holds only the
/// store's reference, the answer names the field and that reference.
#[tokio::test]
async fn t1_a_literal_env_value_is_stored_and_only_its_reference_written() {
    let panel = Panel::new().await;
    let (status, body) = panel.add(literal_add("b")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    no_value(&body, TOKEN);
    let text = panel.text();
    assert!(
        !text.contains(TOKEN),
        "the literal reached gateway.yaml:\n{text}"
    );
    assert_eq!(panel.entries().len(), 1, "one entry: {:?}", panel.entries());
    let stored = body["secrets_stored"].as_array().expect("secrets_stored");
    assert_eq!(stored.len(), 1, "{body}");
    assert_eq!(stored[0]["field"], "env.API_KEY", "{body}");
    let reference = stored[0]["reference"].as_str().expect("a reference");
    // Read back through the loader: the raw text escapes a Windows path's
    // backslashes inside a quoted scalar.
    assert_eq!(
        panel.written("b").env.get("API_KEY").map(String::as_str),
        Some(reference),
        "{text}"
    );
}

/// T2/T3: an empty value, a template and a `file:` reference are written as
/// given and store nothing; the answer's list is empty. Each sits under a
/// credential name, so only the value rule (`classify`) keeps it out of the
/// store, never the name rule.
#[tokio::test]
async fn t2_references_templates_and_empty_values_are_kept_and_store_nothing() {
    let panel = Panel::new().await;
    let file = panel.dir.path().join("token.txt");
    write_owner_only(&file, "from-a-file").expect("secret file");
    let reference = format!("file:{}", file.display());
    let (status, body) = panel
        .add(json!({
            "name": "b",
            "url": "http://127.0.0.1:9/mcp",
            "env": {"EMPTY_TOKEN": "", "TEMPLATE_TOKEN": "${SOME_VAR}", "BEARER_TOKEN": "Bearer ${SOME_VAR}", "REF_TOKEN": reference},
        }))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["secrets_stored"], json!([]), "{body}");
    assert!(panel.entries().is_empty(), "{:?}", panel.entries());
    let text = panel.text();
    for kept in ["${SOME_VAR}", "Bearer ${SOME_VAR}", reference.as_str()] {
        assert!(
            text.contains(kept),
            "{kept} was not written as given:\n{text}"
        );
    }
    let env = panel.written("b").env;
    for (key, value) in [
        ("EMPTY_TOKEN", ""),
        ("TEMPLATE_TOKEN", "${SOME_VAR}"),
        ("BEARER_TOKEN", "Bearer ${SOME_VAR}"),
        ("REF_TOKEN", reference.as_str()),
    ] {
        assert_eq!(
            env.get(key).map(String::as_str),
            Some(value),
            "{key} as written: {env:?}"
        );
    }
}

/// T3b/T3c: a literal beside a template and a literal default are refused by
/// field and code, on add and on update, before any store is opened.
#[tokio::test]
async fn t3b_a_literal_beside_a_template_is_refused_by_field_before_the_store() {
    let panel = Panel::new().await;
    let before = panel.text();
    // With a plain literal beside them, so a refusal checked after the store step
    // would touch the store.
    let env = json!({"A": "sk-${X}", "B": "${X:-literal-default}", "C_TOKEN": TOKEN});
    let expected = json!([
        {"reason": "literal_in_template", "field": "env.A"},
        {"reason": "literal_default", "field": "env.B"},
    ]);
    let store = Arc::new(Limited::new(panel.dir.path()));
    let (status, body) = panel
        .add_into(
            json!({"name": "b", "url": "http://127.0.0.1:9/mcp", "env": env}),
            Some(Arc::clone(&store) as Arc<dyn SecretStore + Send + Sync>),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"], "literal_in_value", "{body}");
    assert_eq!(body["refusals"], expected, "{body}");
    let (status, body2) = panel
        .update_seamed(
            "a",
            json!({"env": env}),
            Some(BackendStoreForTest {
                store: Some(Arc::clone(&store) as Arc<dyn SecretStore + Send + Sync>),
                after_precheck: None,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body2}");
    assert_eq!(body2["refusals"], expected, "{body2}");
    for b in [&body, &body2] {
        no_value(b, "literal-default");
        no_value(b, "sk-$");
        no_value(b, TOKEN);
    }
    assert_eq!(store.calls(), 0, "a refused value touched the store");
    assert_eq!(panel.text(), before, "a refused save wrote");
    assert!(
        panel.entries().is_empty(),
        "a refused save stored: {:?}",
        panel.entries()
    );
}

/// T4/T4b and I1: a duplicate add (409) and an update of a missing backend
/// (404) answer before the value rule and before any store is touched (the
/// counting store sees no call: on a keychain host, no keychain is probed),
/// with a literal or a refused value alike.
#[tokio::test]
async fn t4_a_duplicate_or_missing_backend_answers_first_and_touches_no_store() {
    let panel = Panel::new().await;
    let before = panel.text();
    let store = Arc::new(Limited::new(panel.dir.path()));
    let seam = || BackendStoreForTest {
        store: Some(Arc::clone(&store) as Arc<dyn SecretStore + Send + Sync>),
        after_precheck: None,
    };
    let (status, body) = panel.add_seamed(literal_add("a"), Some(seam())).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    no_value(&body, TOKEN);
    let (status, body) = panel
        .update_seamed("missing", json!({"env": {"K_TOKEN": TOKEN}}), Some(seam()))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    no_value(&body, TOKEN);
    let (status, body) = panel
        .update_seamed("missing", json!({"env": {"K": "sk-${X}"}}), Some(seam()))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a refused value answered before the 404: {body}"
    );
    no_value(&body, "sk-$");
    assert_eq!(store.calls(), 0, "a refused save touched the store");
    assert_eq!(panel.text(), before);
    assert!(panel.entries().is_empty(), "{:?}", panel.entries());
}

/// T5/T14: an update stores only the key it sets; every other value,
/// including a pre-existing plaintext one, is carried byte for byte.
#[tokio::test]
async fn t5_an_update_stores_only_the_key_it_sets_and_carries_the_rest() {
    let panel = Panel::new().await;
    let (status, body) = panel
        .update("a", json!({"env": {"NEW_TOKEN": TOKEN}}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    no_value(&body, TOKEN);
    let text = panel.text();
    assert!(!text.contains(TOKEN), "{text}");
    assert!(
        text.contains("PLAIN: old-plain-value"),
        "a carried value changed:\n{text}"
    );
    assert_eq!(panel.entries().len(), 1, "{:?}", panel.entries());
    assert_eq!(
        body["secrets_stored"][0]["field"], "env.NEW_TOKEN",
        "{body}"
    );
}

/// T6b: a store whose create times out: 503, the file unchanged.
#[tokio::test]
async fn t6b_a_timed_out_create_writes_nothing() {
    let panel = Panel::new().await;
    let before = panel.text();
    let store = Arc::new(Limited {
        time_out: true,
        ..Limited::new(panel.dir.path())
    });
    let (status, body) = panel.add_into(literal_add("b"), Some(store)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    no_value(&body, TOKEN);
    assert_eq!(panel.text(), before);
}

/// T6d: a value larger than the store holds: 422 naming the field, nothing
/// written or stored.
#[tokio::test]
async fn t6d_a_value_over_the_store_limit_is_refused_by_field() {
    let panel = Panel::new().await;
    let before = panel.text();
    let store = Arc::new(Limited {
        limit: 4,
        ..Limited::new(panel.dir.path())
    });
    let (status, body) = panel.add_into(literal_add("b"), Some(store)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(
        body["refusals"],
        json!([{"reason": "value_too_large", "field": "env.API_KEY"}]),
        "{body}"
    );
    no_value(&body, TOKEN);
    assert_eq!(panel.text(), before);
    assert!(panel.entries().is_empty());
}

/// T9: a registry header entry: the token the operator gives for its
/// variable is spliced into `Authorization: Bearer ...` and that whole header
/// value is one stored entry; gateway.yaml holds only its reference.
#[tokio::test]
async fn t9_a_registry_header_token_is_stored_as_the_whole_header_value() {
    let panel = Panel::new().await;
    let (status, body) = panel
        .add(json!({"name": "github", "env": {"GITHUB_TOKEN": TOKEN}}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    no_value(&body, TOKEN);
    let text = panel.text();
    assert!(
        !text.contains(TOKEN),
        "the header token reached gateway.yaml:\n{text}"
    );
    assert_eq!(
        body["secrets_stored"][0]["field"], "headers.Authorization",
        "{body}"
    );
    assert_eq!(panel.entries().len(), 1, "{:?}", panel.entries());
    // The whole header value, as the registry's template spliced it
    // (`Bearer ${GITHUB_TOKEN}`, server_registry_entries.rs), is the entry.
    let reference = body["secrets_stored"][0]["reference"]
        .as_str()
        .expect("reference");
    let path = reference.strip_prefix("file:").expect("a file reference");
    let stored = crate::config::secret_ref::read_file_ref(
        "backends.github.headers.Authorization",
        std::path::Path::new(path),
    )
    .expect("the reference resolves");
    assert_eq!(stored, format!("Bearer {TOKEN}"));
}

/// T10: the round trip: the reference gateway.yaml now holds resolves, through
/// the loader's own `file:` reader, to exactly the value given (the files store
/// writes one trailing newline and the reader drops one: `files.rs`, `secret_ref.rs`).
#[tokio::test]
async fn t10_the_stored_reference_resolves_to_the_value_given() {
    let panel = Panel::new().await;
    let (_, body) = panel.add(literal_add("b")).await;
    let reference = body["secrets_stored"][0]["reference"]
        .as_str()
        .expect("reference")
        .to_owned();
    let path = reference
        .strip_prefix("file:")
        .expect("a file reference from the files store");
    let resolved = crate::config::secret_ref::read_file_ref(
        "backends.b.env.API_KEY",
        std::path::Path::new(path),
    )
    .expect("the reference resolves");
    assert_eq!(resolved, TOKEN);
}

/// T13: the shared rule is the CLI's too: `add_backend` refuses a literal
/// beside a template by field and code, never the value; a plain literal
/// still passes it (the CLI writes it as text, unchanged by this rule).
#[test]
fn t13_the_shared_rule_refuses_the_same_values_for_the_cli() {
    use crate::gateway::ui::backend_ops::{LITERAL_IN_VALUE, add_backend, resolve_backend};
    for (value, code) in [
        ("sk-${X}", "literal_in_template"),
        ("${X:-literal-default}", "literal_default"),
    ] {
        let mut config = Config::default();
        let env = std::collections::HashMap::from([("K".to_owned(), value.to_owned())]);
        let resolved = resolve_backend("b", Some("npx tool"), None, None, env).expect("resolves");
        let message = add_backend(&mut config, "b", resolved).expect_err("refused");
        assert!(
            message.contains(LITERAL_IN_VALUE) && message.contains(code),
            "{message}"
        );
        assert!(message.contains("backends.b.env.K"), "{message}");
        assert!(
            !message.contains("literal-default") && !message.contains("sk-$"),
            "{message}"
        );
        assert!(config.backends.is_empty());
    }
    let mut config = Config::default();
    let env = std::collections::HashMap::from([("K".to_owned(), "plain".to_owned())]);
    let resolved = resolve_backend("b", Some("npx tool"), None, None, env).expect("resolves");
    add_backend(&mut config, "b", resolved).expect("a plain literal passes the rule");
}

/// T15: the add preview refuses what the add would refuse, with the same
/// answer, before anything is described or run.
#[tokio::test]
async fn t15_the_preview_refuses_what_the_add_refuses() {
    let panel = Panel::new().await;
    let body = json!({"name": "b", "url": "http://127.0.0.1:9/mcp", "env": {"A": "sk-${X}"}});
    let request = serde_json::from_value(body.clone()).expect("preview body");
    let guard = Panel::guard(routes::UI_PREVIEWS, &axum::http::Method::POST);
    let (status, answer) = read(
        crate::gateway::ui::preview::preview_backend(
            State(Arc::clone(&panel.state)),
            axum::Extension(panel.state.live_config.generation()),
            guard,
            Json(request),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    let (_, added) = panel.add(body).await;
    assert_eq!(
        answer, added,
        "the preview and the add answered differently"
    );
    assert_eq!(
        answer["refusals"],
        json!([{"reason": "literal_in_template", "field": "env.A"}])
    );
}

/// T12: two literals where the second create fails: nothing is written and
/// the first entry is removed again (the store's all-or-nothing save).
#[tokio::test]
async fn t12_a_failure_after_the_first_entry_leaves_no_entry_and_no_change() {
    let panel = Panel::new().await;
    let before = panel.text();
    let store = Arc::new(Limited {
        fail_create: Some(2),
        ..Limited::new(panel.dir.path())
    });
    let body = json!({"name": "b", "url": "http://127.0.0.1:9/mcp", "env": {"FIRST_TOKEN": TOKEN, "SECOND_TOKEN": "another-literal"}});
    let (status, answer) = panel.add_into(body, Some(store)).await;
    assert!(status.is_server_error(), "{status}: {answer}");
    no_value(&answer, TOKEN);
    no_value(&answer, "another-literal");
    assert_eq!(panel.text(), before, "a failed save wrote");
    assert!(
        panel.entries().is_empty(),
        "the first entry stayed: {:?}",
        panel.entries()
    );
}

/// T7: a reload that refuses the new bytes: the route answers a failure,
/// gateway.yaml is put back as it was, and the save's entry is removed.
#[tokio::test]
async fn t7_a_refused_reload_puts_gateway_yaml_back_and_leaves_no_entry() {
    let panel = Panel::with(START, Reloads::Refuse).await;
    let before = panel.text();
    let (status, body) = panel.add(literal_add("b")).await;
    assert!(status.is_server_error(), "{status}: {body}");
    no_value(&body, TOKEN);
    assert_eq!(panel.text(), before, "the refused bytes stayed on disk");
    assert!(
        panel.entries().is_empty(),
        "a refused save left {:?}",
        panel.entries()
    );
}

/// T4r: another writer adds the backend (or removes it) between the route's
/// pre-check and the locked write: the locked edit refuses it (409 / 404),
/// no entry is left, and the other writer's change is kept.
#[tokio::test]
async fn t4r_a_change_between_the_pre_check_and_the_write_refuses_and_stores_nothing() {
    let panel = Panel::new().await;
    let config = panel.path();
    let raced = format!("{START}  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n");
    let other = raced.clone();
    let seam = BackendStoreForTest {
        store: None,
        after_precheck: Some(Arc::new(move || {
            write_owner_only(&config, &other).expect("race");
        })),
    };
    let (status, body) = panel.add_seamed(literal_add("b"), Some(seam)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(panel.text(), raced, "the other writer's change was lost");
    assert!(panel.entries().is_empty(), "{:?}", panel.entries());

    let panel = Panel::new().await;
    let config = panel.path();
    let removed = "secrets:\n  store: files\nbackends: {}\n".to_owned();
    let other = removed.clone();
    let seam = BackendStoreForTest {
        store: None,
        after_precheck: Some(Arc::new(move || {
            write_owner_only(&config, &other).expect("race");
        })),
    };
    let (status, body) = panel
        .update_seamed("a", json!({"env": {"NEW_TOKEN": TOKEN}}), Some(seam))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(panel.text(), removed);
    assert!(panel.entries().is_empty(), "{:?}", panel.entries());
}

#[path = "backends_secret_name_tests.rs"]
mod names;

#[path = "backends_credential_tests.rs"]
mod credentials;
