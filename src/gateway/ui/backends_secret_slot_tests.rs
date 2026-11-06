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

impl Panel {
    async fn new() -> Self {
        Self::with(START).await
    }

    async fn with(text: &str) -> Self {
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
        let ctx = Arc::new(
            ReloadContext::new(
                path,
                Arc::new(LiveConfig::new(running)),
                Arc::clone(&state.backends),
                FailsafeConfig::default(),
                Duration::from_secs(60),
            )
            .expect("the registry pairs with the config"),
        );
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
            .filter_map(|e| e.ok())
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
        self.add_into(body, None).await
    }

    async fn add_into(
        &self,
        body: Value,
        store: Option<Arc<dyn SecretStore + Send + Sync>>,
    ) -> (StatusCode, Value) {
        let req: AddBackendRequest = serde_json::from_value(body).expect("add body");
        let guard = Self::guard(routes::UI_BACKENDS, &axum::http::Method::POST);
        read(
            add_backend(
                State(Arc::clone(&self.state)),
                store.map(|s| axum::Extension(BackendStoreForTest(s))),
                guard,
                Json(req),
            )
            .await
            .into_response(),
        )
        .await
    }

    async fn update(&self, name: &str, body: Value) -> (StatusCode, Value) {
        let req: UpdateBackendRequest = serde_json::from_value(body).expect("update body");
        let guard = Self::guard(routes::UI_BACKEND, &axum::http::Method::PATCH);
        read(
            update_backend(
                State(Arc::clone(&self.state)),
                None,
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
}

impl SecretStore for Limited {
    fn kind(&self) -> StoreKind {
        self.inner.kind()
    }
    fn limit(&self) -> usize {
        self.limit
    }
    fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe()
    }
    fn exists(&self, name: &str) -> Result<bool, StoreError> {
        self.inner.exists(name)
    }
    fn create(&self, name: &str, value: &[u8]) -> Result<String, StoreError> {
        if self.time_out {
            return Err(StoreError::TimedOut);
        }
        self.inner.create(name, value)
    }
    fn delete(&self, name: &str) -> Result<(), StoreError> {
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
    assert!(
        text.contains(reference),
        "gateway.yaml lacks {reference}:\n{text}"
    );
}

/// T2/T3: an empty value, a template and a `file:` reference are written as
/// given and store nothing; the answer's list is empty.
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
            "env": {"EMPTY": "", "TEMPLATE": "${SOME_VAR}", "BEARER": "Bearer ${SOME_VAR}", "REF": reference},
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
}

/// T3b/T3c: a literal beside a template and a literal default are refused by
/// field and code, on add and on update, before any store is opened.
#[tokio::test]
async fn t3b_a_literal_beside_a_template_is_refused_by_field_before_the_store() {
    let panel = Panel::new().await;
    let before = panel.text();
    let env = json!({"A": "sk-${X}", "B": "${X:-literal-default}"});
    let expected = json!([
        {"reason": "literal_in_template", "field": "env.A"},
        {"reason": "literal_default", "field": "env.B"},
    ]);
    let (status, body) = panel
        .add(json!({"name": "b", "url": "http://127.0.0.1:9/mcp", "env": env}))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"], "literal_in_value", "{body}");
    assert_eq!(body["refusals"], expected, "{body}");
    let (status, body2) = panel.update("a", json!({"env": env})).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body2}");
    assert_eq!(body2["refusals"], expected, "{body2}");
    for b in [&body, &body2] {
        no_value(b, "literal-default");
        no_value(b, "sk-$");
    }
    assert_eq!(panel.text(), before, "a refused save wrote");
    assert!(
        panel.entries().is_empty(),
        "a refused save stored: {:?}",
        panel.entries()
    );
}

/// T4/T4b and I1: a duplicate add (409) and an update of a missing backend
/// (404) answer before the value rule and the store, with a literal or a
/// refused value alike.
#[tokio::test]
async fn t4_a_duplicate_or_missing_backend_answers_first_and_stores_nothing() {
    let panel = Panel::new().await;
    let before = panel.text();
    let (status, body) = panel.add(literal_add("a")).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (status, body) = panel.update("missing", json!({"env": {"K": TOKEN}})).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = panel
        .update("missing", json!({"env": {"K": "sk-${X}"}}))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a refused value answered before the 404: {body}"
    );
    assert_eq!(panel.text(), before);
    assert!(panel.entries().is_empty(), "{:?}", panel.entries());
}

/// T5/T14: an update stores only the key it sets; every other value,
/// including a pre-existing plaintext one, is carried byte for byte.
#[tokio::test]
async fn t5_an_update_stores_only_the_key_it_sets_and_carries_the_rest() {
    let panel = Panel::new().await;
    let (status, body) = panel.update("a", json!({"env": {"NEW": TOKEN}})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let text = panel.text();
    assert!(!text.contains(TOKEN), "{text}");
    assert!(
        text.contains("PLAIN: old-plain-value"),
        "a carried value changed:\n{text}"
    );
    assert_eq!(panel.entries().len(), 1, "{:?}", panel.entries());
    assert_eq!(body["secrets_stored"][0]["field"], "env.NEW", "{body}");
}

/// T6b: a store whose create times out: 503, the file unchanged.
#[tokio::test]
async fn t6b_a_timed_out_create_writes_nothing() {
    let panel = Panel::new().await;
    let before = panel.text();
    let store = Arc::new(Limited {
        inner: FilesStore::new(panel.dir.path()),
        limit: 4096,
        time_out: true,
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
        inner: FilesStore::new(panel.dir.path()),
        limit: 4,
        time_out: false,
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
}

/// T10: the stored entry holds exactly the value given (the files store keeps
/// one file per entry, named by the reference).
#[tokio::test]
async fn t10_the_stored_entry_holds_the_value_given() {
    let panel = Panel::new().await;
    let (_, body) = panel.add(literal_add("b")).await;
    let reference = body["secrets_stored"][0]["reference"]
        .as_str()
        .expect("reference")
        .to_owned();
    let path = reference
        .strip_prefix("file:")
        .expect("a file reference from the files store");
    assert_eq!(std::fs::read_to_string(path).expect("entry reads"), TOKEN);
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
