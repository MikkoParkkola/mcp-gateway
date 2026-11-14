// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shared fixture of the create-key rows: a gateway over a real
//! gateway.yaml, a real reload context and audit log, and one POST helper
//! that captures the answer, the log lines and (for the leak grep) every
//! place a secret could land.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

use super::keys_create::{BeforeLock, InjectWriter, KnownSecret};
use crate::config::{ApiKeyConfig, AuthConfig, Config, FailsafeConfig};
use crate::config_reload::{FileRevision, LiveConfig, ReloadContext};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::router::AppState;
use crate::gateway::test_helpers::write_owner_only;
use crate::security::audit::AuditWho;

pub(super) const URI: &str = "/ui/api/keys";
pub(super) const ROOT: &str = "create-root-secret";
/// The secret the route hands out in every row that injects one.
pub(super) const KNOWN: &str = "mcpgw_create-row-known-secret-0123456789abcdef";

pub(super) fn spec(secret: &str) -> String {
    crate::config::api_key_digest_spec(secret.as_bytes())
}

/// One `auth.api_keys` list item.
pub(super) fn item(name: &str, secret: &str, extra: &str) -> String {
    format!(
        "    - name: {name}\n      key_sha256: \"{}\"\n      backends: [\"*\"]\n{extra}",
        spec(secret)
    )
}

/// A gateway.yaml over the given list items.
pub(super) fn yaml_of(items: &[String]) -> String {
    format!(
        "secrets:\n  store: files\nbackends: {{}}\nauth:\n  enabled: true\n  api_keys:\n{}",
        items.concat()
    )
}

pub(super) fn root_item() -> String {
    item("root", ROOT, "      admin: true\n")
}

/// How a row's gateway is built.
pub(super) struct Setup {
    pub(super) text: String,
    pub(super) audit_log: bool,
    pub(super) reload: bool,
    pub(super) file: bool,
    pub(super) running: AuthConfig,
    /// When set, the handlers read this table while the reload publishes to
    /// its own: a write the live generation never sees.
    pub(super) split_live: Option<AuthConfig>,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            split_live: None,
            text: yaml_of(&[root_item()]),
            audit_log: true,
            reload: true,
            file: true,
            running: AuthConfig {
                enabled: true,
                api_keys: vec![ApiKeyConfig {
                    name: "root".into(),
                    key_sha256: Some(spec(ROOT)),
                    backends: vec!["*".into()],
                    admin: true,
                    ..Default::default()
                }],
                ..AuthConfig::default()
            },
        }
    }
}

/// What one POST came back with.
pub(super) struct Sent {
    pub(super) status: StatusCode,
    pub(super) cache_control: Option<String>,
    pub(super) body: String,
    /// Every response header, name and value.
    pub(super) headers: Vec<(String, String)>,
    pub(super) logs: String,
}

impl Sent {
    pub(super) fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

/// One POST: its body and what rides on the request.
pub(super) struct Call {
    pub(super) body: String,
    pub(super) client: AuthenticatedClient,
    pub(super) known: Option<String>,
    pub(super) before_lock: Option<BeforeLock>,
    pub(super) inject: Option<InjectWriter>,
    /// The named-key provenance the auth layer adds for an API-key caller.
    pub(super) named: Option<crate::gateway::auth::NamedApiKey>,
}

impl Call {
    pub(super) fn new(body: &Value) -> Self {
        Self {
            body: body.to_string(),
            client: admin_client(),
            known: Some(KNOWN.to_owned()),
            before_lock: None,
            inject: None,
            named: None,
        }
    }
}

pub(super) fn admin_client() -> AuthenticatedClient {
    AuthenticatedClient {
        name: "root".into(),
        admin: true,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
        principal: crate::gateway::auth::principal_of("create-root"),
        ..crate::gateway::auth::anonymous_client()
    }
}

/// The bytes of every JSON log record the fixture's threads wrote.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

thread_local! {
    /// The capture subscriber a runtime thread installed when it started.
    static THREAD_CAPTURE: std::cell::RefCell<Option<tracing::dispatcher::DefaultGuard>> =
        const { std::cell::RefCell::new(None) };
}

/// A runtime whose every thread (the blocking loader's and the writer's
/// task included) logs into `dispatch`.
fn capturing_runtime(dispatch: &tracing::Dispatch) -> tokio::runtime::Runtime {
    let dispatch = dispatch.clone();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .on_thread_start(move || {
            let guard = tracing::dispatcher::set_default(&dispatch);
            THREAD_CAPTURE.with(|slot| *slot.borrow_mut() = Some(guard));
        })
        .build()
        .expect("runtime")
}

pub(super) struct Fixture {
    pub(super) rt: tokio::runtime::Runtime,
    capture: Capture,
    dispatch: tracing::Dispatch,
    /// Whether gateway.yaml exists: its absence is the expected state when not.
    has_file: bool,
    /// Whether the audit log is on: then audit.jsonl must be there to read.
    has_audit_log: bool,
    pub(super) dir: Arc<tempfile::TempDir>,
    _store: crate::gateway::router::tests::FixtureDir,
    pub(super) state: Arc<AppState>,
    pub(super) live: Arc<LiveConfig>,
}

impl Fixture {
    pub(super) fn new(setup: Setup) -> Self {
        crate::test_log_capture::keep_interest_open();
        let capture = Capture::default();
        let writer = capture.clone();
        let dispatch = tracing::Dispatch::new(
            tracing_subscriber::fmt()
                .json()
                .without_time()
                .with_ansi(false)
                .with_max_level(tracing::Level::TRACE)
                .with_writer(move || writer.clone())
                .finish(),
        );
        let rt = capturing_runtime(&dispatch);
        let dir = crate::test_dir_keep::kept_tempdir();
        let path = dir.path().join("gateway.yaml");
        if setup.file {
            write_owner_only(&path, &setup.text).expect("write config");
        }
        let (mut state, store) = rt.block_on(crate::gateway::router::tests::audience_state(
            &AuthConfig::default(),
            (None, None),
            |m| m,
        ));
        let reload_live = Arc::new(LiveConfig::new(Config {
            auth: setup.running,
            ..Config::default()
        }));
        let live = setup.split_live.map_or_else(
            || Arc::clone(&reload_live),
            |auth| {
                Arc::new(LiveConfig::new(Config {
                    auth,
                    ..Config::default()
                }))
            },
        );
        let unique = Arc::get_mut(&mut state).expect("state is unique");
        unique.live_config = Arc::clone(&live);
        unique.config_path = setup.file.then(|| path.clone());
        if setup.audit_log {
            unique.transparency_log = Some(Arc::new(open_log(&dir)));
        }
        if setup.reload {
            let context = ReloadContext::new(
                path,
                reload_live,
                Arc::clone(&state.backends),
                FailsafeConfig::default(),
                Duration::from_secs(60),
            )
            .expect("the registry pairs with the config");
            state.meta_mcp.set_reload_context(Arc::new(context));
        }
        Self {
            rt,
            capture,
            dispatch,
            has_file: setup.file,
            has_audit_log: setup.audit_log,
            dir,
            _store: store,
            state,
            live,
        }
    }

    pub(super) fn path(&self) -> std::path::PathBuf {
        self.dir.path().join("gateway.yaml")
    }

    pub(super) fn bytes(&self) -> Vec<u8> {
        std::fs::read(self.path()).unwrap_or_default()
    }

    pub(super) fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes()).into_owned()
    }

    pub(super) fn revision(&self) -> String {
        FileRevision::of(&self.bytes()).as_str().to_owned()
    }

    pub(super) fn audit_text(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("audit.jsonl")).unwrap_or_default()
    }

    /// Every audit record whose event is `event`.
    pub(super) fn records(&self, event: &str) -> Vec<Value> {
        self.audit_text()
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|r| r["event"] == event)
            .collect()
    }

    /// The file's keys, as the loader reads them.
    pub(super) fn file_keys(&self) -> Vec<ApiKeyConfig> {
        Config::load_literal(Some(&self.path()))
            .expect("the file loads")
            .auth
            .api_keys
    }

    /// The minimal valid body for `name`, against the file as it is now.
    pub(super) fn body(&self, name: &str) -> Value {
        serde_json::json!({"name": name, "backends": ["*"], "revision": self.revision()})
    }

    /// Who the route should record for `client`.
    pub(super) fn who(&self, client: &AuthenticatedClient) -> Value {
        let generation = self.live.generation();
        let key = generation.auth().record_key();
        serde_json::to_value(AuditWho::from_request(Some(client), None, key)).expect("who")
    }

    // Private: every row goes through `post`, so none can skip L1.
    async fn send(&self, call: Call) -> Sent {
        let mut request = Request::builder()
            .method("POST")
            .uri(URI)
            .header("content-type", "application/json")
            .extension(call.client)
            .extension(self.live.generation());
        if let Some(known) = call.known {
            request = request.extension(KnownSecret(known));
        }
        if let Some(hook) = call.before_lock {
            request = request.extension(hook);
        }
        if let Some(inject) = call.inject {
            request = request.extension(inject);
        }
        if let Some(named) = call.named {
            request = request.extension(named);
        }
        let response = super::admin_audit::audited_api_router(&self.state)
            .with_state(Arc::clone(&self.state))
            .oneshot(request.body(Body::from(call.body)).expect("request"))
            .await
            .expect("infallible");
        let status = response.status();
        let cache_control = response
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), String::from_utf8_lossy(v.as_bytes()).into()))
            .collect();
        let bytes = to_bytes(response.into_body(), 1 << 16).await.expect("body");
        Sent {
            status,
            cache_control,
            headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
            logs: String::new(),
        }
    }

    /// `send`, capturing the log records of every thread the request
    /// touches, then the shared leak check (L1): no row can skip it.
    pub(super) fn post(&self, call: Call) -> Sent {
        self.post_driven(call, |send| send)
    }

    /// [`Fixture::post`] for a row that must drive the request's future
    /// alongside its own (a held lock, a clock to advance).
    #[expect(
        clippy::needless_lifetimes,
        reason = "'a ties the boxed send future to self; elided in the Fn bound it would be higher-ranked"
    )]
    pub(super) fn post_driven<'a, Fut: std::future::Future<Output = Sent>>(
        &'a self,
        call: Call,
        drive: impl FnOnce(std::pin::Pin<Box<dyn std::future::Future<Output = Sent> + 'a>>) -> Fut,
    ) -> Sent {
        let known = call.known.clone();
        let asked = serde_json::from_str::<Value>(&call.body).unwrap_or(Value::Null);
        self.capture.0.lock().expect("capture").clear();
        let mut sent = tracing::dispatcher::with_default(&self.dispatch, || {
            self.rt.block_on(drive(Box::pin(self.send(call))))
        });
        let bytes = self.capture.0.lock().expect("capture").clone();
        sent.logs = String::from_utf8(bytes).expect("utf-8 log output");
        let secret = known.or_else(|| sent.json()["secret"].as_str().map(str::to_owned));
        // Every POST is checked: a row that knows no secret and got none back
        // would otherwise skip L1, so it fails instead.
        let secret =
            secret.expect("L1: set call.known, or the answer must be a 201 with its secret");
        self.assert_leak_free(&sent, &secret, asked["name"].as_str());
        sent
    }

    /// `GET /ui/api/keys` against the live generation.
    pub(super) fn get(&self) -> Value {
        let request = Request::builder()
            .uri(URI)
            .extension(self.live.generation())
            .extension(admin_client())
            .body(Body::empty())
            .expect("request");
        self.rt.block_on(async {
            let response = super::admin_audit::audited_api_router(&self.state)
                .with_state(Arc::clone(&self.state))
                .oneshot(request)
                .await
                .expect("infallible");
            let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
            serde_json::from_slice(&bytes).expect("json")
        })
    }
}

/// The fixture's audit log, which keeps its directory until its last handle,
/// so a late write lands before the directory goes.
fn open_log(dir: &Arc<tempfile::TempDir>) -> crate::security::TransparencyLogger {
    let log = crate::security::TransparencyLogger::open(Arc::new(
        crate::security::transparency_log::TransparencyLogConfig {
            enabled: true,
            path: dir
                .path()
                .join("audit.jsonl")
                .to_string_lossy()
                .into_owned(),
            key_id: "create-rows".to_string(),
            ..Default::default()
        },
    ))
    .expect("open log");
    log.keep_test_dir(Arc::clone(dir));
    log
}

/// Every spelling of `bytes` the leak checks refuse: hex in both cases,
/// standard and URL-safe base64 padded and not, a JSON byte array and the
/// spaced Debug list.
fn spellings(bytes: &[u8]) -> Vec<String> {
    use base64::Engine as _;
    let list: Vec<String> = bytes.iter().map(u8::to_string).collect();
    vec![
        hex::encode(bytes),
        hex::encode_upper(bytes),
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
        base64::engine::general_purpose::STANDARD.encode(bytes),
        base64::engine::general_purpose::URL_SAFE.encode(bytes),
        format!("[{}]", list.join(",")),
        format!("[{}]", list.join(", ")),
    ]
}

/// The `mcpgw_` secret-shaped strings in `text`.
fn secret_shaped(text: &str) -> Vec<String> {
    text.match_indices("mcpgw_")
        .map(|(at, _)| {
            text[at..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .collect()
        })
        .collect()
}

/// `path`'s text. A missing file is `None`; any other failure fails the test,
/// so an unreadable place is never taken for an empty one.
fn read_present(path: &std::path::Path) -> Option<String> {
    match std::fs::read(path) {
        Ok(bytes) => Some(String::from_utf8(bytes).expect("utf-8 text")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => panic!("{} cannot be read: {e}", path.display()),
    }
}

fn collect_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.push(s.clone()),
        Value::Array(items) => items.iter().for_each(|v| collect_strings(v, out)),
        Value::Object(map) => map.iter().for_each(|(k, v)| {
            out.push(k.clone());
            collect_strings(v, out);
        }),
        _ => {}
    }
}

/// `raw` and, when it is JSON (a document or one record per line), every
/// string in it decoded, so a `\u`-escaped spelling is seen too.
fn decoded(raw: &str) -> Vec<String> {
    let mut out = vec![raw.to_owned()];
    let values: Vec<Value> = serde_json::from_str(raw).map_or_else(
        |_| {
            raw.lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect()
        },
        |whole| vec![whole],
    );
    for value in &values {
        collect_strings(value, &mut out);
    }
    out
}

/// Fails when any of `needles` is in `raw` or in a string decoded from it.
fn assert_clean(place: &str, raw: &str, needles: &[String]) {
    for text in decoded(raw) {
        for needle in needles {
            assert!(
                !text.contains(needle.as_str()),
                "{place} holds a forbidden value ({needle})"
            );
        }
    }
}

/// How many `key_sha256` values of the created entry an outcome may hold.
fn digest_allowance(sent: &Sent) -> std::ops::RangeInclusive<usize> {
    match sent.status {
        StatusCode::CREATED => 1..=1,
        StatusCode::INTERNAL_SERVER_ERROR if sent.json()["error"] == "state_uncertain" => 0..=1,
        _ => 0..=0,
    }
}

/// The 201 body with its one permitted secret removed; any other body whole.
fn body_without_secret(sent: &Sent, secret: &str) -> String {
    if sent.status != StatusCode::CREATED {
        return sent.body.clone();
    }
    let mut answer = sent.json();
    assert_eq!(answer["secret"], secret, "{}", sent.body);
    answer["secret"] = Value::String(String::new());
    answer.to_string()
}

impl Fixture {
    /// L1: the secret nowhere but a 201's `secret` field, and its digest
    /// nowhere but `key_sha256` of the created entry (a definite refusal
    /// holds none; an uncertain ending at most one). Looks in gateway.yaml,
    /// the answer and its headers, the captured logs, the audit log (which
    /// also records every write intent) and the replace journal with its
    /// staged original. Only a missing file is empty, and only where its
    /// absence is the expected state; any other read failure fails.
    fn assert_leak_free(&self, sent: &Sent, secret: &str, name: Option<&str>) {
        let spec_text = spec(secret);
        let digest = crate::config::parse_api_key_digest(&spec_text).expect("digest");
        let mut bare = spellings(&digest);
        bare.push(secret.to_owned());
        let mut forbidden = bare.clone();
        forbidden.push(spec_text.clone());
        let headers: Vec<String> = sent
            .headers
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect();
        assert_clean("headers", &headers.join("\n"), &forbidden);
        assert_clean("answer", &body_without_secret(sent, secret), &forbidden);
        assert_clean("logs", &sent.logs, &forbidden);
        let target = crate::identity_grants::journal::resolved(&self.path());
        let side = [
            ("audit", self.dir.path().join("audit.jsonl")),
            (
                "journal",
                crate::config_persistence::journal::journal_path(&target),
            ),
            (
                "staged original",
                crate::config_persistence::journal::original_path(&target),
            ),
        ];
        let mut texts = vec![sent.body.clone(), sent.logs.clone()];
        for (place, path) in side {
            let text = match read_present(&path) {
                Some(text) => text,
                // The log is opened at start, so with it on, a missing file
                // is a lost sink, never an empty one.
                None if place == "audit" && self.has_audit_log => {
                    panic!("audit.jsonl is missing though the audit log is on")
                }
                None => String::new(),
            };
            assert_clean(place, &text, &forbidden);
            texts.push(text);
        }
        texts.push(self.assert_file(secret, name, digest_allowance(sent), &bare));
        let others: Vec<String> = texts
            .iter()
            .flat_map(|t| secret_shaped(t))
            .filter(|s| s != secret)
            .collect();
        assert!(
            others.is_empty(),
            "another secret-shaped string: {others:?}"
        );
    }

    /// gateway.yaml: the secret absent, the digest spec exactly where the
    /// parsed entry says (raw count equal to parsed count, so a comment or
    /// a second entry fails), every other spelling absent. Returns the text.
    fn assert_file(
        &self,
        secret: &str,
        name: Option<&str>,
        allowed: std::ops::RangeInclusive<usize>,
        bare: &[String],
    ) -> String {
        let Some(file) = read_present(&self.path()) else {
            assert!(!self.has_file, "gateway.yaml is gone");
            return String::new();
        };
        assert!(!file.contains(secret), "the secret is in the file");
        let spec_text = spec(secret);
        let keys = Config::load_literal(Some(&self.path()))
            .map_or_else(|_| Vec::new(), |c| c.auth.api_keys);
        let holding = keys
            .iter()
            .filter(|k| k.key_sha256.as_deref() == Some(spec_text.as_str()));
        let own = holding
            .clone()
            .filter(|k| Some(k.name.as_str()) == name)
            .count();
        assert_eq!(holding.count(), own, "another entry holds the digest");
        assert_eq!(
            file.matches(spec_text.as_str()).count(),
            own,
            "digest spec outside key_sha256"
        );
        assert!(
            allowed.contains(&own),
            "{own} entries hold the digest, allowed {allowed:?}"
        );
        assert_clean("file", &file.replace(spec_text.as_str(), ""), bare);
        file
    }
}
