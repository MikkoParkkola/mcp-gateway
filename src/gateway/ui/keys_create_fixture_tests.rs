// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shared fixture of the create-key rows: a gateway over a real
//! gateway.yaml, a real reload context and audit log, and one POST helper
//! that captures the answer, the log lines and (for the leak grep) every
//! place a secret could land.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

use super::keys_create::{BeforeLock, KnownSecret};
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
}

impl Default for Setup {
    fn default() -> Self {
        Self {
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
}

impl Call {
    pub(super) fn new(body: &Value) -> Self {
        Self {
            body: body.to_string(),
            client: admin_client(),
            known: Some(KNOWN.to_owned()),
            before_lock: None,
        }
    }

    pub(super) fn raw(body: &str) -> Self {
        Self {
            body: body.to_owned(),
            ..Self::new(&Value::Null)
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

pub(super) struct Fixture {
    pub(super) rt: tokio::runtime::Runtime,
    pub(super) dir: tempfile::TempDir,
    _store: crate::gateway::router::tests::FixtureDir,
    pub(super) state: Arc<AppState>,
    pub(super) live: Arc<LiveConfig>,
}

impl Fixture {
    pub(super) fn new(setup: Setup) -> Self {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("gateway.yaml");
        if setup.file {
            write_owner_only(&path, &setup.text).expect("write config");
        }
        let (mut state, store) = rt.block_on(crate::gateway::router::tests::audience_state(
            &AuthConfig::default(),
            (None, None),
            |m| m,
        ));
        let live = Arc::new(LiveConfig::new(Config {
            auth: setup.running,
            ..Config::default()
        }));
        let unique = Arc::get_mut(&mut state).expect("state is unique");
        unique.live_config = Arc::clone(&live);
        unique.config_path = setup.file.then(|| path.clone());
        if setup.audit_log {
            unique.transparency_log = Some(Arc::new(open_log(&dir)));
        }
        if setup.reload {
            let context = ReloadContext::new(
                path,
                Arc::clone(&live),
                Arc::clone(&state.backends),
                FailsafeConfig::default(),
                Duration::from_secs(60),
            )
            .expect("the registry pairs with the config");
            state.meta_mcp.set_reload_context(Arc::new(context));
        }
        Self {
            rt,
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
        let key = generation.auth().record_key().clone();
        serde_json::to_value(AuditWho::from_request(Some(client), None, &key)).expect("who")
    }

    pub(super) async fn send(&self, call: Call) -> Sent {
        let mut request = Request::builder()
            .method("POST")
            .uri(URI)
            .header("content-type", "application/json")
            .extension(call.client);
        if let Some(known) = call.known {
            request = request.extension(KnownSecret(known));
        }
        if let Some(hook) = call.before_lock {
            request = request.extension(hook);
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
        let bytes = to_bytes(response.into_body(), 1 << 16).await.expect("body");
        Sent {
            status,
            cache_control,
            body: String::from_utf8_lossy(&bytes).into_owned(),
            logs: String::new(),
        }
    }

    /// `send`, capturing the log records written on this thread.
    pub(super) fn post(&self, call: Call) -> Sent {
        let mut sent = None;
        let logs = crate::test_log_capture::records(|| {
            sent = Some(self.rt.block_on(self.send(call)));
        });
        let mut sent = sent.expect("the call ran");
        sent.logs = serde_json::to_string(&logs).expect("logs");
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

fn open_log(dir: &tempfile::TempDir) -> crate::security::TransparencyLogger {
    crate::security::TransparencyLogger::open(Arc::new(
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
    .expect("open log")
}

/// Every spelling of `bytes` the leak checks refuse: hex in both cases,
/// unpadded standard and URL-safe base64, a JSON byte array and the spaced
/// Debug list.
fn spellings(bytes: &[u8]) -> Vec<String> {
    use base64::Engine as _;
    let list: Vec<String> = bytes.iter().map(u8::to_string).collect();
    vec![
        hex::encode(bytes),
        hex::encode_upper(bytes),
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
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

impl Fixture {
    /// L1: the secret nowhere but a 201's `secret` field, and its digest
    /// nowhere but `key_sha256` of a written entry (a definite refusal holds
    /// no digest at all, the file included). Looks in the file, the answer,
    /// the captured log and the audit log.
    pub(super) fn assert_leak_free(&self, sent: &Sent, secret: &str) {
        let created = sent.status == StatusCode::CREATED;
        let digest = crate::config::parse_api_key_digest(&spec(secret)).expect("digest");
        let mut digests = spellings(&digest);
        digests.push(spec(secret));
        let file = self.text();
        let audit = self.audit_text();
        for (place, text) in [("logs", &sent.logs), ("audit", &audit)] {
            assert!(!text.contains(secret), "the secret is in the {place}");
            for d in &digests {
                assert!(
                    !text.contains(d.as_str()),
                    "a digest ({d}) is in the {place}"
                );
            }
        }
        assert!(!file.contains(secret), "the secret is in the file");
        for d in &digests {
            let (in_file, in_answer) = (
                file.matches(d.as_str()).count(),
                sent.body.contains(d.as_str()),
            );
            assert!(!in_answer, "a digest ({d}) is in the answer: {}", sent.body);
            let allowed = usize::from(created && d.as_str() == spec(secret));
            assert_eq!(in_file, allowed, "digest {d} in the file {in_file} times");
        }
        let answered = sent.body.matches(secret).count();
        assert_eq!(answered, usize::from(created), "{}", sent.body);
        let others: Vec<String> = [&file, &sent.body, &sent.logs, &audit]
            .iter()
            .flat_map(|t| secret_shaped(t))
            .filter(|s| s != secret)
            .collect();
        assert!(
            others.is_empty(),
            "another secret-shaped string: {others:?}"
        );
    }
}
