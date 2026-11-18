// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! H1r: each UI write route records `Source::Ui` with the admin account.
//! Red while the writers still pass `Source::Ui { who: "" }`.
#![cfg(feature = "webui")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::BoxFuture;

use super::{Bounds, ConfigHistory, HistoryHook, Outcome, Source};
use crate::config::{ApiKeyConfig, ApiKeyKind, AuthConfig, FailsafeConfig};
use crate::discovery::config_scanner::ConfigScanner;
use crate::discovery::config_scanner::client_scan::{ClientScan, Fingerprint};
use crate::discovery::listing::ScanSource;
use crate::discovery::{DiscoveredServer, DiscoverySource, ServerMetadata};
use crate::gateway::record_principal::test_record_key;
use crate::gateway::test_helpers::{create_router, write_owner_only};

const ADMIN: Key = Key {
    name: "ui-admin",
    secret: "ui-admin",
    admin: true,
};

struct Key {
    name: &'static str,
    secret: &'static str,
    admin: bool,
}

struct Held<F> {
    state: Arc<crate::gateway::test_helpers::AppState>,
    store: Arc<ConfigHistory>,
    path: PathBuf,
    _dir: Arc<tempfile::TempDir>,
    _fixture: F,
}

fn spec(secret: &str) -> String {
    crate::config::api_key_digest_spec(secret.as_bytes())
}

/// The `auth.api_keys` block the keys fixture writes (`yaml_of` / `item`).
fn auth_block(keys: &[Key]) -> String {
    use std::fmt::Write as _;
    let mut text = String::from("auth:\n  enabled: true\n  api_keys:\n");
    for key in keys {
        let _ = write!(
            text,
            "    - name: {name}\n      key_sha256: \"{digest}\"\n      backends: [\"*\"]\n",
            name = key.name,
            digest = spec(key.secret),
        );
        if key.admin {
            text.push_str("      admin: true\n");
        }
    }
    text
}

fn auth_config(keys: &[Key]) -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: keys
            .iter()
            .map(|key| ApiKeyConfig {
                key: None,
                key_sha256: Some(spec(key.secret)),
                expires_at: None,
                name: key.name.to_string(),
                rate_limit: 0,
                backends: vec!["*".to_string()],
                allowed_tools: None,
                denied_tools: None,
                admin: key.admin,
                kind: ApiKeyKind::Shared,
                ..ApiKeyConfig::default()
            })
            .collect(),
        ..AuthConfig::default()
    }
}

fn tag(secret: &str) -> Result<String, String> {
    let digest = crate::config::parse_api_key_digest(&spec(secret)).ok_or("digest")?;
    Ok(crate::gateway::auth::digest_tag_of(&digest))
}

/// Router, shared live config, history hook, and audit log. The live config is
/// the one `audience_state` authenticated and the one the reload publishes, so
/// a key write's `landed` check and a revoke receipt see the publish.
async fn stage(yaml: &str, keys: &[Key]) -> Result<Held<impl Send>, String> {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, yaml).map_err(|error| format!("write: {error}"))?;
    let evaluated = crate::config::Config::load_evaluated(Some(&path))
        .map_err(|error| format!("load: {error:?}"))?;
    let inputs = evaluated.inputs.clone();
    let (mut state, fixture) =
        crate::gateway::audience_state(&auth_config(keys), (None, None), |meta| meta).await;
    let resolved = Arc::clone(state.live_config.generation().auth());
    let store = Arc::new(ConfigHistory::open(dir.path(), Bounds::default(), 1));
    let hook = HistoryHook {
        store: Arc::clone(&store),
        config_path: path.display().to_string(),
    };
    let live = Arc::new(
        crate::config_reload::LiveConfig::with_auth(evaluated.config, resolved)
            .with_history(hook)
            .with_startup_revision(&test_record_key(), Some(inputs)),
    );
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::transparency_log::TransparencyLogConfig {
                enabled: true,
                path: dir
                    .path()
                    .join("audit.jsonl")
                    .to_string_lossy()
                    .into_owned(),
                key_id: "ui-write".to_string(),
                ..Default::default()
            },
        ))
        .map_err(|error| format!("audit log: {error}"))?,
    );
    log.keep_test_dir(Arc::clone(&dir));
    let ctx = crate::config_reload::ReloadContext::new(
        path.clone(),
        Arc::clone(&live),
        Arc::clone(&state.backends),
        FailsafeConfig::default(),
        Duration::from_secs(60),
    )
    .map_err(|error| format!("reload context: {error:?}"))?;
    {
        let unique = Arc::get_mut(&mut state).ok_or("audience state is not unique")?;
        unique.live_config = live;
        unique.config_path = Some(path.clone());
        unique.transparency_log = Some(log);
    }
    state.meta_mcp.set_reload_context(Arc::new(ctx));
    Ok(Held {
        state,
        store,
        path,
        _dir: dir,
        _fixture: fixture,
    })
}

fn revision(path: &std::path::Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("read: {error}"))?;
    Ok(crate::config_reload::FileRevision::of(&bytes)
        .as_str()
        .to_owned())
}

async fn send(
    state: Arc<crate::gateway::test_helpers::AppState>,
    method: &str,
    uri: &str,
    body: String,
) -> Result<(axum::http::StatusCode, String), String> {
    use tower::ServiceExt as _;
    let request = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", "Bearer ui-admin")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .map_err(|error| format!("request: {error}"))?;
    let response = create_router(state)
        .oneshot(request)
        .await
        .map_err(|error| format!("response: {error:?}"))?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .map_err(|error| format!("body: {error}"))?;
    Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
}

fn recorded(
    store: &ConfigHistory,
    status: axum::http::StatusCode,
    body: &str,
) -> Result<(), String> {
    if !status.is_success() {
        return Err(format!("status {status}: {body}"));
    }
    let events = store.events();
    let Some(newest) = events.last() else {
        return Err(format!("no history event after {status}: {body}"));
    };
    if newest.outcome != Outcome::Applied {
        return Err(format!(
            "outcome {:?} after {status}: {body}",
            newest.outcome
        ));
    }
    let want = Source::Ui {
        who: "ui-admin".to_string(),
    };
    if newest.source != want {
        return Err(format!(
            "source {:?} != {want:?} after {status}",
            newest.source
        ));
    }
    Ok(())
}

/// `backends_audit_tests::Audited::add`: URL-only add, 201.
async fn backend_write() -> Result<(), String> {
    let yaml = format!(
        "# keep me\nbackends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\" # first\n{}",
        auth_block(&[ADMIN])
    );
    let held = stage(&yaml, &[ADMIN]).await?;
    let (status, body) = send(
        Arc::clone(&held.state),
        "POST",
        "/ui/api/backends",
        r#"{"name":"b","url":"http://127.0.0.1:9/mcp"}"#.to_owned(),
    )
    .await?;
    recorded(&held.store, status, &body)
}

struct Clients {
    finds: Vec<DiscoveredServer>,
}

impl ScanSource for Clients {
    fn fingerprint(&self) -> Fingerprint {
        ConfigScanner::fingerprint(&[])
    }
    fn scan(&self) -> BoxFuture<'_, ClientScan> {
        let scan = ClientScan {
            finds: self.finds.clone(),
            fingerprint: self.fingerprint(),
            unreadable: Vec::new(),
        };
        Box::pin(async move { scan })
    }
    fn now(&self) -> Instant {
        Instant::now()
    }
}

fn stdio(name: &str, command: &str) -> DiscoveredServer {
    let mut server = DiscoveredServer::new(
        name.to_owned(),
        String::new(),
        DiscoverySource::ClaudeDesktop,
        crate::config::TransportConfig::Stdio {
            command: command.to_owned(),
            cwd: None,
            protocol_version: None,
        },
        ServerMetadata::default(),
    );
    server.entry_digest = format!("digest-{name}");
    server
}

/// `discovery_adopt_route_tests::an_adopt_writes_its_paired_intent_first`:
/// stdio `tool` / `npx tool`, empty env, 201.
async fn discovery_adopt() -> Result<(), String> {
    let yaml = format!(
        "# keep me\nsecrets:\n  store: files\nbackends: {{}}\n{}",
        auth_block(&[ADMIN])
    );
    let held = stage(&yaml, &[ADMIN]).await?;
    let source: Arc<dyn ScanSource> = Arc::new(Clients {
        finds: vec![stdio("tool", "npx tool")],
    });
    let cache = Arc::new(crate::discovery::listing::DiscoveryCache::new(source));
    held.state.meta_mcp.set_discovery_cache(Arc::clone(&cache));
    let (listing, _) = cache
        .listing()
        .await
        .map_err(|_| "discovery listing timed out".to_string())?;
    let find_id = listing
        .finds
        .iter()
        .find(|find| find.name == "tool")
        .map(|find| find.find_id.clone())
        .ok_or("tool not listed")?;
    let revision = revision(&held.path)?;
    let body = serde_json::json!({"find_id": find_id, "revision": revision}).to_string();
    let (status, text) = send(
        Arc::clone(&held.state),
        "POST",
        "/ui/api/discovery/adopt",
        body,
    )
    .await?;
    recorded(&held.store, status, &text)
}

/// `keys_create_tests::p8b_a_minimal_body_writes_the_defaults`: name, backends, revision.
async fn key_create() -> Result<(), String> {
    let yaml = format!(
        "secrets:\n  store: files\nbackends: {{}}\n{}",
        auth_block(&[ADMIN])
    );
    let held = stage(&yaml, &[ADMIN]).await?;
    let revision = revision(&held.path)?;
    let body = serde_json::json!({
        "name": "plain",
        "backends": ["*"],
        "revision": revision,
    })
    .to_string();
    let (status, text) = send(Arc::clone(&held.state), "POST", "/ui/api/keys", body).await?;
    recorded(&held.store, status, &text)
}

/// `keys_revoke_writer_tests::revoke_writes_through_the_audited_writer` and
/// `keys_revoke_target_tests::target_setup`: DELETE target with its tag.
async fn key_revoke() -> Result<(), String> {
    let keys = [
        ADMIN,
        Key {
            name: "target",
            secret: "target-secret",
            admin: false,
        },
    ];
    let yaml = format!(
        "secrets:\n  store: files\nbackends: {{}}\n{}",
        auth_block(&keys)
    );
    let held = stage(&yaml, &keys).await?;
    let revision = revision(&held.path)?;
    let body = serde_json::json!({
        "revision": revision,
        "expected_key_tag": tag("target-secret")?,
    })
    .to_string();
    let (status, text) = send(
        Arc::clone(&held.state),
        "DELETE",
        "/ui/api/keys/target",
        body,
    )
    .await?;
    recorded(&held.store, status, &text)
}

/// `settings_support_tests` environment edit (`saved_body` / `set`) on a
/// non-refusing reload. Auth is on so the bearer is `ui-admin`.
async fn settings_save() -> Result<(), String> {
    let yaml = format!(
        "# operator's note\nenvironment: \"dev\" # where\nsecrets:\n  store: files\n{}backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\" # first\n    owner: \"team\"\n",
        auth_block(&[ADMIN])
    );
    let held = stage(&yaml, &[ADMIN]).await?;
    let revision = revision(&held.path)?;
    let body = serde_json::json!({
        "base_revision": revision,
        "fields": [{"field": "environment", "value": {"set": "prod"}}],
    })
    .to_string();
    let (status, text) = send(Arc::clone(&held.state), "POST", "/ui/api/settings", body).await?;
    recorded(&held.store, status, &text)
}

/// Every UI write route, named, so one failure list is the whole table.
/// One route case: its name and the request it runs.
#[cfg(feature = "webui")]
type Case = (
    &'static str,
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>>,
);

#[cfg(feature = "webui")]
#[tokio::test]
async fn h1r_each_ui_write_route_records_its_admin() {
    let cases: Vec<Case> = vec![
        ("backend-write", Box::pin(backend_write())),
        ("discovery-adopt", Box::pin(discovery_adopt())),
        ("key-create", Box::pin(key_create())),
        ("key-revoke", Box::pin(key_revoke())),
        ("settings-save", Box::pin(settings_save())),
    ];
    let mut failed = Vec::<&str>::new();
    let mut why = Vec::new();
    for (name, run) in cases {
        if let Err(reason) = run.await {
            why.push(format!("{name}: {reason}"));
            failed.push(name);
        }
    }
    assert_eq!(failed, Vec::<&str>::new(), "{why:?}");
}
