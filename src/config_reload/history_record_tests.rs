// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::{Bounds, ConfigHistory, Event, HistoryHook, Outcome, Snapshot, Source, StoredFile};
use crate::backend::BackendRegistry;
use crate::config::{Config, FailsafeConfig};
use crate::config_reload::reload_context::replace::{Expected, Replace, Replaced, StatusChange};
use crate::config_reload::revision::{ConsumedInput, ConsumedSource, RawInputs};
use crate::config_reload::{LiveConfig, ReloadContext};
use crate::gateway::record_principal::test_record_key;
use crate::gateway::test_helpers::write_owner_only;

pub(super) const ONE_BACKEND: &str = "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";
pub(super) const TWO_BACKENDS: &str = "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";
pub(super) const THREE_BACKENDS: &str = "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n  c:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";
const PORT_A: &str = "server:\n  port: 39001\n";
const PORT_B: &str = "server:\n  port: 39002\n";
pub(super) const MARKER: &[u8] = b"GWMARK-7f3a";

pub(super) struct Rig {
    /// Shared, so a kept dir (`crate::test_dir_keep`) can outlive the rig in a
    /// store a late worker still holds.
    pub(super) dir: Arc<tempfile::TempDir>,
    pub(super) path: PathBuf,
    pub(super) ctx: Arc<ReloadContext>,
    pub(super) store: Arc<ConfigHistory>,
}

pub(super) fn rig(yaml: &str) -> Rig {
    rig_in(tempfile::tempdir().expect("tempdir"), yaml)
}

/// [`rig`] in `dir`, so a test can install seams for it before the store opens.
pub(super) fn rig_in(dir: impl Into<Arc<tempfile::TempDir>>, yaml: &str) -> Rig {
    let dir = dir.into();
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, yaml).expect("write config");
    // The startup inputs as a real start reads them, process overrides
    // included, so an untouched reload digests the same inputs on any host.
    let started = Config::load_evaluated(Some(&path)).expect("config loads");
    let (live, store) = hold_at(
        dir.path(),
        started.inputs,
        path.display().to_string(),
        None,
        started.config,
        None,
    );
    let ctx = Arc::new(
        ReloadContext::new(
            path.clone(),
            Arc::new(live),
            Arc::new(BackendRegistry::new()),
            FailsafeConfig::default(),
            Duration::from_secs(60),
        )
        .expect("the registry pairs with the config"),
    );
    Rig {
        dir,
        path,
        ctx,
        store,
    }
}

pub(super) fn hold_at(
    dir: &Path,
    raw: RawInputs,
    config_path: String,
    // Grants versions are recorded separately; the argument stays for its callers.
    _grants_path: Option<String>,
    config: Config,
    pause: Option<Arc<dyn Fn() + Send + Sync>>,
) -> (LiveConfig, Arc<ConfigHistory>) {
    let store = Arc::new(ConfigHistory::open(dir, Bounds::default(), 1));
    let hook = HistoryHook {
        store: Arc::clone(&store),
        config_path,
    };
    let mut live = LiveConfig::new(config).with_history(hook);
    if let Some(pause) = pause {
        live = live.with_record_pause(pause);
    }
    let live = live.with_startup_revision(&test_record_key(), Some(raw));
    (live, store)
}

pub(super) fn replace_with(bytes: &'static str) -> Replace {
    Replace {
        expected: Expected::Any,
        compute: Box::new(move |_| {
            Ok(crate::config_persistence::keyedit::Template::plain(
                bytes.as_bytes().to_vec(),
            ))
        }),
        replaced: Replaced::Discard,
        secrets: None,
        status_change: StatusChange::Refuse,
    }
}

pub(super) fn snapshot_revisions(store: &ConfigHistory) -> Vec<String> {
    store
        .snapshots()
        .into_iter()
        .map(|snapshot| snapshot.revision)
        .collect()
}

pub(super) fn file_paths(snapshot: &Snapshot) -> Vec<String> {
    snapshot
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect()
}

pub(super) fn stored<'s>(snapshot: &'s Snapshot, path: &str) -> Option<&'s StoredFile> {
    snapshot.files.iter().find(|file| file.path == path)
}

pub(super) fn event_keys(event: &Event) -> Vec<String> {
    let value = serde_json::to_value(event).expect("event serializes");
    let mut keys: Vec<String> = value
        .as_object()
        .expect("event json is an object")
        .keys()
        .cloned()
        .collect();
    keys.sort();
    keys
}

pub(super) fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

pub(super) fn path_string(path: &Path) -> String {
    path.display().to_string()
}

#[tokio::test]
async fn h2_an_unchanged_reload_is_an_event_without_a_snapshot() {
    let rig = rig(ONE_BACKEND);
    let before_events = rig.store.events().len();
    let before_snapshots = snapshot_revisions(&rig.store);
    rig.ctx
        .reload_outcome()
        .await
        .expect("an untouched file reloads");
    assert_eq!(rig.store.events().len(), before_events + 1);
    let newest = rig.store.events().last().cloned();
    assert_eq!(newest.as_ref().map(|event| event.unchanged), Some(true));
    assert_eq!(
        newest.as_ref().and_then(|event| event.revision.clone()),
        rig.ctx.live_config.running_revision()
    );
    assert_eq!(snapshot_revisions(&rig.store), before_snapshots);

    let before_edit = snapshot_revisions(&rig.store);
    write_owner_only(&rig.path, TWO_BACKENDS).expect("add a backend");
    rig.ctx
        .reload_outcome()
        .await
        .expect("the edited file reloads");
    let after_edit = snapshot_revisions(&rig.store);
    assert_eq!(after_edit.len(), before_edit.len() + 1);
    let newest = rig.store.events().last().cloned();
    assert_eq!(
        after_edit.last().cloned(),
        newest.as_ref().and_then(|event| event.revision.clone())
    );
}

/// Every string and byte array in the history file, as bytes, plus the raw
/// text: what a reader of the file could recover, whichever JSON encoding the
/// store picks for bytes.
pub(super) fn history_file_bytes(dir: &Path) -> Vec<u8> {
    fn visible(value: &serde_json::Value, out: &mut Vec<u8>) {
        match value {
            serde_json::Value::String(text) => out.extend_from_slice(text.as_bytes()),
            serde_json::Value::Array(items) => {
                let bytes: Option<Vec<u8>> = items
                    .iter()
                    .map(|item| item.as_u64().and_then(|n| u8::try_from(n).ok()))
                    .collect();
                match bytes {
                    Some(bytes) if !bytes.is_empty() => out.extend(bytes),
                    _ => items.iter().for_each(|item| visible(item, out)),
                }
            }
            serde_json::Value::Object(map) => {
                for (key, item) in map {
                    out.extend_from_slice(key.as_bytes());
                    visible(item, out);
                }
            }
            _ => {}
        }
    }
    let text = std::fs::read(dir.join(ConfigHistory::FILE)).unwrap_or_default();
    let value = serde_json::from_slice(&text).unwrap_or(serde_json::Value::Null);
    let mut out = text;
    visible(&value, &mut out);
    out
}

fn with_marker(consumed: Vec<ConsumedInput<Vec<u8>>>) -> RawInputs {
    RawInputs {
        gateway_yaml: b"marker: GWMARK-7f3a\n".to_vec(),
        consumed,
        ..RawInputs::default()
    }
}

fn token(value: &[u8]) -> Vec<ConsumedInput<Vec<u8>>> {
    vec![ConsumedInput {
        source: ConsumedSource::EnvVar,
        name: "TOKEN".into(),
        value: value.to_vec(),
    }]
}

/// The premise h6 rests on: an applied publish leaves the history file on
/// disk, holding the published version, so h6 cannot pass on a missing file.
#[test]
fn h6a_a_publish_leaves_the_history_file_with_its_version() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (live, _store) = hold_at(
        dir.path(),
        with_marker(Vec::new()),
        path_string(&dir.path().join("gateway.yaml")),
        None,
        Config::default(),
        None,
    );
    live.set_inputs(with_marker(token(b"rotated")), &[]);
    let published = live
        .applied_now()
        .published
        .map(|applied| applied.revision.clone())
        .expect("a keyed holder publishes a revision");

    assert!(
        dir.path().join(ConfigHistory::FILE).exists(),
        "data_dir/config-history.json exists"
    );
    let stored = history_file_bytes(dir.path());
    assert!(holds(&stored, published.as_bytes()), "it holds {published}");
    assert!(holds(&stored, MARKER), "it holds the gateway.yaml bytes");
}

#[tokio::test]
async fn h9_pending_restart_is_recorded() {
    let rig = rig(PORT_A);
    write_owner_only(&rig.path, PORT_B).expect("change the port");
    let outcome = rig
        .ctx
        .reload_outcome()
        .await
        .expect("the port reload applies");
    assert_eq!(outcome.pending_restart_fields, vec!["server"]);
    assert_eq!(
        rig.store
            .snapshots()
            .last()
            .map(|snapshot| snapshot.pending_restart.clone()),
        Some(vec!["server".to_string()])
    );

    let before_unchanged = snapshot_revisions(&rig.store);
    rig.ctx
        .reload_outcome()
        .await
        .expect("an unchanged reload applies");
    assert_eq!(snapshot_revisions(&rig.store), before_unchanged);
    assert_eq!(
        rig.store
            .snapshots()
            .last()
            .map(|snapshot| snapshot.pending_restart.clone()),
        Some(vec!["server".to_string()])
    );

    let reopened = ConfigHistory::open(rig.dir.path(), Bounds::default(), 1);
    assert_eq!(
        reopened
            .snapshots()
            .last()
            .map(|snapshot| snapshot.pending_restart.clone()),
        Some(vec!["server".to_string()])
    );
}

/// H8: `gateway_reload_config` through the tool dispatch records source `ui`
/// with the caller's account. `AuditWho::from_caller` copies `api_key_name`,
/// so a caller named `ops-admin` has account `ops-admin`. Red against the
/// stub, which records `who: ""`.
#[tokio::test]
async fn h8_a_meta_tool_reload_records_its_caller() {
    use std::borrow::Cow;

    use crate::gateway::authz::{AdminStanding, AllowAll};
    use crate::gateway::test_helpers::{Authentication, MetaMcp, MetaMcpCallerContext};
    use crate::protocol::{JsonRpcResponse, RequestId};

    let rig = rig(ONE_BACKEND);
    let meta = MetaMcp::new(Arc::clone(&rig.ctx.registry));
    meta.set_reload_context(Arc::clone(&rig.ctx));
    write_owner_only(&rig.path, TWO_BACKENDS).expect("add a backend");

    let caller = MetaMcpCallerContext {
        signing: None,
        execution: None,
        credential_principal: None,
        record_principal: crate::gateway::record_principal::RecordPrincipal::none(),
        authentication: Authentication::Authenticated,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
        is_modern: false,
        protocol_revision: None,
        authorizer: &AllowAll,
        api_key_name: Some("ops-admin"),
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        stdio_nonce: None,
        caller_key: None,
        verified_identity: None,
        admin: AdminStanding::Gateway,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        task: None,
        era: crate::protocol::meta::Era::Legacy,
        channel: &crate::gateway::input_bridge::NoClientChannel,
        generation: None,
    };
    let response: JsonRpcResponse = meta
        .dispatch_below_gate(
            RequestId::Number(1),
            "gateway_reload_config",
            Cow::Owned(serde_json::json!({})),
            None,
            &caller,
            false,
        )
        .await;
    assert!(
        response.error.is_none(),
        "dispatch ran the reload: {:?}",
        response.error
    );
    let newest = rig.store.events().last().cloned().expect("a reload event");
    assert_eq!(newest.outcome, Outcome::Applied);
    assert_eq!(
        newest.source,
        Source::Ui {
            who: "ops-admin".to_string()
        }
    );
}

/// H8b: `POST /ui/api/reload` as the configured admin key `ui-admin` records
/// that key's account. The handler `reload` takes a `Guard` and does not pass
/// `caller_who`; the stub records `who: ""`. The history hook is the one
/// `Gateway::history_hook` attaches when a config path is set and grants are
/// off, on the reload context's `LiveConfig` (the store the reload publishes).
#[cfg(feature = "webui")]
#[tokio::test]
async fn h8b_a_ui_reload_records_its_caller() {
    use axum::body::to_bytes;
    use axum::http::StatusCode;
    use tower::ServiceExt;

    use crate::config::{ApiKeyConfig, AuthConfig, FailsafeConfig};
    use crate::gateway::test_helpers::create_router;

    const KEY: &str = "ui-admin";
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, ONE_BACKEND).expect("write config");
    let started = Config::load_evaluated(Some(&path)).expect("config loads");
    let (live, store) = hold_at(
        dir.path(),
        started.inputs,
        path.display().to_string(),
        None,
        started.config,
        None,
    );
    let auth = AuthConfig {
        enabled: true,
        api_keys: vec![ApiKeyConfig {
            key: None,
            key_sha256: Some(crate::config::api_key_digest_spec(KEY.as_bytes())),
            expires_at: None,
            name: KEY.to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: true,
            kind: crate::config::ApiKeyKind::Shared,
            ..Default::default()
        }],
        ..Default::default()
    };
    let key_server: Option<Arc<crate::key_server::KeyServer>> = None;
    let agents: Option<Arc<crate::gateway::AgentRegistry>> = None;
    let (state, _fixture) =
        crate::gateway::audience_state(&auth, (key_server, agents), |meta| meta).await;
    let ctx = ReloadContext::new(
        path.clone(),
        Arc::new(live),
        Arc::clone(&state.backends),
        FailsafeConfig::default(),
        Duration::from_secs(60),
    )
    .expect("the registry pairs with the config");
    state.meta_mcp.set_reload_context(Arc::new(ctx));
    write_owner_only(&path, TWO_BACKENDS).expect("add a backend");

    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/ui/api/reload")
        .header("authorization", format!("Bearer {KEY}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from("{}"))
        .expect("request");
    let response = create_router(state)
        .oneshot(request)
        .await
        .expect("response");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let newest = store.events().last().cloned().expect("a reload event");
    assert_eq!(newest.outcome, Outcome::Applied);
    assert_eq!(
        newest.source,
        Source::Ui {
            who: "ui-admin".to_string()
        }
    );
}
