// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::{Bounds, ConfigHistory, Event, HistoryHook, Outcome, Snapshot, Source, StoredFile};
use crate::backend::BackendRegistry;
use crate::config::{Config, FailsafeConfig};
use crate::config_reload::reload_context::replace::{
    Expected, Replace, Replaced, replace_detached,
};
use crate::config_reload::revision::{ConsumedInput, ConsumedSource, RawInputs};
use crate::config_reload::{LiveConfig, ReloadContext};
use crate::gateway::record_principal::test_record_key;
use crate::gateway::test_helpers::write_owner_only;

const ONE_BACKEND: &str = "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";
const TWO_BACKENDS: &str = "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";
const THREE_BACKENDS: &str = "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n  c:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";
const PORT_A: &str = "server:\n  port: 39001\n";
const PORT_B: &str = "server:\n  port: 39002\n";
const MARKER: &[u8] = b"GWMARK-7f3a";

struct Rig {
    dir: tempfile::TempDir,
    path: PathBuf,
    ctx: Arc<ReloadContext>,
    store: Arc<ConfigHistory>,
}

fn rig(yaml: &str) -> Rig {
    let dir = tempfile::tempdir().expect("tempdir");
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

fn hold_at(
    dir: &Path,
    raw: RawInputs,
    config_path: String,
    grants_path: Option<String>,
    config: Config,
) -> (LiveConfig, Arc<ConfigHistory>) {
    let store = Arc::new(ConfigHistory::open(dir, Bounds::default(), 1));
    let hook = HistoryHook {
        store: Arc::clone(&store),
        config_path,
        grants_path,
    };
    let live = LiveConfig::new(config)
        .with_history(hook)
        .with_startup_revision(&test_record_key(), Some(raw));
    (live, store)
}

fn replace_with(bytes: &'static str) -> Replace {
    Replace {
        expected: Expected::Any,
        compute: Box::new(move |_| {
            Ok(crate::config_persistence::keyedit::Template::plain(
                bytes.as_bytes().to_vec(),
            ))
        }),
        replaced: Replaced::Discard,
        secrets: None,
    }
}

fn snapshot_revisions(store: &ConfigHistory) -> Vec<String> {
    store
        .snapshots()
        .into_iter()
        .map(|snapshot| snapshot.revision)
        .collect()
}

fn file_paths(snapshot: &Snapshot) -> Vec<String> {
    snapshot
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect()
}

fn stored<'s>(snapshot: &'s Snapshot, path: &str) -> Option<&'s StoredFile> {
    snapshot.files.iter().find(|file| file.path == path)
}

fn event_keys(event: &Event) -> Vec<String> {
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

fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}

#[tokio::test]
async fn h1_start_and_file_reloads_are_recorded_by_source() {
    let rig = rig(ONE_BACKEND);
    write_owner_only(&rig.path, TWO_BACKENDS).expect("add a backend");
    rig.ctx
        .reload_outcome()
        .await
        .expect("the file reload applies");
    replace_detached(
        Arc::clone(&rig.ctx),
        replace_with(THREE_BACKENDS),
        Duration::from_secs(5),
    )
    .await
    .expect("the replace applies");

    let events = rig.store.events();
    let first_two: Vec<Source> = events
        .iter()
        .take(2)
        .map(|event| event.source.clone())
        .collect();
    assert_eq!(first_two, vec![Source::Start, Source::File]);
    assert!(matches!(
        events.get(2).map(|event| &event.source),
        Some(Source::Ui { .. })
    ));
    assert_eq!(
        events.iter().map(|event| event.outcome).collect::<Vec<_>>(),
        vec![Outcome::Applied, Outcome::Applied, Outcome::Applied]
    );
    let revisions: Vec<Option<String>> =
        events.iter().map(|event| event.revision.clone()).collect();
    let mut distinct = revisions.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(revisions.len(), 3);
    assert_eq!(distinct.len(), 3);
    assert!(distinct.iter().all(Option::is_some));
    let snapshot_revisions: Vec<Option<String>> = rig
        .store
        .snapshots()
        .iter()
        .map(|snapshot| Some(snapshot.revision.clone()))
        .collect();
    assert_eq!(snapshot_revisions, revisions);
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
        rig.ctx.live_config.running_revision().map(str::to_string)
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

#[tokio::test]
async fn h3_a_refused_reload_stores_no_bytes() {
    let rig = rig(ONE_BACKEND);
    // An applied edit first, so the version still served is not the one the
    // process started with: the row says which of the two a refusal names.
    write_owner_only(&rig.path, TWO_BACKENDS).expect("add a backend");
    rig.ctx.reload_outcome().await.expect("the edit applies");
    let served = rig
        .ctx
        .live_config
        .applied_now()
        .map(|applied| applied.revision.clone());
    assert_ne!(
        served.as_deref(),
        rig.ctx.live_config.running_revision(),
        "the premise: the served version moved off the startup one"
    );
    let before_snapshots = snapshot_revisions(&rig.store);
    write_owner_only(&rig.path, "server:\n  port: not-a-number\n").expect("write a refusal");
    let refused = rig.ctx.reload_outcome().await;
    assert!(refused.is_err(), "the reload refused: {refused:?}");

    let newest = rig.store.events().last().cloned();
    assert_eq!(
        newest.as_ref().map(|event| event.outcome),
        Some(Outcome::Refused)
    );
    assert_eq!(
        newest.as_ref().and_then(|event| event.revision.clone()),
        None
    );
    assert_eq!(
        newest.as_ref().and_then(|event| {
            event
                .still_running
                .as_ref()
                .map(|running| running.revision.clone())
        }),
        served
    );
    let mut expected_keys = [
        "at",
        "source",
        "outcome",
        "revision",
        "unchanged",
        "still_running",
    ]
    .map(str::to_string)
    .to_vec();
    expected_keys.sort();
    assert_eq!(newest.as_ref().map(event_keys), Some(expected_keys));
    assert_eq!(snapshot_revisions(&rig.store), before_snapshots);
}

#[test]
fn h5_a_snapshot_holds_every_operator_file_with_presence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let gateway = path_string(&dir.path().join("gateway.yaml"));
    let env_path = path_string(&dir.path().join("app.env"));
    let grants_path = path_string(&dir.path().join("grants.yaml"));
    let gateway_bytes = b"gateway: yes\n".to_vec();
    let env_bytes = b"K=1\n".to_vec();
    let grants_bytes = b"grant: yes\n".to_vec();
    let raw = RawInputs {
        gateway_yaml: gateway_bytes.clone(),
        grants: Some(grants_bytes.clone()),
        env_files: vec![(env_path.clone(), Some(env_bytes.clone()))],
        ..RawInputs::default()
    };
    let (live, store) = hold_at(
        dir.path(),
        raw,
        gateway.clone(),
        Some(grants_path.clone()),
        Config::default(),
    );
    live.set_inputs(
        RawInputs {
            gateway_yaml: gateway_bytes,
            grants: None,
            env_files: vec![(env_path.clone(), None)],
            ..RawInputs::default()
        },
        &[],
    );

    let expected = vec![gateway, env_path.clone(), grants_path.clone()];
    let lists: Vec<Vec<String>> = store.snapshots().iter().map(file_paths).collect();
    assert_eq!(lists, vec![expected.clone(), expected]);
    let snapshots = store.snapshots();
    let newer = snapshots.last().cloned();
    let older = snapshots.iter().rev().nth(1).cloned();
    assert_eq!(
        older
            .as_ref()
            .and_then(|snapshot| stored(snapshot, &env_path))
            .map(|file| file.bytes.clone()),
        Some(Some(env_bytes))
    );
    assert_eq!(
        newer
            .as_ref()
            .and_then(|snapshot| stored(snapshot, &env_path))
            .map(|file| file.bytes.clone()),
        Some(None)
    );
    assert_eq!(
        newer
            .as_ref()
            .and_then(|snapshot| stored(snapshot, &grants_path))
            .map(|file| file.bytes.clone()),
        Some(Some(grants_bytes))
    );
}

/// Every string and byte array in the history file, as bytes, plus the raw
/// text: what a reader of the file could recover, whichever JSON encoding the
/// store picks for bytes.
fn history_file_bytes(dir: &Path) -> Vec<u8> {
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
    );
    live.set_inputs(with_marker(token(b"rotated")), &[]);
    let published = live
        .applied_now()
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

#[test]
fn h6_consumed_values_are_never_stored() {
    use rand::RngExt;
    let secret = format!("s3cr3t-{}", rand::rng().random::<u64>());
    let dir = tempfile::tempdir().expect("tempdir");
    let (live, _store) = hold_at(
        dir.path(),
        with_marker(token(secret.as_bytes())),
        path_string(&dir.path().join("gateway.yaml")),
        None,
        Config::default(),
    );
    let other_dir = tempfile::tempdir().expect("tempdir");
    let (other, _other_store) = hold_at(
        other_dir.path(),
        with_marker(token(b"other-value")),
        path_string(&other_dir.path().join("gateway.yaml")),
        None,
        Config::default(),
    );
    assert_ne!(
        live.running_revision(),
        other.running_revision(),
        "the premise: the consumed value is in the revision"
    );
    // A publish after startup, so a store that records only from here on
    // still has written its file.
    live.set_inputs(with_marker(token(secret.as_bytes())), &[]);

    let stored = history_file_bytes(dir.path());
    assert!(
        holds(&stored, MARKER),
        "the search finds a planted file value"
    );
    assert!(
        !holds(&stored, secret.as_bytes()),
        "a consumed value is not stored"
    );
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
