// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use super::record_tests::{
    self, MARKER, ONE_BACKEND, Rig, THREE_BACKENDS, TWO_BACKENDS, event_keys, file_paths,
    history_file_bytes, hold_at, holds, path_string, replace_with, rig, stored,
};
use super::{Outcome, Source};
use crate::backend::BackendRegistry;
use crate::config::{Config, FailsafeConfig, LiveEnv};
use crate::config_reload::reload_context::replace::{Audit, replace_audited};
use crate::config_reload::{IdentityGrantSink, ReloadContext};
use crate::gateway::test_helpers::write_owner_only;
use crate::identity_grants::LocalIdentityGrantStore;

const H6_FLAG: &str = "H6_SCENARIO";
const H6_SCENARIO: &str = "config_reload::history::reload_tests::h6_consumed_scenario";
const H6_PLANTED: &str = "H6_PLANTED_FILE";
const GRANTS_EMPTY: &str = "schema_version: identity_grants.v1\ngrants: []\n";
const REFUSED_PORT: &str = "server:\n  port: not-a-number\n";

struct Started {
    path: std::path::PathBuf,
    ctx: Arc<ReloadContext>,
    store: Arc<super::ConfigHistory>,
    env: Arc<LiveEnv>,
}

/// A real start: `Config::load_evaluated`, then the same `LiveEnv` on the
/// reload context, so a later reload reuses the recorded env paths.
fn start(
    dir: &std::path::Path,
    yaml: &str,
    grants_path: Option<String>,
    grants_bytes: Option<Vec<u8>>,
    pause: Option<Arc<dyn Fn() + Send + Sync>>,
    sink: Option<Arc<IdentityGrantSink>>,
) -> Started {
    let path = dir.join("gateway.yaml");
    write_owner_only(&path, yaml).expect("write config");
    let mut evaluated = Config::load_evaluated(Some(&path)).expect("config loads");
    let env = Arc::new(evaluated.live_env());
    if let Some(bytes) = grants_bytes {
        env.set_startup_grants(Some(bytes));
    }
    let raw = env.take_startup_inputs().expect("startup inputs");
    let (live, store) = hold_at(
        dir,
        raw,
        path.display().to_string(),
        grants_path,
        evaluated.config,
        pause,
    );
    let ctx = ReloadContext::new(
        path.clone(),
        Arc::new(live),
        Arc::new(BackendRegistry::new()),
        FailsafeConfig::default(),
        Duration::from_secs(60),
    )
    .expect("the registry pairs with the config")
    .with_env(Arc::clone(&env));
    let ctx = match sink {
        Some(sink) => ctx.with_identity_grant_sink(sink),
        None => ctx,
    };
    Started {
        path,
        ctx: Arc::new(ctx),
        store,
        env,
    }
}

fn grant_sink(path: &std::path::Path) -> Arc<IdentityGrantSink> {
    Arc::new(IdentityGrantSink::new(
        Arc::new(parking_lot::RwLock::new(LocalIdentityGrantStore::default())),
        Arc::new(AtomicU64::new(0)),
        path.to_path_buf(),
    ))
}

#[tokio::test]
async fn h1_start_file_and_ui_writes_are_recorded_by_source_and_caller() {
    let rig = rig(ONE_BACKEND);
    write_owner_only(&rig.path, TWO_BACKENDS).expect("add a backend");
    rig.ctx
        .reload_outcome()
        .await
        .expect("the file reload applies");
    replace_audited(
        Arc::clone(&rig.ctx),
        replace_with(THREE_BACKENDS),
        Audit::Off,
        Source::Ui {
            who: "admin-a".to_string(),
        },
        Duration::from_secs(5),
    )
    .await
    .expect("the replace applies");

    let events = rig.store.events();
    let sources: Vec<Source> = events.iter().map(|event| event.source.clone()).collect();
    assert_eq!(
        sources,
        vec![
            Source::Start,
            Source::File,
            Source::Ui {
                who: "admin-a".to_string(),
            },
        ]
    );
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
async fn h1a_an_env_file_edit_seen_by_the_poll_is_its_own_version() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env_path = dir.path().join("app.env");
    write_owner_only(&env_path, "K=1\n").expect("env file");
    let env_spelling = path_string(&env_path);
    let yaml = format!("env_files:\n  - '{env_spelling}'\n");
    let started = start(dir.path(), &yaml, None, None, None, None);
    write_owner_only(&env_path, "K=2\n").expect("edit the env file");

    let mut poller = super::super::env_poll::EnvPoller::new(
        Arc::clone(&started.env),
        Arc::default(),
        started.path.clone(),
    );
    let trigger = poller.tick(Duration::from_secs(5)).await;
    let found = match trigger {
        Some(super::super::watcher::ReloadTrigger::EnvFile(path)) => Some(path),
        _ => None,
    };
    assert_eq!(found.as_deref(), Some(env_path.as_path()));

    let before = started.store.events().len();
    let previous = started
        .store
        .events()
        .last()
        .and_then(|event| event.revision.clone());
    let gateway = path_string(&started.path);
    let previous_gateway = started
        .store
        .snapshots()
        .last()
        .and_then(|snapshot| stored(snapshot, &gateway))
        .and_then(|file| file.bytes.clone());
    started
        .ctx
        .reload_outcome()
        .await
        .expect("the env-file reload applies");

    assert_eq!(
        started.store.events().len(),
        before + 1,
        "an env-file edit under an unchanged config is one new event"
    );
    let newest = started.store.events().last().cloned();
    assert_eq!(
        newest.as_ref().map(|event| event.source.clone()),
        Some(Source::File)
    );
    assert_ne!(
        newest.as_ref().and_then(|event| event.revision.clone()),
        previous
    );
    let snapshots = started.store.snapshots();
    let recorded = snapshots
        .last()
        .and_then(|snapshot| stored(snapshot, &env_spelling));
    assert_eq!(
        recorded.map(|file| file.bytes.clone()),
        Some(Some(b"K=2\n".to_vec()))
    );
    assert_eq!(
        snapshots
            .last()
            .and_then(|snapshot| stored(snapshot, &gateway))
            .map(|file| file.bytes.clone()),
        previous_gateway
    );
}

#[tokio::test]
async fn h3_a_refused_reload_is_an_event_without_bytes_naming_its_line() {
    let rig: Rig = rig(ONE_BACKEND);
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
    let before_snapshots = record_tests::snapshot_revisions(&rig.store);
    write_owner_only(&rig.path, REFUSED_PORT).expect("write a refusal");
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
    assert_eq!(
        newest.as_ref().map(event_keys),
        Some(
            ["at", "location", "outcome", "source", "still_running"]
                .map(str::to_string)
                .to_vec()
        )
    );
    assert_eq!(newest.as_ref().and_then(|event| event.location), Some(2));
    let since = newest
        .as_ref()
        .and_then(|event| event.still_running.as_ref())
        .map(|running| running.since);
    let held_at = rig
        .store
        .snapshots()
        .iter()
        .find(|snapshot| Some(snapshot.revision.as_str()) == served.as_deref())
        .map(|snapshot| snapshot.at);
    assert_eq!(since, held_at);
    assert_eq!(
        record_tests::snapshot_revisions(&rig.store),
        before_snapshots
    );
}

#[tokio::test]
async fn h5_a_version_holds_every_operator_file_with_presence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env_path = dir.path().join("app.env");
    let grants_file = dir.path().join("grants.yaml");
    write_owner_only(&env_path, "K=1\n").expect("env file");
    write_owner_only(&grants_file, GRANTS_EMPTY).expect("grants file");
    let env_spelling = path_string(&env_path);
    let grants_spelling = path_string(&grants_file);
    let yaml = format!(
        "env_files:\n  - '{env_spelling}'\nsecurity:\n  identity_grants:\n    enabled: true\n    path: '{grants_spelling}'\n"
    );
    let started = start(
        dir.path(),
        &yaml,
        Some(grants_spelling.clone()),
        Some(GRANTS_EMPTY.as_bytes().to_vec()),
        None,
        None,
    );
    std::fs::remove_file(&env_path).expect("delete the env file");
    started
        .ctx
        .reload_outcome()
        .await
        .expect("a missing env file reloads");

    let gateway = path_string(&started.path);
    let expected = vec![gateway, env_spelling.clone(), grants_spelling.clone()];
    let lists: Vec<Vec<String>> = started.store.snapshots().iter().map(file_paths).collect();
    assert_eq!(lists, vec![expected.clone(), expected]);
    let snapshots = started.store.snapshots();
    let newer = snapshots.last();
    let older = snapshots.iter().rev().nth(1);
    assert_eq!(
        older
            .and_then(|snapshot| stored(snapshot, &env_spelling))
            .map(|file| file.bytes.clone()),
        Some(Some(b"K=1\n".to_vec()))
    );
    assert_eq!(
        newer
            .and_then(|snapshot| stored(snapshot, &env_spelling))
            .map(|file| file.bytes.clone()),
        Some(None)
    );
    assert_eq!(
        newer
            .and_then(|snapshot| stored(snapshot, &grants_spelling))
            .map(|file| file.bytes.clone()),
        Some(Some(GRANTS_EMPTY.as_bytes().to_vec()))
    );
}

#[tokio::test]
async fn h6_no_consumed_value_reaches_the_history() {
    use rand::RngExt;
    let p1 = format!("p1-{}", rand::rng().random::<u128>());
    let p2 = format!("p2-{}", rand::rng().random::<u128>());
    let p3 = format!("p3-{}", rand::rng().random::<u128>());
    let mut nested = tokio::process::Command::new(std::env::current_exe().expect("test binary"));
    nested
        .args(["--exact", H6_SCENARIO, "--nocapture"])
        .env(H6_FLAG, "1")
        .env("MCP_GATEWAY_BACKENDS__A__DESCRIPTION", &p1)
        .env("H6_TOKEN", &p2)
        .env(H6_PLANTED, &p3)
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(60), nested.output())
        .await
        .expect("the scenario finished within the limit")
        .expect("run the consumed-value scenario");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains(H6_SCENARIO),
        "the nested filter did not run the scenario; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "consumed-value scenario failed; stdout={stdout:?} stderr={stderr:?}"
    );
}

#[tokio::test]
async fn h6_consumed_scenario() {
    if std::env::var_os(H6_FLAG).is_none() {
        return;
    }
    let p1 = std::env::var("MCP_GATEWAY_BACKENDS__A__DESCRIPTION").expect("p1");
    let p2 = std::env::var("H6_TOKEN").expect("p2");
    let p3 = std::env::var(H6_PLANTED).expect("p3");
    let secrets = tempfile::tempdir().expect("secret dir");
    let secret_path = secrets.path().join("h6.secret");
    write_owner_only(&secret_path, format!("{p3}\n")).expect("secret");
    let secret_spelling = path_string(&secret_path);
    let yaml = format!(
        "server:\n  metrics_token: 'file:{secret_spelling}'\nbackends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n    headers:\n      X-Tok: \"${{H6_TOKEN}}\"\n# GWMARK-7f3a\n"
    );
    let rig = rig(&yaml);
    let edited = format!(
        "server:\n  metrics_token: 'file:{secret_spelling}'\nbackends:\n  a:\n    http_url: \"http://127.0.0.1:8/mcp\"\n    headers:\n      X-Tok: \"${{H6_TOKEN}}\"\n# GWMARK-7f3a\n"
    );
    write_owner_only(&rig.path, &edited).expect("edit the config");
    rig.ctx.reload_outcome().await.expect("the edit applies");

    let loaded = Config::load_evaluated(Some(&rig.path)).expect("the edited config loads");
    let names: Vec<&str> = loaded
        .inputs
        .consumed
        .iter()
        .map(|input| input.name.as_str())
        .collect();
    assert!(
        names.contains(&"MCP_GATEWAY_BACKENDS__A__DESCRIPTION"),
        "consumed names the process override; saw {names:?}"
    );
    assert!(
        names.contains(&"H6_TOKEN"),
        "consumed names the header template; saw {names:?}"
    );
    assert!(
        names.iter().any(|name| *name == secret_spelling.as_str()),
        "consumed names the secret file path {secret_spelling}; saw {names:?}"
    );

    let file = history_file_bytes(rig.dir.path());
    let events = serde_json::to_vec(&rig.store.events()).unwrap_or_default();
    // The stored bytes themselves: serialised, they are number arrays a text
    // search would never match.
    let mut kept = Vec::new();
    for snapshot in rig.store.snapshots() {
        for file in &snapshot.files {
            kept.extend(file.path.as_bytes());
            kept.extend(file.bytes.iter().flatten());
        }
    }
    for secret in [p1.as_bytes(), p2.as_bytes(), p3.as_bytes()] {
        assert!(
            !holds(&file, secret) && !holds(&events, secret) && !holds(&kept, secret),
            "a consumed value reached the history"
        );
    }
    assert!(
        holds(&file, MARKER),
        "a marker planted in gateway.yaml is found"
    );
}

#[tokio::test]
async fn h7_a_grants_change_with_a_broken_config_is_two_events() {
    let dir = tempfile::tempdir().expect("tempdir");
    let grants_file = dir.path().join("grants.yaml");
    write_owner_only(&grants_file, GRANTS_EMPTY).expect("grants file");
    let grants_spelling = path_string(&grants_file);
    let yaml = format!(
        "{ONE_BACKEND}security:\n  identity_grants:\n    enabled: true\n    path: '{grants_spelling}'\n"
    );
    let started = start(
        dir.path(),
        &yaml,
        Some(grants_spelling.clone()),
        Some(GRANTS_EMPTY.as_bytes().to_vec()),
        None,
        Some(grant_sink(&grants_file)),
    );
    let before = started
        .ctx
        .live_config
        .applied_now()
        .map(|applied| applied.revision.clone());
    let changed = format!("{GRANTS_EMPTY}\n");
    write_owner_only(&grants_file, &changed).expect("edit the grants");
    write_owner_only(&started.path, REFUSED_PORT).expect("break the config");
    let outcome = started.ctx.reload_outcome().await;
    assert!(outcome.is_err(), "the config half refused: {outcome:?}");

    let events = started.store.events();
    let applied = events.iter().rev().nth(1);
    let refused = events.last();
    assert_eq!(applied.map(|event| event.outcome), Some(Outcome::Applied));
    assert_eq!(refused.map(|event| event.outcome), Some(Outcome::Refused));
    let revision = applied.and_then(|event| event.revision.clone());
    assert_ne!(revision.as_deref(), before.as_deref());
    let snapshots = started.store.snapshots();
    let granted = snapshots
        .iter()
        .find(|snapshot| Some(snapshot.revision.as_str()) == revision.as_deref());
    assert_eq!(
        granted
            .and_then(|snapshot| stored(snapshot, &grants_spelling))
            .map(|file| file.bytes.clone()),
        Some(Some(changed.into_bytes()))
    );
    assert_eq!(
        refused
            .and_then(|event| event.still_running.as_ref())
            .map(|running| running.revision.as_str()),
        revision.as_deref()
    );
}

#[tokio::test]
async fn h10_the_version_holds_the_published_bytes_not_the_disk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    let overwrite = path.clone();
    let pause = Arc::new(move || {
        write_owner_only(&overwrite, THREE_BACKENDS).expect("the pause overwrites gateway.yaml");
    });
    let started = start(dir.path(), ONE_BACKEND, None, None, Some(pause), None);
    write_owner_only(&started.path, TWO_BACKENDS).expect("the edit");
    started
        .ctx
        .reload_outcome()
        .await
        .expect("the edit applies");

    let gateway = path_string(&started.path);
    let newest = started.store.snapshots().last();
    assert_eq!(
        newest
            .and_then(|snapshot| stored(snapshot, &gateway))
            .map(|file| file.bytes.clone()),
        Some(Some(TWO_BACKENDS.as_bytes().to_vec()))
    );
    let published = started
        .ctx
        .live_config
        .applied_now()
        .map(|applied| applied.revision.clone());
    assert_eq!(
        newest.map(|snapshot| snapshot.revision.as_str()),
        published.as_deref()
    );
}
