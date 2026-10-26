// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8914.API2A.1: the inputs a configuration was built from are the bytes
//! the load parsed, and the revision is published with the config it names.

use super::env_support::{RecordingHome, config_naming_env_files, env_file, startup_through};
use super::*;
use crate::config_reload::revision::{AppliedInputs, ConsumedSource, RawInputs, config_revision};

fn revision(live: &LiveConfig) -> Option<String> {
    live.applied_now().map(|applied| applied.revision.clone())
}

fn revision_key() -> [u8; 32] {
    crate::gateway::record_principal::test_record_key().config_revision_key()
}

#[test]
fn t7_inputs_are_the_parsed_bytes_not_a_reread() {
    let dir = tempfile::tempdir().unwrap();
    let env = env_file(dir.path(), "a.env", "GW_T7=one\n");
    let cfg = config_naming_env_files(dir.path(), &[env.to_str().unwrap()]);
    let yaml = std::fs::read(&cfg).unwrap();
    let evaluated = startup_through(&cfg, &RecordingHome::new());
    // Both files change on disk after the load parsed them.
    crate::gateway::test_helpers::write_owner_only(&cfg, "env_files: []\n").unwrap();
    crate::gateway::test_helpers::write_owner_only(&env, "GW_T7=two\n").unwrap();
    assert_eq!(evaluated.inputs.gateway_yaml, yaml);
    assert_eq!(
        evaluated.inputs.env_files,
        vec![(
            env.to_string_lossy().into_owned(),
            Some(b"GW_T7=one\n".to_vec())
        )]
    );
}

#[test]
fn a_missing_env_file_is_absent_and_an_empty_one_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    let empty = env_file(dir.path(), "empty.env", "");
    let missing = dir.path().join("missing.env");
    let cfg = config_naming_env_files(
        dir.path(),
        &[empty.to_str().unwrap(), missing.to_str().unwrap()],
    );
    let evaluated = startup_through(&cfg, &RecordingHome::new());
    assert_eq!(
        evaluated.inputs.env_files,
        vec![
            (empty.to_string_lossy().into_owned(), Some(Vec::new())),
            (missing.to_string_lossy().into_owned(), None),
        ]
    );
}

#[test]
fn an_env_file_alone_consumes_no_value() {
    let dir = tempfile::tempdir().unwrap();
    let env = env_file(dir.path(), "a.env", "GW_LIT=v\n");
    let cfg = config_naming_env_files(dir.path(), &[env.to_str().unwrap()]);
    let evaluated = startup_through(&cfg, &RecordingHome::new());
    // An env file alone consumes no value: nothing in the config names it.
    assert!(
        evaluated
            .inputs
            .consumed
            .iter()
            .all(|c| c.source != ConsumedSource::EnvVar || c.name != "GW_LIT"),
        "{:?}",
        evaluated.inputs
    );
}

#[test]
fn the_published_revision_names_the_published_inputs() {
    let live = LiveConfig::new(Config::default()).with_revision_key(revision_key());
    assert_eq!(revision(&live), None, "nothing applied yet");
    let inputs = RawInputs {
        gateway_yaml: b"server:\n  port: 1\n".to_vec(),
        ..RawInputs::default()
    };
    live.set_applied(Config::default(), inputs.clone());
    let id_of = |raw: RawInputs| {
        config_revision(
            &revision_key(),
            &AppliedInputs::digest(&revision_key(), raw),
        )
    };
    let first = id_of(inputs.clone());
    assert_eq!(revision(&live).as_deref(), Some(first.as_str()));

    // New grants over the same config get their own id.
    live.set_grants(Some(b"[]\n"));
    let with_grants = RawInputs {
        grants: Some(b"[]\n".to_vec()),
        ..inputs
    };
    assert_eq!(revision(&live), Some(id_of(with_grants)));

    // A config published without inputs carries no revision, never a stale one.
    live.set(Config::default());
    assert_eq!(revision(&live), None);
}

#[test]
fn without_a_revision_key_no_revision_is_published() {
    let live = LiveConfig::new(Config::default());
    live.set_applied(Config::default(), RawInputs::default());
    assert_eq!(revision(&live), None);
}

#[test]
fn a_reload_keeps_the_grants_their_sink_published() {
    let live = LiveConfig::new(Config::default())
        .with_revision_key(revision_key())
        .with_applied(RawInputs::default());
    live.set_grants(Some(b"[]\n"));
    let reloaded = RawInputs {
        gateway_yaml: b"server:\n  port: 2\n".to_vec(),
        ..RawInputs::default()
    };
    live.set_applied(Config::default(), reloaded.clone());
    let expected = RawInputs {
        grants: Some(b"[]\n".to_vec()),
        ..reloaded
    };
    assert_eq!(
        revision(&live),
        Some(config_revision(
            &revision_key(),
            &AppliedInputs::digest(&revision_key(), expected)
        ))
    );
}

#[test]
fn rotated_env_files_under_an_unchanged_config_get_a_new_revision() {
    let env = |bytes: &[u8]| RawInputs {
        env_files: vec![("/e/.env".to_owned(), Some(bytes.to_vec()))],
        ..RawInputs::default()
    };
    let live = LiveConfig::new(Config::default())
        .with_revision_key(revision_key())
        .with_applied(env(b"K=1\n"));
    let before = revision(&live);
    assert_eq!(before.as_deref(), live.running_revision());
    live.set_inputs(env(b"K=2\n"));
    assert_ne!(revision(&live), before);
    assert_eq!(
        live.running_revision(),
        before.as_deref(),
        "startup's stays"
    );
}

#[test]
fn startup_inputs_are_moved_into_the_first_publish_and_taken_once() {
    let dir = tempfile::tempdir().unwrap();
    let env = env_file(dir.path(), "a.env", "GW_ONCE=1\n");
    let cfg = config_naming_env_files(dir.path(), &[env.to_str().unwrap()]);
    let mut evaluated = startup_through(&cfg, &RecordingHome::new());
    let live_env = evaluated.live_env();
    assert_eq!(
        evaluated.inputs,
        RawInputs::default(),
        "moved out of the load, not copied"
    );
    let record_key = crate::gateway::record_principal::test_record_key();
    let live = LiveConfig::new(Config::default())
        .with_startup_revision(&record_key, live_env.take_startup_inputs());
    assert!(revision(&live).is_some(), "startup publishes a revision");
    assert_eq!(live.running_revision(), revision(&live).as_deref());
    assert!(
        live_env.take_startup_inputs().is_none(),
        "the slot is empty after the startup publish, and a second take gets nothing"
    );
}

#[test]
fn a_startup_without_captured_inputs_publishes_no_revision() {
    let record_key = crate::gateway::record_principal::test_record_key();
    let live = LiveConfig::new(Config::default()).with_startup_revision(&record_key, None);
    assert_eq!(revision(&live), None);
}
