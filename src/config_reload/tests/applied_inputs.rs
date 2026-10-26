// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8914.API2A.1: the inputs a configuration was built from are the bytes
//! the load parsed, and the revision is published with the config it names.

use super::env_support::{RecordingHome, config_naming_env_files, env_file, startup_through};
use super::*;
use crate::config_reload::revision::{AppliedInputs, ConsumedSource, config_revision};

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
    crate::gateway::write_owner_only(&cfg, "env_files: []\n").unwrap();
    crate::gateway::write_owner_only(&env, "GW_T7=two\n").unwrap();
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
    assert_eq!(live.revision(), None, "nothing applied yet");
    let inputs = AppliedInputs {
        gateway_yaml: b"server:\n  port: 1\n".to_vec(),
        ..AppliedInputs::default()
    };
    live.set_applied(Config::default(), inputs.clone());
    let first = config_revision(&revision_key(), &inputs);
    assert_eq!(live.revision().as_deref(), Some(first.as_str()));

    // New grants over the same config get their own id.
    live.set_grants(Some(b"[]\n".to_vec()));
    let with_grants = AppliedInputs {
        grants: Some(b"[]\n".to_vec()),
        ..inputs
    };
    assert_eq!(
        live.revision(),
        Some(config_revision(&revision_key(), &with_grants))
    );

    // A config published without inputs carries no revision, never a stale one.
    live.set(Config::default());
    assert_eq!(live.revision(), None);
}

#[test]
fn without_a_revision_key_no_revision_is_published() {
    let live = LiveConfig::new(Config::default());
    live.set_applied(Config::default(), AppliedInputs::default());
    assert_eq!(live.revision(), None);
}
