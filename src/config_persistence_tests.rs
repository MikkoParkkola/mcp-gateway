// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests for `config_persistence` (moved from `config_persistence.rs`).

#[test]
fn gateway_state_override_precedes_home_and_preserves_default_fallback() {
    let home = Some(std::path::PathBuf::from("operator-home"));
    assert_eq!(
        super::resolve_gateway_data_dir(Some("isolated-state".into()), home.clone()),
        std::path::PathBuf::from("isolated-state")
    );
    assert_eq!(
        super::resolve_gateway_data_dir(None, home),
        std::path::PathBuf::from("operator-home/.mcp-gateway")
    );
    assert_eq!(
        super::resolve_gateway_data_dir(None, None),
        std::path::PathBuf::from("./.mcp-gateway")
    );
}
use super::*;

#[test]
fn load_existing_or_default_returns_default_when_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.yaml");

    let config = load_existing_or_default(&path).unwrap();

    assert!(config.backends.is_empty());
}

#[test]
// POSIX mode bits: asserts 0600 owner-only; Windows enforces owner-only through DACLs (win_acl).
#[cfg(unix)]
fn a_written_config_is_not_readable_by_other_users() {
    // A config can hold a bearer token and API keys. Loopback isolates
    // machines, not users, so another account on the same host can already
    // reach the port; it must not also be able to read the credential.
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_config(&path, &Config::default()).expect("write");

    let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "config wrote mode {mode:o}, expected 600");
}

#[test]
// POSIX mode bits: asserts 0600 owner-only; Windows enforces owner-only through DACLs (win_acl).
#[cfg(unix)]
fn the_scratch_file_is_not_readable_by_other_users_either() {
    // The scratch file exists next to the config for the duration of the
    // write. Creating it at the umask and tightening the final file after
    // the rename leaves exactly the window this is meant to close.
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    let (file, scratch) = create_scratch_exclusive(&path, 1).expect("scratch");
    let mode = file.metadata().expect("stat").permissions().mode() & 0o777;
    let _ = std::fs::remove_file(&scratch);
    assert_eq!(mode, 0o600, "scratch wrote mode {mode:o}, expected 600");
}

#[test]
fn write_config_persists_yaml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    let config = Config::default();

    write_config(&path, &config).unwrap();

    assert!(path.exists());
    let loaded = Config::load(Some(&path)).unwrap();
    assert_eq!(loaded.backends.len(), config.backends.len());
}

/// The temp file used by an atomic config write must be unique per call.
/// A shared `<config>.tmp` lets two concurrent writers clobber each other:
/// one renames the other's bytes into place and reports its own edit saved.
/// Every platform writes through a scratch file and renames it into place.
///
/// Windows used to write the config in place, so a crash mid-write left a
/// truncated config behind — on the one platform no test covered. This
/// asserts the observable half of the unified path: the scratch file is
/// gone, the config parses, and nothing extra is left in the directory.
#[test]
fn a_config_write_leaves_no_scratch_file_on_any_platform() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");

    write_config(&path, &Config::default()).unwrap();

    assert!(Config::load(Some(&path)).is_ok(), "config is not parseable");
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|entry| entry.ok().map(|e| e.file_name()))
        // The lock sidecar stays by design (MIK-8042): never deleted.
        .filter(|name| name != "gateway.yaml" && name != ".gateway.yaml.lock")
        .collect();
    assert!(
        leftovers.is_empty(),
        "the write left scratch files next to the config: {leftovers:?}"
    );
}

/// A rename that fails for a reason another process can stop causing is
/// retried; one that cannot succeed is reported immediately.
#[test]
fn only_transient_rename_errors_are_retried() {
    assert!(
        is_transient(&std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        "a sharing violation would be reported as a permanent failure"
    );
    assert!(
        !is_transient(&std::io::Error::from(std::io::ErrorKind::NotFound)),
        "a missing scratch file would be retried until the attempts ran out"
    );
}

/// The write path runs on an async executor worker while the reload lock is
/// held. Parking that thread stalls unrelated requests and lengthens the
/// hold that the busy bound exists to cap, so no sleep may creep back in.
#[test]
fn the_write_path_never_parks_the_thread_it_runs_on() {
    // Split so this needle does not match the line that defines it.
    let needle = concat!("thread::", "sleep");
    let source = include_str!("config_persistence.rs");
    let sleeps: Vec<&str> = source
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
        .filter(|line| line.contains(needle))
        .collect();
    assert!(
        sleeps.is_empty(),
        "the config write path blocks its executor thread: {sleeps:?}"
    );
}

#[test]
fn a_scratch_name_already_in_use_is_never_claimed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    let taken = scratch_candidate(&path, 7);
    std::fs::write(&taken, b"another writer's bytes").unwrap();

    let (_file, chosen) = create_scratch_exclusive(&path, 7).unwrap();

    assert_ne!(
        chosen, taken,
        "the write claimed a scratch file another writer already held"
    );
    assert_eq!(
        std::fs::read(&taken).unwrap(),
        b"another writer's bytes",
        "the write truncated another writer's scratch file"
    );
}

/// Exhausting every candidate must fail rather than reuse a live name.
#[test]
fn a_write_fails_when_every_scratch_name_is_taken() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    for seed in 0..SCRATCH_ATTEMPTS {
        std::fs::write(scratch_candidate(&path, seed), b"held").unwrap();
    }

    let error = create_scratch_exclusive(&path, 0).unwrap_err();

    assert!(
        error.contains("were all in use"),
        "exhaustion is not distinguishable from an I/O failure: {error}"
    );
}

#[test]
fn each_config_write_gets_its_own_temp_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");

    let (_first_handle, first) = create_scratch_exclusive(&path, next_scratch_seed()).unwrap();
    let (_second_handle, second) = create_scratch_exclusive(&path, next_scratch_seed()).unwrap();

    assert_ne!(
        first, second,
        "two writers shared one temp path, so either can overwrite the other"
    );
    for tmp in [&first, &second] {
        assert_eq!(tmp.parent(), path.parent(), "temp file left its directory");
    }
}

/// Concurrent writers must each either persist their own bytes or fail
/// honestly, and the file left behind must be exactly one writer's config.
/// Against a shared scratch path one writer's rename finds the file already
/// renamed away and fails with "Failed to replace config file", and the
/// bytes that land can belong to a writer that reported success elsewhere.
#[test]
fn concurrent_config_writes_do_not_lose_the_temp_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");

    // Each writer's config is distinguishable, so the assertion below can
    // tell "one writer won" from "the file is a mix of two writers".
    let config_for = |writer: usize| {
        let mut config = Config::default();
        config.backends.insert(
            format!("writer-{writer}"),
            crate::config::BackendConfig {
                transport: crate::config::TransportConfig::Http {
                    http_url: "http://127.0.0.1:9/mcp".to_string(),
                    streamable_http: Some(false),
                    protocol_version: None,
                },
                ..crate::config::BackendConfig::default()
            },
        );
        config
    };

    for _ in 0..40 {
        let errors: Vec<String> = std::thread::scope(|scope| {
            let path = &path;
            let config_for = &config_for;
            let handles: Vec<_> = (0..8)
                .map(|writer| scope.spawn(move || write_config(path, &config_for(writer))))
                .collect();
            handles
                .into_iter()
                .filter_map(|h| h.join().unwrap().err())
                .collect()
        });

        assert!(
            errors.is_empty(),
            "concurrent writers collided on the scratch file: {errors:?}"
        );

        let loaded = Config::load(Some(&path)).expect("config left unparseable");
        let names: Vec<&String> = loaded.backends.keys().collect();
        assert_eq!(
            names.len(),
            1,
            "persisted config is not any single writer's: {names:?}"
        );
        assert!(
            names[0].starts_with("writer-"),
            "persisted config is not any single writer's: {names:?}"
        );
    }

    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name()))
        // The lock sidecar stays by design (MIK-8042): never deleted.
        .filter(|name| name != "gateway.yaml" && name != ".gateway.yaml.lock")
        .collect();
    assert!(
        leftovers.is_empty(),
        "scratch files were left next to the config: {leftovers:?}"
    );
}

#[test]
fn write_config_rejects_invalid_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    let mut config = Config::default();
    config.backends.insert(
        "invalid_backend".to_string(),
        crate::config::BackendConfig {
            transport: crate::config::TransportConfig::Http {
                http_url: "not a url".to_string(),
                streamable_http: Some(false),
                protocol_version: None,
            },
            ..crate::config::BackendConfig::default()
        },
    );

    let result = write_config(&path, &config);

    assert!(matches!(result, Err(msg) if msg.contains("Failed to validate config")));
    assert!(!path.exists());
}

/// A config edit must not turn secret *references* into secret *values* on
/// disk. The read-modify-write helpers behind `mcp-gateway add` and the
/// admin UI load the file, apply one change, and serialise the whole
/// struct back — so anything the loader resolved in memory is written out
/// in plaintext, into a file an operator keeps in version control.
#[test]
fn a_config_rewrite_keeps_secret_references_unresolved() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env_path = dir.path().join("secrets.env");
    crate::gateway::test_helpers::write_owner_only(
        &env_path,
        "FALSIFIER_TOKEN=tok-must-not-land\nFALSIFIER_HEADER=hdr-must-not-land\n",
    )
    .expect("write env file");
    let path = dir.path().join("config.yaml");
    crate::gateway::test_helpers::write_owner_only(
        &path,
        format!(
            "env_files:\n  - {}\nsecurity:\n  transparency_log:\n    enabled: true\nauth:\n  enabled: true\n  bearer_token: env:FALSIFIER_TOKEN\nbackends:\n  demo:\n    http_url: https://example.invalid/mcp\n    headers:\n      Authorization: \"Bearer ${{FALSIFIER_HEADER}}\"\n",
            env_path.display()
        ),
    )
    .expect("write config");

    let mut config = load_config_or_default(&path);
    config.server.port = 9191;
    write_config(&path, &config).expect("rewrite the config");

    let written = std::fs::read_to_string(&path).expect("read the config back");
    assert!(
        !written.contains("tok-must-not-land"),
        "the bearer token was written in plaintext:\n{written}"
    );
    assert!(
        !written.contains("hdr-must-not-land"),
        "the expanded header was written in plaintext:\n{written}"
    );
    assert!(
        written.contains("env:FALSIFIER_TOKEN"),
        "the reference must survive the rewrite:\n{written}"
    );
}

#[test]
#[cfg(windows)]
fn a_written_config_is_owner_only_even_in_an_open_directory() {
    // WT-ASSERT 1718-W1: the scratch file is created private, so the rename
    // hands the config an owner-only DACL, not the directory's.
    use crate::private_fs::test_support::{assert_owner_only, everyone_full_dir};

    let dir = everyone_full_dir("1718-W1");
    let path = dir.path().join("gateway.yaml");

    write_config_text(&path, "server:\n  port: 1\n").expect("write");

    // Relies on `create_file_private(.., Share::Exclusive)`: owner-only from creation, not repaired after.
    assert_owner_only("1718-W1", &path, false);
}

/// The one public writer: `Ok` when it keeps the comments; under
/// `Refuse` the refusal as `Err`, naming the lines and leaving the file
/// untouched; under `Rewrite` the rewrite, with that refusal returned.
#[test]
fn the_preserving_writer_reports_each_outcome() {
    use crate::config_persistence::{CommentLoss, write_config_preserving};
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    // Owner-only, as the loader requires (CONFIG.2): a file it refuses to
    // load would be refused for that reason, not the one under test.
    let write = crate::gateway::test_helpers::write_owner_only;
    let flow = "backends: {a: {command: a}}  # kept by hand\n";
    write(&path, flow).expect("write");
    let two: Config =
        serde_yaml::from_str("backends:\n  a: {command: a}\n  b: {command: b}\n").expect("config");
    let set = |target: Config| {
        move |config: &mut Config| {
            *config = target;
            Ok::<(), String>(())
        }
    };
    let refusal =
        write_config_preserving(&path, CommentLoss::Refuse, set(two.clone())).expect_err("refused");
    assert!(
        refusal.starts_with("Not saved:") && refusal.contains("line 1"),
        "{refusal}"
    );
    assert_eq!(std::fs::read_to_string(&path).expect("read"), flow);
    let block = "backends:\n  a:  # kept by hand\n    command: a\n";
    write(&path, block).expect("write");
    assert_eq!(
        write_config_preserving(&path, CommentLoss::Refuse, set(two.clone())),
        Ok(((), None))
    );
    assert!(
        std::fs::read_to_string(&path)
            .expect("read")
            .contains("# kept by hand")
    );
    // Under Rewrite, a refusal is overridden and returned beside the value:
    // the file is rewritten in full, so the comment is gone and both
    // backends are there.
    write(&path, flow).expect("write");
    let (_, forced) =
        write_config_preserving(&path, CommentLoss::Rewrite, set(two)).expect("rewritten");
    assert!(forced.is_some_and(|r| r.contains("line 1")));
    let rewritten = std::fs::read_to_string(&path).expect("read");
    assert!(!rewritten.contains("# kept by hand"), "{rewritten}");
    let loaded = Config::load_literal(Some(&path)).expect("loads");
    assert!(loaded.backends.contains_key("a") && loaded.backends.contains_key("b"));
}

/// MIK-8042: `write_config_text` creates, never replaces. Its existence check
/// and its write are one locked step, so `init` cannot overwrite a config
/// another writer created after `init` looked.
#[test]
fn writing_config_text_refuses_an_existing_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, "server:\n  port: 2\n").expect("write");
    let error = write_config_text(&path, "server:\n  port: 1\n").expect_err("refused");
    assert!(error.contains("already exists"), "{error}");
    assert_eq!(
        std::fs::read_to_string(&path).expect("read"),
        "server:\n  port: 2\n"
    );
    assert!(dir.path().join(".gateway.yaml.lock").is_file());
}
