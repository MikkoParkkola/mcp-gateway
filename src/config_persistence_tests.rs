// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests for `config_persistence` (moved from `config_persistence.rs`).

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

/// Both CLI writers load the file again under the lock and refuse one that
/// exists but no longer loads (it changed after the command loaded it),
/// with or without `--force`; a missing file is still created.
#[test]
fn a_cli_write_refuses_a_config_that_no_longer_loads() {
    const BROKEN: &str = "backends: 5\n";
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, BROKEN).expect("write");
    let config = Config::default();
    for (name, result) in [
        ("preserving", write_config_preserving(&path, &config)),
        ("--force", write_config(&path, &config)),
    ] {
        let error = result.expect_err(name);
        assert!(error.starts_with("Failed to load"), "{name}: {error}");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            BROKEN,
            "{name}"
        );
    }
    let missing = dir.path().join("new.yaml");
    write_config_preserving(&missing, &config).expect("a missing file is created");
    assert!(missing.exists());
}

/// MIK-8029: `text` spliced with `edit`'s change to the config it loads as.
fn spliced(text: &str, edit: impl FnOnce(&mut Config)) -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    std::fs::write(&path, text).expect("write");
    let (before, read) = Config::load_literal_with_text(&path).expect("load");
    assert_eq!(read, text, "the loader hands back the file's own bytes");
    let mut config = before.clone();
    edit(&mut config);
    splice::with_backends_edited(&read, &before, &config, Splice::One).expect("spliced")
}

/// A file whose first line ends `\n` and whose other lines end `\r\n`.
const MIXED: &str = "backends:\n  a:\n    command: x\r\n  b:\r\n    command: y\r\n";

fn backend(yaml: &str) -> crate::config::BackendConfig {
    serde_yaml::from_str(yaml).expect("backend")
}

/// MIK-8029.EOL.1: editing one field leaves every other line's ending as it
/// was, and the edited line keeps its own.
#[test]
fn an_edit_keeps_every_line_ending_of_a_mixed_file() {
    let out = spliced(MIXED, |c| {
        c.backends.insert("b".into(), backend("command: z\n"));
    });
    assert_eq!(out, MIXED.replace("command: y", "command: z"));
}

/// MIK-8029.EOL.2: a removal keeps the other lines' endings.
#[test]
fn a_removal_keeps_every_other_line_ending_of_a_mixed_file() {
    let out = spliced(MIXED, |c| {
        c.backends.remove("a");
    });
    assert_eq!(out, "backends:\n  b:\r\n    command: y\r\n");
}

/// MIK-8029.EOL.2/3: an addition keeps the file's bytes and its new lines
/// take the ending of the line they follow.
#[test]
fn an_addition_keeps_a_mixed_file_and_follows_its_last_ending() {
    let out = spliced(MIXED, |c| {
        c.backends.insert("c".into(), backend("command: w\n"));
    });
    assert!(out.starts_with(MIXED), "{out:?}");
    let added = &out[MIXED.len()..];
    assert!(
        !added.is_empty() && added.split_inclusive('\n').all(|l| l.ends_with("\r\n")),
        "{added:?}"
    );
}

/// MIK-8029.EOL.4: a file with no final line break keeps none.
#[test]
fn a_file_without_a_final_line_break_keeps_none() {
    let out = spliced("backends:\n  a:\n    command: x", |c| {
        c.backends.insert("a".into(), backend("command: z\n"));
    });
    assert_eq!(out, "backends:\n  a:\n    command: z");
}
