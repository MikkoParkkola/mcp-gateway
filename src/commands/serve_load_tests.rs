// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The serve paths' first load recovers a crashed byte write first, and
//! refuses to start on one it cannot resolve; read-only commands never
//! reach that recovery, so they never write.

use std::path::{Path, PathBuf};

use sha2::Digest as _;

const ORIGINAL: &str = "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";
const CANDIDATE: &str = "backends: [not: yaml\n";

/// The disk a writer killed after its rename leaves, written by hand in the
/// journal's on-disk form: the candidate in place, the original staged, the
/// journal `staged`. Returns the journal's path.
fn crashed_write(config: &Path) -> PathBuf {
    std::fs::write(config, CANDIDATE).unwrap();
    let target = std::fs::canonicalize(config).unwrap();
    let staged = target.with_file_name(".gateway.yaml.replace-original");
    std::fs::write(&staged, ORIGINAL).unwrap();
    let journal = target.with_file_name(".gateway.yaml.replace-journal");
    let revision = hex::encode(sha2::Sha256::digest(ORIGINAL.as_bytes()));
    let body = serde_json::json!({
        "version": 1,
        "state": "staged",
        "target": target,
        "original": staged,
        "original_revision": revision,
    });
    std::fs::write(&journal, body.to_string()).unwrap();
    journal
}

/// A gateway starting after a crashed write loads the original, not the
/// candidate no reload accepted, and leaves no journal behind.
#[test]
fn a_starting_gateway_recovers_a_crashed_write_before_loading() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("gateway.yaml");
    let journal = crashed_write(&config);

    let evaluated = super::load_for_serve(Some(&config)).expect("recovered, then loaded");

    assert!(evaluated.config.backends.contains_key("a"));
    assert_eq!(std::fs::read_to_string(&config).unwrap(), ORIGINAL);
    assert!(!journal.exists());
}

/// A start with no journal is today's start: nothing is locked or written,
/// not even a lock file.
#[test]
fn a_start_without_a_journal_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("gateway.yaml");
    std::fs::write(&config, ORIGINAL).unwrap();

    super::load_for_serve(Some(&config)).expect("loads");

    let names: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["gateway.yaml"]);
}

/// A config directory this account cannot write: `None` under root, where
/// permissions do not bind.
#[cfg(unix)]
fn unwritable(dir: &Path) -> Option<()> {
    use std::os::unix::fs::PermissionsExt as _;
    if rustix::process::geteuid().is_root() {
        return None;
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    Some(())
}

#[cfg(unix)]
fn writable(dir: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A root-owned config under an unprivileged gateway, no journal: it starts,
/// as it always has.
#[cfg(unix)]
#[test]
fn an_unwritable_directory_without_a_journal_starts() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("gateway.yaml");
    std::fs::write(&config, ORIGINAL).unwrap();
    if unwritable(dir.path()).is_none() {
        return;
    }

    let loaded = super::load_for_serve(Some(&config));

    writable(dir.path());
    loaded.expect("no journal, so the start goes ahead");
}

/// The same with a pending journal: the gateway refuses to start, naming
/// the journal and the action, rather than start on either version.
#[cfg(unix)]
#[test]
fn an_unwritable_directory_with_a_journal_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("gateway.yaml");
    let journal = crashed_write(&config);
    if unwritable(dir.path()).is_none() {
        return;
    }

    let refused = super::load_for_serve(Some(&config));

    writable(dir.path());
    let message = refused
        .err()
        .expect("a pending journal it cannot lock refuses")
        .to_string();
    assert!(
        message.contains("resolve the pending write from the writable side"),
        "{message}"
    );
    assert!(journal.exists(), "nothing was changed");
    assert_eq!(std::fs::read_to_string(&config).unwrap(), CANDIDATE);
}

/// `validate` and `doctor` are read-only: no file of theirs names the
/// startup recovery or the serve load that runs it.
#[test]
fn validate_and_doctor_never_reach_the_startup_recovery() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = vec![root.join("src/commands/doctor.rs")];
    let mut dirs = vec![root.join("src/commands/doctor"), root.join("src/validator")];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    assert!(
        files.len() > 10,
        "the scan found the sources: {}",
        files.len()
    );
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        for name in ["recover_before_start", "load_for_serve"] {
            assert!(!text.contains(name), "{} names {name}", file.display());
        }
    }
}
