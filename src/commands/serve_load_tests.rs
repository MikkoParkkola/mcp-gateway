// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The serve paths' first load recovers a crashed byte write first, and
//! refuses to start on one it cannot resolve; read-only commands never
//! reach that recovery, so they never write.

use std::path::{Path, PathBuf};

use sha2::Digest as _;

const ORIGINAL: &str = "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";
const CANDIDATE: &str = "backends: [not: yaml\n";

/// Write `text` owner-only, as the loader requires of a config (a bare
/// `fs::write` inherits an ACL the Windows loader refuses).
fn write_private(path: &Path, text: &str) {
    mcp_gateway::gateway::test_helpers::write_owner_only(path, text).unwrap();
}

/// The disk a writer killed after its rename leaves, written by hand in the
/// journal's on-disk form: the candidate in place, the original staged, the
/// journal `staged`. Returns the journal's path.
fn crashed_write(config: &Path) -> PathBuf {
    crashed_write_as(config, ORIGINAL, CANDIDATE, "staged")
}

/// [`crashed_write`] with the staged `original`, the `candidate` on disk and
/// the journal in `state` given.
fn crashed_write_as(config: &Path, original: &str, candidate: &str, state: &str) -> PathBuf {
    write_private(config, candidate);
    let target = std::fs::canonicalize(config).unwrap();
    let staged = target.with_file_name(".gateway.yaml.replace-original");
    write_private(&staged, original);
    let journal = target.with_file_name(".gateway.yaml.replace-journal");
    let revision = hex::encode(sha2::Sha256::digest(original.as_bytes()));
    let body = serde_json::json!({
        "version": 1,
        "state": state,
        "target": target,
        "original": staged,
        "original_revision": revision,
    });
    write_private(&journal, &body.to_string());
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
    write_private(&config, ORIGINAL);

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
    write_private(&config, ORIGINAL);
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
    let message = match refused {
        Err(e) => e.to_string(),
        Ok(_) => panic!("a pending journal it cannot lock must refuse the start"),
    };
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

/// Startup's half of the audit posture: serve's own load refuses auth on
/// with the audit log off, so no running gateway has auth on and no log.
#[test]
fn serve_refuses_auth_on_with_the_audit_log_off() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    let digest = hex::encode(sha2::Sha256::digest(b"zq-startup-pin-key"));
    write_private(
        &path,
        &format!(
            "auth:\n  enabled: true\n  api_keys:\n    - name: ci\n      key_sha256: \"sha256:{digest}\"\nsecurity:\n  transparency_log:\n    enabled: false\n"
        ),
    );
    let refused = super::load_for_serve(Some(&path))
        .expect_err("serve refuses auth on without an audit log")
        .to_string();
    assert!(
        refused.contains("security.transparency_log must be enabled"),
        "the refusal names the audit log: {refused}"
    );
}

/// [`ORIGINAL`] with its audit log on at `log`, auth off.
fn logged(log: &Path) -> String {
    format!(
        "{ORIGINAL}security:\n  transparency_log:\n    enabled: true\n    path: {:?}\n",
        log.display().to_string()
    )
}

/// A config with auth on (one API key) and the audit log at `log`, or off.
fn auth_on(log: Option<&Path>) -> String {
    let digest = hex::encode(sha2::Sha256::digest(b"zq-startup-pin-key"));
    let log = match log {
        Some(log) => format!("enabled: true\n    path: {:?}", log.display().to_string()),
        None => "enabled: false".to_owned(),
    };
    format!(
        "{ORIGINAL}auth:\n  enabled: true\n  api_keys:\n    - name: ci\n      key_sha256: \"sha256:{digest}\"\nsecurity:\n  transparency_log:\n    {log}\n"
    )
}

/// The recovery intents in the audit log at `log`, as their JSON lines.
fn recovery_intents(log: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|line| line.contains("config_recovery_intent"))
        .map(|line| serde_json::from_str(line).expect("an audit line is JSON"))
        .collect()
}

/// The string at `key` anywhere in `value`.
fn field<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    match value {
        serde_json::Value::Object(map) => map
            .get(key)
            .and_then(serde_json::Value::as_str)
            .or_else(|| map.values().find_map(|v| field(v, key))),
        serde_json::Value::Array(items) => items.iter().find_map(|v| field(v, key)),
        _ => None,
    }
}

/// A refused start recovered nothing: the candidate is still on disk and the
/// journal and the staged original are still beside it.
fn nothing_recovered(config: &Path, journal: &Path, candidate: &str) {
    assert_eq!(std::fs::read_to_string(config).unwrap(), candidate);
    assert!(journal.exists(), "the journal stays for the hand recovery");
    assert!(
        journal
            .with_file_name(".gateway.yaml.replace-original")
            .exists(),
        "the staged original stays"
    );
}

/// The refusal of a start whose recovery cannot be audited.
fn refused_start(config: &Path) -> String {
    match super::load_for_serve(Some(config)) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("a recovery that cannot be audited must refuse the start"),
    }
}

/// STARTREC.1: a staged journal is recovered to the original, so its intent
/// goes to the original's audit log, never the candidate's, and names the
/// bytes on disk before the recovery. The log is free again afterwards and
/// its chain still opens.
#[test]
fn a_start_records_the_recovery_in_the_surviving_configs_log_first() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("gateway.yaml");
    let (log_a, log_b) = (dir.path().join("a.ndjson"), dir.path().join("b.ndjson"));
    let original = logged(&log_a);
    let candidate = logged(&log_b);
    let journal = crashed_write_as(&config, &original, &candidate, "staged");

    super::load_for_serve(Some(&config)).expect("recovered, then loaded");

    let intents = recovery_intents(&log_a);
    assert_eq!(
        intents.len(),
        1,
        "one intent in the original's log: {intents:?}"
    );
    let base = field(&intents[0], "base_revision").expect("the intent names its base");
    let before = hex::encode(sha2::Sha256::digest(candidate.as_bytes()));
    assert!(
        base.contains(&before),
        "the intent names the bytes before recovery ({before}), so it came first: {base}"
    );
    assert!(!log_b.exists(), "nothing in the candidate's log");
    assert_eq!(std::fs::read_to_string(&config).unwrap(), original);
    assert!(!journal.exists());
    mcp_gateway::security::TransparencyLogger::open(std::sync::Arc::new(
        mcp_gateway::security::transparency_log::TransparencyLogConfig {
            enabled: true,
            path: log_a.display().to_string(),
            ..Default::default()
        },
    ))
    .expect("the startup logger let its lease go and left a chain that opens");
}

/// STARTREC.1: an `all_renamed` journal keeps the new bytes, so its intent
/// goes to the new file's log.
#[test]
fn a_kept_write_records_its_recovery_in_the_new_files_log() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("gateway.yaml");
    let (log_a, log_b) = (dir.path().join("a.ndjson"), dir.path().join("b.ndjson"));
    let candidate = logged(&log_b);
    let journal = crashed_write_as(&config, &logged(&log_a), &candidate, "all_renamed");

    super::load_for_serve(Some(&config)).expect("recovered, then loaded");

    assert_eq!(
        recovery_intents(&log_b).len(),
        1,
        "one intent in the new file's log"
    );
    assert!(!log_a.exists(), "nothing in the replaced file's log");
    assert_eq!(std::fs::read_to_string(&config).unwrap(), candidate);
    assert!(!journal.exists());
}

/// STARTREC.2: the surviving config has auth on and no audit log, so the
/// recovery cannot be recorded: the start refuses, recovers nothing, and
/// says how to finish by hand.
#[test]
fn auth_on_without_a_log_refuses_the_recovery_and_says_how_to_finish() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("gateway.yaml");
    let journal = crashed_write_as(&config, &auth_on(None), CANDIDATE, "staged");

    let message = refused_start(&config);

    nothing_recovered(&config, &journal, CANDIDATE);
    assert!(
        message.contains(".gateway.yaml.replace-journal"),
        "{message}"
    );
    assert!(
        message.contains("original_revision"),
        "the hand steps: {message}"
    );
}

/// STARTREC.3: a staged original that matches its digest but does not parse
/// cannot say where its recovery is recorded: refused, nothing recovered.
#[test]
fn an_unparseable_surviving_config_refuses_the_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("gateway.yaml");
    let journal = crashed_write_as(&config, "backends: [not: yaml\n", ORIGINAL, "staged");

    let message = refused_start(&config);

    nothing_recovered(&config, &journal, ORIGINAL);
    assert!(
        message.contains(".gateway.yaml.replace-journal"),
        "{message}"
    );
    assert!(
        message.contains("original_revision"),
        "the hand steps: {message}"
    );
}

/// STARTREC.3: the surviving config is refused as the normal load refuses
/// it: one naming a reserved writer slot is not recovered to, so the start
/// refuses before its journal is touched.
#[test]
fn a_surviving_config_naming_a_reserved_slot_refuses_the_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("gateway.yaml");
    let original = format!("{ORIGINAL}    description: \"env:MCPGW_PENDING_SLOT_X\"\n");
    let journal = crashed_write_as(&config, &original, CANDIDATE, "staged");

    let message = refused_start(&config);

    nothing_recovered(&config, &journal, CANDIDATE);
    assert!(message.contains("MCPGW_PENDING_SLOT_X"), "{message}");
}

/// A log under a regular file cannot open: with auth on or off, a configured
/// log that cannot record the recovery refuses it.
#[test]
fn a_log_that_cannot_open_refuses_the_recovery() {
    for auth in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("gateway.yaml");
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, "a file, not a directory").unwrap();
        let log = blocker.join("audit.ndjson");
        let original = if auth {
            auth_on(Some(&log))
        } else {
            logged(&log)
        };
        let journal = crashed_write_as(&config, &original, CANDIDATE, "staged");

        let message = refused_start(&config);

        nothing_recovered(&config, &journal, CANDIDATE);
        assert!(
            message.contains(".gateway.yaml.replace-journal"),
            "auth {auth}: {message}"
        );
    }
}

/// The journal's own refusals come before any log is opened: a staged
/// original that does not match its digest records nothing.
#[test]
fn a_digest_mismatch_refuses_before_any_log_opens() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("gateway.yaml");
    let log = dir.path().join("a.ndjson");
    let journal = crashed_write_as(&config, &logged(&log), CANDIDATE, "staged");
    let staged = journal.with_file_name(".gateway.yaml.replace-original");
    write_private(&staged, &logged(&dir.path().join("planted.ndjson")));

    refused_start(&config);

    assert!(journal.exists());
    assert_eq!(std::fs::read_to_string(&config).unwrap(), CANDIDATE);
    assert!(!log.exists() && !dir.path().join("planted.ndjson").exists());
}
