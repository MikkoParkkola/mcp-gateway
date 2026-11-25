// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The writer's owner refusal as a user meets it at the command line.
//!
//! Root only: the CI root job runs these with `--ignored`, having created
//! group G and user C in it, and each row asserts root first so a run without
//! that setup fails instead of passing.
#![cfg(unix)]

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::ffi::OsString;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Output;

/// One backend, so `remove` has something to take out.
const CONFIG: &str = "backends:\n  srv:\n    command: echo\n";

fn job_id(name: &str) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("precondition: the job exports {name} as a number"))
}

fn job_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("precondition: the job exports {name}"))
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

/// The gateway binary run as user C (group G) through the shared spawn
/// helper: an isolated home and nothing inherited, so no variable from the
/// job (a config path among them) reaches it. The wrapper keeps the
/// environment it is given (setpriv always; sudo with -E, which root may use).
fn gateway_as_c(home: &Path, args: &[&std::ffi::OsStr]) -> Output {
    let (uid, gid) = (
        job_id("ACCESS_ROWS_UID_C").to_string(),
        job_id("ACCESS_ROWS_GID_G").to_string(),
    );
    let user = job_env("ACCESS_ROWS_USER_C");
    // Absolute paths: the child's environment is empty, PATH included.
    let wrapper: Vec<&str> = if cfg!(target_os = "linux") {
        vec![
            "/usr/bin/setpriv",
            "--reuid",
            &uid,
            "--regid",
            &gid,
            "--init-groups",
        ]
    } else {
        vec!["/usr/bin/sudo", "-E", "-u", &user]
    };
    gateway_bin::wrapped(&wrapper, home, gateway_bin::Inherit::Nothing)
        .args(args)
        .output()
        .expect("start the gateway binary as user C")
}

/// S-cli: an admin-owned config (root, group G, 0640) in a directory G may
/// write. The loader admits it for C (root is a trusted owner), so the save is
/// the first thing to object: `remove` must refuse, say why, and leave it be.
#[test]
#[ignore = "root job"]
fn s_cli_remove_refuses_to_take_over_a_root_owned_config() {
    assert!(
        rustix::process::geteuid().is_root(),
        "precondition: the row runs as root (the access-rows root job)"
    );
    let (c, g) = (job_id("ACCESS_ROWS_UID_C"), job_id("ACCESS_ROWS_GID_G"));
    let scratch = tempfile::tempdir_in("/tmp").expect("temp root");
    set_mode(scratch.path(), 0o711);
    let base = std::fs::canonicalize(scratch.path()).expect("canonical temp root");
    let conf_dir = base.join("conf");
    std::fs::create_dir(&conf_dir).expect("config dir");
    std::os::unix::fs::chown(&conf_dir, Some(0), Some(g)).expect("chown config dir");
    set_mode(&conf_dir, 0o770);
    let home = base.join("home");
    std::fs::create_dir(&home).expect("home");
    std::os::unix::fs::chown(&home, Some(c), Some(g)).expect("chown home");
    let config = conf_dir.join("gateway.yaml");
    std::fs::write(&config, CONFIG).expect("config");
    std::os::unix::fs::chown(&config, Some(0), Some(g)).expect("chown config");
    set_mode(&config, 0o640);

    let listed = gateway_as_c(
        &home,
        &["--config".as_ref(), config.as_ref(), "list".as_ref()],
    );
    // `list` falls back to a default config when the file will not load, so
    // only seeing `srv` proves C loaded this one.
    assert!(
        listed.status.success() && String::from_utf8_lossy(&listed.stdout).contains("srv"),
        "precondition: user C loads the config, so a refusal below is the writer's: {}{}",
        String::from_utf8_lossy(&listed.stdout),
        String::from_utf8_lossy(&listed.stderr)
    );

    let removed = gateway_as_c(
        &home,
        &[
            "--config".as_ref(),
            config.as_ref(),
            "remove".as_ref(),
            "srv".as_ref(),
        ],
    );
    let stderr = String::from_utf8_lossy(&removed.stderr);
    assert!(
        !removed.status.success(),
        "S-cli: remove exits non-zero; stderr: {stderr}"
    );
    let reason = format!(
        "foreign-owner: refused to replace {}: the file belongs to uid 0, but this gateway runs as uid {c}.",
        config.display()
    );
    assert!(
        stderr.contains(&reason),
        "S-cli: stderr names the owner refusal: {stderr}"
    );

    assert_eq!(
        std::fs::read_to_string(&config).expect("read config"),
        CONFIG,
        "S-cli: bytes"
    );
    let meta = std::fs::metadata(&config).expect("stat config");
    assert_eq!(
        (meta.uid(), meta.gid(), meta.mode() & 0o7777),
        (0, g, 0o640),
        "S-cli: config uid, gid, mode"
    );
    let others: Vec<OsString> = std::fs::read_dir(&conf_dir)
        .expect("list config dir")
        .map(|entry| entry.expect("config dir entry").file_name())
        // The lock sidecar stays by design (src/config_persistence_lock.rs:14-16).
        .filter(|name| name != "gateway.yaml" && name != ".gateway.yaml.lock")
        .collect();
    assert!(
        others.is_empty(),
        "S-cli: files left beside the config: {others:?}"
    );
}
