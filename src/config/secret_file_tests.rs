// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! CONFIG.2: a config or env file other users can read is refused at load.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use super::{Refusal, secret_file_refusal};
use crate::config::Config;

const OWNER: u32 = 1001;
const OTHER: u32 = 0;

fn write_mode(path: &Path, body: &str, mode: u32) {
    std::fs::write(path, body).expect("write fixture");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod fixture");
}

/// A 0600 config naming one env file, and that env file at `env_mode`.
fn config_with_env_file(dir: &Path, env_mode: u32) -> (PathBuf, PathBuf) {
    let env = dir.join("gateway.env");
    write_mode(&env, "MCP_GW_C2_FIXTURE=1\n", env_mode);
    let config = dir.join("gateway.yaml");
    write_mode(
        &config,
        &format!("env_files:\n  - \"{}\"\n", env.display()),
        0o600,
    );
    (config, env)
}

#[test]
fn secret_file_refusal_table() {
    for (mode, own, not_own) in [
        (0o600, None, None),
        (0o400, None, None),
        (0o640, Some(Refusal::GroupReadOwned), None),
        (0o440, Some(Refusal::GroupReadOwned), None),
        (0o644, Some(Refusal::World), Some(Refusal::World)),
        (0o660, Some(Refusal::GroupWrite), Some(Refusal::GroupWrite)),
        (0o604, Some(Refusal::World), Some(Refusal::World)),
    ] {
        assert_eq!(
            secret_file_refusal(mode, OWNER, OWNER),
            own,
            "own file, mode {mode:04o}"
        );
        assert_eq!(
            secret_file_refusal(mode, OTHER, OWNER),
            not_own,
            "file owned by another uid, mode {mode:04o}"
        );
    }
}

#[test]
fn world_readable_config_refused_at_load() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_mode(&path, "server:\n  port: 39170\n", 0o644);

    let err = Config::load_evaluated(Some(&path)).expect_err("a 0644 config must be refused");
    let msg = err.to_string();
    assert!(msg.contains("mode 0644"), "the error names the mode: {msg}");
    // Refused for its world bit, not merely for group read on an own file.
    assert!(msg.contains("lets other users read it"), "{msg}");
    assert!(
        msg.contains(&path.display().to_string()),
        "the error names the path: {msg}"
    );
}

#[test]
fn group_readable_own_config_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_mode(&path, "server:\n  port: 39170\n", 0o640);

    let err = Config::load_evaluated(Some(&path)).expect_err("a 0640 own config must be refused");
    assert!(err.to_string().contains("mode 0640"), "{err}");
}

#[test]
fn world_readable_env_file_refused_on_serve_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (config, env) = config_with_env_file(dir.path(), 0o644);

    let err = Config::load_evaluated(Some(&config)).expect_err("a 0644 env file must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains(&env.display().to_string()),
        "the error names the env file: {msg}"
    );
    assert!(msg.contains("env file"), "{msg}");
}

#[test]
fn owner_only_files_load() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (config, _env) = config_with_env_file(dir.path(), 0o600);

    let loaded = Config::load_evaluated(Some(&config)).expect("0600 files load");
    assert_eq!(loaded.env_paths.as_paths().len(), 1);
}

#[test]
fn reload_refuses_loosened_env_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (config, env) = config_with_env_file(dir.path(), 0o600);
    let startup = Config::load_evaluated(Some(&config)).expect("0600 files load");

    std::fs::set_permissions(&env, std::fs::Permissions::from_mode(0o644)).expect("loosen");

    let err = Config::load_with_overlay(Some(&config), &startup.env_paths)
        .expect_err("a reload must refuse the loosened env file");
    assert!(err.to_string().contains("mode 0644"), "{err}");
}

#[test]
fn refusal_fix_depends_on_ownership() {
    let path = Path::new("/etc/mcp-gateway/gateway.yaml");
    let own = super::refusal_fix(path, true, super::SecretFile::Config);
    assert!(
        own.contains("chmod 600 /etc/mcp-gateway/gateway.yaml"),
        "{own}"
    );
    assert!(
        !own.contains("fsGroup"),
        "an owned config needs only chmod: {own}"
    );

    // chmod on a config another uid owns would lock this process out of it.
    let other = super::refusal_fix(path, false, super::SecretFile::Config);
    assert!(
        other.contains("fsGroup") && other.contains("defaultMode"),
        "{other}"
    );
    assert!(!other.contains("chmod 600"), "{other}");
}

/// A 0600 config setting port 39170, and an env file at `env_mode` moving it to 39171.
fn config_with_port_env_file(dir: &Path, env_mode: u32) -> PathBuf {
    let env = dir.join("port.env");
    write_mode(&env, "MCP_GATEWAY_SERVER__PORT=39171\n", env_mode);
    let config = dir.join("gateway.yaml");
    write_mode(
        &config,
        &format!(
            "server:\n  port: 39170\nenv_files:\n  - \"{}\"\n",
            env.display()
        ),
        0o600,
    );
    config
}

#[test]
fn serving_loader_refuses_and_tolerant_loader_skips_a_readable_env_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = config_with_port_env_file(dir.path(), 0o644);

    let err = Config::load_evaluated(Some(&config)).expect_err("serving loader refuses");
    assert!(err.to_string().contains("env file"), "{err}");

    let tolerant = Config::load(Some(&config)).expect("the tolerant loader still loads");
    assert_eq!(
        tolerant.server.port, 39170,
        "the refused env file must not be applied"
    );

    // Positive control: owner-only, the same env file is applied.
    std::fs::set_permissions(
        dir.path().join("port.env"),
        std::fs::Permissions::from_mode(0o600),
    )
    .expect("tighten");
    assert_eq!(
        Config::load(Some(&config)).expect("load").server.port,
        39171
    );
}

#[test]
fn reload_refuses_a_loosened_config() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (config, _env) = config_with_env_file(dir.path(), 0o600);
    let startup = Config::load_evaluated(Some(&config)).expect("0600 files load");

    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).expect("loosen");

    let err = Config::load_with_overlay(Some(&config), &startup.env_paths)
        .expect_err("a reload must refuse the loosened config");
    let msg = err.to_string();
    assert!(
        msg.contains("config file") && msg.contains("mode 0644"),
        "{msg}"
    );
}

/// A `file:` secret (C9) on a Secret volume another uid owns: the fix names the
/// Secret's own `defaultMode`, not the config volume's.
#[test]
fn refusal_fix_for_a_reference_names_the_secret_mount() {
    let path = Path::new("/run/secrets/gateway/token");
    let other = super::refusal_fix(path, false, super::SecretFile::Reference);
    assert!(
        other.contains("mount the Secret") && other.contains("fsGroup"),
        "{other}"
    );
    assert!(!other.contains("config volume"), "{other}");
}
