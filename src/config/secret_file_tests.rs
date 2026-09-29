// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! CONFIG.2: a config or env file other users can read is refused at load.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use super::{Refusal, secret_file_refusal};
use crate::config::Config;

const OWNER: u32 = 1001;
const OTHER: u32 = 0;
/// An account that is neither `OWNER` (this process) nor root.
const FOREIGN: u32 = 2002;

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
        own.contains("chmod 600 -- /etc/mcp-gateway/gateway.yaml"),
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

// ── F18: the integrity rule and the new nouns ─────────────────────────────────

#[test]
fn integrity_file_refusal_table() {
    for mode in 0o000..=0o777_u32 {
        let got = super::integrity_file_refusal(mode, OWNER, OWNER);
        let want = if mode & 0o002 != 0 {
            Some(Refusal::World)
        } else if mode & 0o020 != 0 {
            Some(Refusal::GroupWrite)
        } else {
            None
        };
        assert_eq!(got, want, "mode {mode:04o}");
        assert_eq!(got.is_some(), mode & 0o022 != 0, "mode {mode:04o}");
    }
}

#[test]
fn refusal_fix_names_secret_volume_for_new_nouns() {
    let path = Path::new("/run/secrets/tls/server.key");
    for what in [
        super::SecretFile::TlsKey,
        super::SecretFile::OAuthToken,
        super::SecretFile::CredentialFile,
        super::SecretFile::Reference,
    ] {
        let other = super::refusal_fix(path, false, what);
        assert!(
            other.contains("defaultMode: 288") && other.contains("fsGroup"),
            "{what:?}: {other}"
        );
        assert!(!other.contains("config volume"), "{what:?}: {other}");
        let own = super::refusal_fix(path, true, what);
        assert!(own.contains("chmod 600"), "{what:?}: {own}");
    }
    for what in [
        super::SecretFile::TlsCert,
        super::SecretFile::TlsCrl,
        super::SecretFile::IdentityGrants,
        super::SecretFile::ControlPlaneCollection,
    ] {
        let own = super::refusal_fix(path, true, what);
        assert!(
            own.contains("chmod go-w") && !own.contains("chmod 600"),
            "{what:?}: {own}"
        );
    }
}

#[test]
fn integrity_file_readable_loads_and_writable_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("ca.pem");
    write_mode(&path, "public", 0o644);
    assert_eq!(
        super::read_secret_file(&path, super::SecretFile::TlsCert).expect("0644 loads"),
        "public"
    );
    write_mode(&path, "public", 0o664);
    let err = super::read_secret_file(&path, super::SecretFile::TlsCert)
        .expect_err("group-writable refused")
        .to_string();
    assert!(
        err.contains("TLS certificate") && err.contains("change it") && err.contains("chmod go-w"),
        "{err}"
    );
}

/// The 64 KiB cap is for one `file:` secret only: a CRL or a grants file may
/// be larger.
#[test]
fn size_cap_applies_to_references_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("big.pem");
    write_mode(&path, &"a".repeat(64 * 1024 + 1), 0o644);
    for what in [super::SecretFile::TlsCrl, super::SecretFile::IdentityGrants] {
        assert!(super::read_secret_file(&path, what).is_ok(), "{what:?}");
    }
    write_mode(&path, &"a".repeat(64 * 1024 + 1), 0o600);
    assert!(super::read_secret_file(&path, super::SecretFile::Reference).is_err());
}

// ── #2266: the owner must be this process or root ─────────────────────────────

const ALL_MODES: std::ops::RangeInclusive<u32> = 0o000..=0o777;

#[test]
fn secrecy_foreign_owner_refused_at_every_mode() {
    for mode in ALL_MODES {
        assert_eq!(
            secret_file_refusal(mode, FOREIGN, OWNER),
            Some(Refusal::ForeignOwner),
            "mode {mode:04o} owned by uid {FOREIGN}"
        );
    }
}

#[test]
fn integrity_foreign_owner_refused_at_every_mode() {
    for mode in ALL_MODES {
        assert_eq!(
            super::integrity_file_refusal(mode, FOREIGN, OWNER),
            Some(Refusal::ForeignOwner),
            "mode {mode:04o} owned by uid {FOREIGN}"
        );
    }
}

#[test]
fn secrecy_root_owned_kubernetes_projection_accepted() {
    for mode in [0o600, 0o400, 0o440, 0o640] {
        assert_eq!(secret_file_refusal(mode, 0, OWNER), None, "mode {mode:04o}");
    }
}

#[test]
fn integrity_root_owned_projection_accepted() {
    for mode in [0o600, 0o644, 0o444, 0o640] {
        assert_eq!(
            super::integrity_file_refusal(mode, 0, OWNER),
            None,
            "mode {mode:04o}"
        );
    }
}

#[test]
fn euid_owned_file_passes_the_owner_rule_in_both_classes() {
    assert_eq!(secret_file_refusal(0o600, OWNER, OWNER), None);
    assert_eq!(super::integrity_file_refusal(0o644, OWNER, OWNER), None);
}

#[test]
fn root_gateway_refuses_a_file_owned_by_another_account() {
    assert_eq!(
        secret_file_refusal(0o600, FOREIGN, 0),
        Some(Refusal::ForeignOwner)
    );
    assert_eq!(
        super::integrity_file_refusal(0o644, FOREIGN, 0),
        Some(Refusal::ForeignOwner)
    );
    assert_eq!(secret_file_refusal(0o600, 0, 0), None);
}

#[test]
fn class_refusal_applies_the_owner_rule_to_each_class() {
    for protects in [super::Protects::Secrecy, super::Protects::Integrity] {
        assert_eq!(
            super::class_refusal(protects, 0o600, FOREIGN, OWNER),
            Some(Refusal::ForeignOwner),
            "{protects:?} foreign"
        );
        assert_eq!(
            super::class_refusal(protects, 0o600, 0, OWNER),
            None,
            "{protects:?} root"
        );
        assert_eq!(
            super::class_refusal(protects, 0o600, OWNER, OWNER),
            None,
            "{protects:?} euid"
        );
    }
}

#[test]
fn foreign_owner_message_names_file_owner_and_chown_fix() {
    let path = Path::new("/etc/mcp-gateway/tls/server.key");
    let key_message = super::refusal_message(
        super::SecretFile::TlsKey,
        path,
        Refusal::ForeignOwner,
        (0o600, FOREIGN, 1002),
        OWNER,
    );
    for want in [
        "TLS private key /etc/mcp-gateway/tls/server.key",
        "owned by uid 2002",
        "uid 1001",
        "chown 1001 -- /etc/mcp-gateway/tls/server.key",
        "chmod 600 -- /etc/mcp-gateway/tls/server.key",
        "UPGRADING-4.0 \u{a7}96",
    ] {
        assert!(key_message.contains(want), "{want}: {key_message}");
    }
    let integrity = super::refusal_message(
        super::SecretFile::TlsCert,
        Path::new("/etc/mcp-gateway/tls/ca.pem"),
        Refusal::ForeignOwner,
        (0o644, FOREIGN, 1002),
        OWNER,
    );
    assert!(integrity.contains("certificate"), "{integrity}");
    assert!(integrity.contains("owned by uid 2002"), "{integrity}");
    // `chown` keeps a group- or world-write bit, which the trust rule still
    // refuses once this process owns the file, so the fix clears it too.
    assert!(
        integrity.contains(
            "chown 1001 -- /etc/mcp-gateway/tls/ca.pem && chmod go-w -- /etc/mcp-gateway/tls/ca.pem"
        ),
        "{integrity}"
    );
}

#[test]
fn foreign_owner_message_prints_the_exact_fix_with_real_uid_and_path() {
    let key_message = super::refusal_message(
        super::SecretFile::TlsKey,
        Path::new("/srv/k.pem"),
        Refusal::ForeignOwner,
        (0o600, FOREIGN, 1002),
        OWNER,
    );
    assert!(
        key_message.ends_with(
            "Fix: chown 1001 -- /srv/k.pem && chmod 600 -- /srv/k.pem (see UPGRADING-4.0 \u{a7}96)."
        ),
        "{key_message}"
    );
    let integrity = super::refusal_message(
        super::SecretFile::TlsCert,
        Path::new("/srv/c.pem"),
        Refusal::ForeignOwner,
        (0o644, FOREIGN, 1002),
        OWNER,
    );
    assert!(
        integrity.ends_with(
            "Fix: chown 1001 -- /srv/c.pem && chmod go-w -- /srv/c.pem (see UPGRADING-4.0 \u{a7}96)."
        ),
        "{integrity}"
    );
}

/// A path with a space, a leading `-` or shell metacharacters must reach the
/// operator's shell as one literal operand, never as options or commands.
#[test]
fn fix_command_quotes_the_path_and_ends_options() {
    let text = super::refusal_message(
        super::SecretFile::TlsKey,
        Path::new("/tmp/gateway key.pem; touch pwned"),
        Refusal::ForeignOwner,
        (0o600, FOREIGN, 1002),
        OWNER,
    );
    let quoted = "'/tmp/gateway key.pem; touch pwned'";
    assert!(
        text.contains(&format!("chown 1001 -- {quoted} && chmod 600 -- {quoted}")),
        "{text}"
    );
    let owned = super::refusal_message(
        super::SecretFile::Config,
        Path::new("-rf x"),
        Refusal::World,
        (0o644, OWNER, 1002),
        OWNER,
    );
    assert!(owned.contains("Fix: chmod 600 -- '-rf x' "), "{owned}");
    // A dash-led path that quoting leaves bare is still an operand, not an option.
    let bare = super::refusal_message(
        super::SecretFile::TlsCert,
        Path::new("-rf"),
        Refusal::GroupWrite,
        (0o664, OWNER, 1002),
        OWNER,
    );
    assert!(bare.contains("Fix: chmod go-w -- -rf "), "{bare}");
}

#[test]
fn mode_refusal_message_is_unchanged() {
    let got = super::refusal_message(
        super::SecretFile::Config,
        Path::new("/etc/x.yaml"),
        Refusal::World,
        (0o644, OWNER, 1002),
        OWNER,
    );
    assert_eq!(
        got,
        "Refusing to load config file /etc/x.yaml: mode 0644 lets other users read it, \
         and it can hold credentials. Fix: chmod 600 -- /etc/x.yaml (see UPGRADING-4.0 \u{a7}35)."
    );
}
