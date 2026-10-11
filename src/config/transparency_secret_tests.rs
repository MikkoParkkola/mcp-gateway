// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8365: `security.transparency_log.shared_secret` is resolved like every
//! other secret (`${VAR}`, `env:NAME`, `file:PATH`), refused unresolved while
//! the log is on, and held to message signing's 32-byte minimum. Before this,
//! an env reference reached the HMAC key as its literal text.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::config::env_overlay::EnvOverlay;

const FIELD: &str = "security.transparency_log.shared_secret";
const VAR: &str = "MCP_GW_8365_TLOG_KEY";
/// 40 bytes: comfortably over the 32-byte minimum.
const KEY: &str = "tlog-8365-resolved-key-0123456789abcdefg";

fn write_0600(path: &Path, body: &str) {
    std::fs::write(path, body).expect("write fixture");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
}

/// A 0600 config with the transparency log `enabled` and `shared_secret`
/// written as `secret`, plus a 0600 env file holding `env_body`.
fn config(dir: &Path, enabled: bool, secret: &str, env_body: &str) -> PathBuf {
    let env = dir.join("gateway.env");
    write_0600(&env, env_body);
    let path = dir.join("gateway.yaml");
    let log = dir.join("transparency.jsonl");
    write_0600(
        &path,
        &format!(
            "env_files:\n  - \"{}\"\nsecurity:\n  transparency_log:\n    enabled: {enabled}\n    \
             path: \"{}\"\n    shared_secret: \"{secret}\"\n",
            env.display(),
            log.display()
        ),
    );
    path
}

/// The key the logger is handed (`Config::audit_log`, what `main` passes on).
fn logger_key(path: &Path) -> String {
    let loaded = Config::load_evaluated(Some(path)).expect("the config loads");
    loaded
        .config
        .audit_log()
        .expect("the transparency log is on")
        .shared_secret
}

/// The load refusal's text, which must name the field and never the value.
fn refusal(path: &Path) -> String {
    let error = Config::load_evaluated(Some(path)).expect_err("the config is refused");
    let text = error.to_string();
    assert!(text.contains(FIELD), "the refusal names the field: {text}");
    text
}

/// TLOG.1: an `env:NAME` reference resolves to the variable's value.
#[test]
fn an_env_reference_is_the_key_the_logger_gets() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = config(
        dir.path(),
        true,
        &format!("env:{VAR}"),
        &format!("{VAR}={KEY}\n"),
    );
    assert_eq!(logger_key(&path), KEY, "the reference text became the key");
}

/// TLOG.1: a `${VAR}` reference resolves the same way.
#[test]
fn a_dollar_brace_reference_is_the_key_the_logger_gets() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = config(
        dir.path(),
        true,
        &format!("${{{VAR}}}"),
        &format!("{VAR}={KEY}\n"),
    );
    assert_eq!(logger_key(&path), KEY, "the reference text became the key");
}

/// TLOG.2: a `file:` reference resolves, and its file is tracked for reload
/// like every other secret file.
#[test]
fn a_file_reference_resolves_and_is_tracked_for_reload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret = dir.path().join("tlog.key");
    write_0600(&secret, KEY);
    let path = config(dir.path(), true, &format!("file:{}", secret.display()), "");
    let loaded = Config::load_evaluated(Some(&path)).expect("the config loads");
    assert_eq!(
        loaded.config.audit_log().expect("on").shared_secret,
        KEY,
        "the reference text became the key"
    );
    let tracked = loaded.overlay.rotated_secret_files(&EnvOverlay::none());
    assert!(
        tracked.contains(&format!("file:{}", secret.display())),
        "the key file is not tracked for reload: {tracked:?}"
    );
}

/// TLOG.3: with the log on, a reference that does not resolve refuses the
/// load, naming the field and never a value.
#[test]
fn an_unresolved_reference_refuses_the_load() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cases = [
        format!("env:{VAR}"),
        format!("${{{VAR}}}"),
        format!("file:{}", dir.path().join("absent.key").display()),
    ];
    for (i, secret) in cases.iter().enumerate() {
        let case = dir.path().join(format!("case{i}"));
        std::fs::create_dir(&case).expect("case dir");
        // Unset: the env file holds another variable.
        let unset = config(&case, true, secret, "MCP_GW_8365_OTHER=1\n");
        let text = refusal(&unset);
        assert!(!text.contains(KEY), "{secret}: a value leaked: {text}");
    }
    let empty = config(
        dir.path(),
        true,
        &format!("env:{VAR}"),
        &format!("{VAR}=\n"),
    );
    refusal(&empty);
}

/// TLOG.3 control: with the log off, an unset reference is not consulted.
#[test]
fn a_disabled_log_does_not_consult_its_reference() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = config(
        dir.path(),
        false,
        &format!("env:{VAR}"),
        "MCP_GW_8365_OTHER=1\n",
    );
    Config::load_evaluated(Some(&path)).expect("a disabled log's reference is not read");
}

/// TLOG.4: a resolved secret under 32 bytes is refused, as message signing
/// refuses its key; through a reference and as a literal.
#[test]
fn a_secret_under_32_bytes_is_refused() {
    let short = "x".repeat(31);
    let dir = tempfile::tempdir().expect("tempdir");
    let literal = config(dir.path(), true, &short, "");
    refusal(&literal);
    let by_ref = dir.path().join("by_ref");
    std::fs::create_dir(&by_ref).expect("case dir");
    let referenced = config(
        &by_ref,
        true,
        &format!("env:{VAR}"),
        &format!("{VAR}={short}\n"),
    );
    let text = refusal(&referenced);
    assert!(!text.contains(&short), "the short value leaked: {text}");
}

/// TLOG.4 control: a 32-byte literal still loads unchanged.
#[test]
fn a_32_byte_literal_still_loads() {
    let key = "k".repeat(32);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = config(dir.path(), true, &key, "");
    assert_eq!(logger_key(&path), key);
}

/// Control: an empty secret stays empty, so entries are unsigned (hash chain
/// only), as documented.
#[test]
fn an_empty_secret_stays_unsigned() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = config(dir.path(), true, "", "");
    assert_eq!(logger_key(&path), "");
}
