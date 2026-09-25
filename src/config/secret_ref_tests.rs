// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! C4 / SECRET.1: a secret reference that resolves to nothing fails closed.

use super::*;

/// 0600, so the C2 file-mode rule does not refuse the fixture first.
fn private(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Writes `yaml` as `gateway.yaml` under `dir` and loads it.
fn load_c4(dir: &std::path::Path, yaml: &str) -> Result<Config> {
    let path = dir.join("gateway.yaml");
    std::fs::write(&path, yaml).expect("write config");
    private(&path);
    Config::load(Some(&path))
}

/// Writes one env file under `dir` and returns its path for a YAML single-quoted scalar.
fn env_file_c4(dir: &std::path::Path, body: &str) -> String {
    let path = dir.join("c4.env");
    std::fs::write(&path, body).expect("write env file");
    private(&path);
    path.display().to_string()
}

#[test]
fn missing_header_var_refused_for_enabled_backend() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = load_c4(
        dir.path(),
        "backends:\n  x:\n    http_url: \"http://127.0.0.1:39400/mcp\"\n    headers:\n      Authorization: \"Bearer ${MCP_GW_C4_NOPE}\"\n",
    )
    .expect_err("an unset ${VAR} with no default must refuse an enabled backend");
    let msg = err.to_string();
    assert!(
        msg.contains("backends.x.headers.Authorization"),
        "field path missing: {msg}"
    );
    assert!(
        msg.contains("MCP_GW_C4_NOPE"),
        "variable name missing: {msg}"
    );
}

#[test]
fn missing_var_in_disabled_backend_left_verbatim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = load_c4(
        dir.path(),
        "backends:\n  x:\n    enabled: false\n    http_url: \"http://127.0.0.1:39400/mcp\"\n    headers:\n      Authorization: \"Bearer ${MCP_GW_C4_NOPE}\"\n",
    )
    .expect("a disabled backend's references are not resolved");
    assert_eq!(
        cfg.backends["x"].headers["Authorization"],
        "Bearer ${MCP_GW_C4_NOPE}"
    );
}

#[test]
fn explicit_empty_default_and_set_refs_resolve() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = env_file_c4(dir.path(), "MCP_GW_C4_SET=abc\n");
    let cfg = load_c4(
        dir.path(),
        &format!(
            "env_files: ['{env}']\nbackends:\n  x:\n    http_url: \"http://127.0.0.1:39400/mcp\"\n    headers:\n      Authorization: \"Bearer ${{MCP_GW_C4_SET}}\"\n      X-Empty: \"${{MCP_GW_C4_NOPE:-}}\"\n"
        ),
    )
    .expect("set references and an explicit empty default load");
    let headers = &cfg.backends["x"].headers;
    assert_eq!(headers["Authorization"], "Bearer abc");
    assert_eq!(headers["X-Empty"], "");
}

#[test]
fn empty_env_bearer_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = env_file_c4(dir.path(), "MCP_GW_C4_EMPTY=\n");
    let err = load_c4(
        dir.path(),
        &format!(
            "env_files: ['{env}']\nauth:\n  enabled: true\n  bearer_token: env:MCP_GW_C4_EMPTY\n"
        ),
    )
    .expect_err("a set-but-empty env: secret must be refused");
    let msg = err.to_string();
    assert!(msg.contains("empty"), "error must say empty: {msg}");
    assert!(
        msg.contains("auth.bearer_token"),
        "error must name the field: {msg}"
    );
}

#[test]
fn literal_empty_api_key_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = load_c4(
        dir.path(),
        "auth:\n  enabled: true\n  api_keys:\n    - key: \"\"\n      name: ci\n      backends: [\"*\"]\n",
    )
    .expect_err("an empty literal api key must be refused");
    assert!(err.to_string().contains("empty"), "got: {err}");
}

#[test]
fn missing_env_file_named_in_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let absent = dir.path().join("absent-c4.env").display().to_string();
    let err = load_c4(
        dir.path(),
        &format!(
            "env_files: ['{absent}']\nauth:\n  enabled: true\n  bearer_token: env:MCP_GW_C4_NOPE\n"
        ),
    )
    .expect_err("an unset reference must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains(&absent),
        "error must name the absent env file: {msg}"
    );
}
