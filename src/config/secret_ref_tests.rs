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
    // The variable is what the operator has to fix; a bare "field is empty"
    // (the literal-empty check) would hide which one.
    assert!(
        msg.contains("MCP_GW_C4_EMPTY"),
        "error must name the variable: {msg}"
    );
}

#[test]
fn literal_empty_api_key_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = load_c4(
        dir.path(),
        "auth:\n  enabled: true\n  api_keys:\n    - key_sha256: \"\"\n      name: ci\n      backends: [\"*\"]\n",
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

#[test]
fn set_but_empty_template_var_refused() {
    // POSIX `:-`: an empty variable takes the default, and with no default it
    // is refused like an unset one. `${VAR:-}` stays the explicit empty.
    let dir = tempfile::tempdir().expect("tempdir");
    let env = env_file_c4(dir.path(), "MCP_GW_C4_BLANK=\n");
    let backend = |header: &str| {
        format!(
            "env_files: ['{env}']\nbackends:\n  x:\n    http_url: http://127.0.0.1:9/mcp\n    \
             headers:\n      Authorization: \"{header}\"\n"
        )
    };
    let err = load_c4(dir.path(), &backend("Bearer ${MCP_GW_C4_BLANK}"))
        .expect_err("a set-but-empty ${VAR} must not ship an empty credential");
    assert!(err.to_string().contains("MCP_GW_C4_BLANK"), "got: {err}");
    let cfg = load_c4(dir.path(), &backend("Bearer ${MCP_GW_C4_BLANK:-d}")).expect("default");
    assert_eq!(cfg.backends["x"].headers["Authorization"], "Bearer d");
    let cfg = load_c4(dir.path(), &backend("Bearer ${MCP_GW_C4_BLANK:-}")).expect("opt-out");
    assert_eq!(cfg.backends["x"].headers["Authorization"], "Bearer ");
}

#[test]
fn every_unresolved_reference_is_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = load_c4(
        dir.path(),
        "backends:\n  a:\n    http_url: http://127.0.0.1:9/mcp\n    headers:\n      \
         X-A: \"${MCP_GW_C4_NOPE_A}\"\n  b:\n    http_url: http://127.0.0.1:9/mcp\n    \
         env:\n      B: \"${MCP_GW_C4_NOPE_B}\"\n",
    )
    .expect_err("unset references must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("MCP_GW_C4_NOPE_A") && msg.contains("MCP_GW_C4_NOPE_B"),
        "one load must report every unresolved reference: {msg}"
    );
}

#[test]
fn empty_admin_token_refused_by_resolve() {
    // Where the key server's comparator gets its token: an empty literal would
    // match `Authorization: Bearer ` with nothing after it.
    let ks = KeyServerConfig {
        enabled: true,
        admin_token: Some(String::new()),
        ..KeyServerConfig::default()
    };
    let err = ks
        .resolve_admin_token(&EnvOverlay::none())
        .expect_err("an empty admin token must be refused");
    assert!(
        err.to_string().contains("key_server.admin_token"),
        "got: {err}"
    );
}

#[test]
fn empty_hs256_literal_refused_by_resolve() {
    let agent = AgentDefinitionConfig {
        client_id: "svc".to_string(),
        name: "svc".to_string(),
        hs256_secret: Some(String::new()),
        rs256_public_key: None,
        scopes: Vec::new(),
        issuer: None,
        audience: Some("mcp-gateway-test".to_string()),
    };
    let err = agent
        .resolved_hs256_secret(&EnvOverlay::none())
        .expect_err("an empty hs256 secret must be refused");
    assert!(err.to_string().contains("svc"), "got: {err}");
}

#[test]
fn overlay_only_bearer_resolves_in_try_from_config() {
    // The runtime resolvers read the load overlay, not only the process env.
    let dir = tempfile::tempdir().expect("tempdir");
    let env = env_file_c4(dir.path(), "MCP_GW_C4_OVERLAY_ONLY=tok-from-env-file\n");
    let overlay = EnvOverlay::from_paths(&[std::path::PathBuf::from(env)]);
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some("env:MCP_GW_C4_OVERLAY_ONLY".to_string()),
        ..AuthConfig::default()
    };
    assert_eq!(
        auth.resolve_bearer_token(&overlay).expect("resolves"),
        Some("tok-from-env-file".to_string())
    );
}

#[test]
fn empty_admin_token_refused_at_load() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = load_c4(
        dir.path(),
        "key_server:\n  enabled: true\n  admin_token: \"\"\n",
    )
    .expect_err("an empty key-server admin token must be refused at load");
    assert!(
        err.to_string().contains("key_server.admin_token"),
        "got: {err}"
    );
}

#[test]
fn unset_template_and_bad_env_secret_reported_together() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = load_c4(
        dir.path(),
        "auth:\n  enabled: true\n  bearer_token: env:MCP_GW_C4_NOPE_BEARER\nbackends:\n  \
         a:\n    http_url: http://127.0.0.1:9/mcp\n    headers:\n      \
         X-A: \"${MCP_GW_C4_NOPE_HDR}\"\n",
    )
    .expect_err("unresolved references must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("MCP_GW_C4_NOPE_HDR") && msg.contains("MCP_GW_C4_NOPE_BEARER"),
        "one load must report the template and the env: secret together: {msg}"
    );
}

#[test]
fn malformed_template_name_refused() {
    // `${lower}` does not match the variable pattern; it used to pass through
    // as literal text, so a typo shipped `${github_token}` upstream verbatim.
    let dir = tempfile::tempdir().expect("tempdir");
    let err = load_c4(
        dir.path(),
        "backends:\n  a:\n    http_url: http://127.0.0.1:9/mcp\n    headers:\n      \
         Authorization: \"Bearer ${github_token}\"\n",
    )
    .expect_err("a ${...} that is not a variable reference must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("backends.a.headers.Authorization") && msg.contains("github_token"),
        "got: {msg}"
    );
}
