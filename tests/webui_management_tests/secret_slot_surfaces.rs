// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One table over every surface that shows config: `get`, `list`, `doctor`
//! and the web UI config read. A backend's env slots hold a `file:` and an
//! `env:` reference whose resolved values are planted sentinels; each surface
//! must render the slot and show neither value (ADR-028).

use super::*;

const FILE_SECRET: &str = "SENTINEL_SURFACE_FILE_5e1c";
const ENV_SECRET: &str = "SENTINEL_SURFACE_ENV_a93f";

fn cli(config: &std::path::Path, args: &[&str]) -> String {
    let output = crate::gateway_bin::command(
        config.parent().expect("the config sits in a temp dir"),
        crate::gateway_bin::Inherit::Environment,
    )
    .args(args)
    .arg("--config")
    .arg(config)
    .output()
    .expect("run mcp-gateway");
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[tokio::test]
async fn no_surface_shows_a_resolved_secret_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_file = dir.path().join("tavily.key");
    write_owner_only(&key_file, FILE_SECRET).expect("write the key file");
    let env_file = dir.path().join("surface.env");
    write_owner_only(&env_file, format!("SURFACE_TOKEN={ENV_SECRET}\n")).expect("env file");
    let config_path = dir.path().join("gateway.yaml");
    // Single-quoted, so a Windows path's backslashes stay literal.
    write_owner_only(
        &config_path,
        format!(
            "env_files:\n  - '{}'\nbackends:\n  tavily:\n    command: 'tavily-mcp'\n    env:\n      TAVILY_API_KEY: 'file:{}'\n      SEARCH_TOKEN: 'env:SURFACE_TOKEN'\n",
            env_file.display(),
            key_file.display()
        ),
    )
    .expect("write the config");

    // Not vacuous: both references resolve to the planted values.
    let config = Config::load(Some(&config_path)).expect("the config loads");
    let env = &config.backends["tavily"].env;
    assert_eq!(env["TAVILY_API_KEY"], FILE_SECRET);
    assert_eq!(env["SEARCH_TOKEN"], ENV_SECRET);

    let (state, _live, _store) =
        make_app_state_with_reload(config, None, config_path.clone()).await;
    let (status, read) =
        send_json(&create_router(state), Method::GET, "/ui/api/config", None).await;
    assert_eq!(status, StatusCode::OK, "{read}");
    let file_ref = format!("file:{}", key_file.display());

    // (surface, what it printed, a line proving it rendered the slot)
    let surfaces = [
        (
            "get",
            cli(&config_path, &["get", "tavily"]),
            format!("TAVILY_API_KEY={file_ref}"),
        ),
        ("list", cli(&config_path, &["list"]), "tavily".to_owned()),
        (
            "doctor",
            cli(&config_path, &["doctor"]),
            format!("is set as {file_ref}"),
        ),
        (
            "web UI config read",
            read.to_string(),
            serde_json::to_string(&file_ref).expect("json string"),
        ),
    ];
    for (surface, shown, rendered) in &surfaces {
        assert!(
            shown.contains(rendered.as_str()),
            "{surface} did not render the slot: {shown}"
        );
        for secret in [FILE_SECRET, ENV_SECRET] {
            assert!(
                !shown.contains(secret),
                "{surface} showed {secret}: {shown}"
            );
        }
    }
    assert_eq!(
        read["secret_references"]["backends.tavily.env.SEARCH_TOKEN"],
        "env:SURFACE_TOKEN"
    );
}
