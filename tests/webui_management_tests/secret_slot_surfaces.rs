// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One table over every surface that shows config: `get`, `list`, `doctor`
//! and the web UI config read. A backend's env slots hold a `file:` and an
//! `env:` reference whose resolved values are planted sentinels; no surface
//! may show either value (ADR-028). `get`, `doctor` and the UI read must also
//! render the reference. `list` prints no slot values at all, so its row is a
//! leak guard only: its anchor, the backend's own line, proves it ran.

use super::*;

const FILE_SECRET: &str = "SENTINEL_SURFACE_FILE_5e1c";
const ENV_SECRET: &str = "SENTINEL_SURFACE_ENV_a93f";
/// Named for this test, so no variable on the runner can stand in for it.
const ENV_NAME: &str = "SLOT_TABLE_TOKEN_A93F";

/// One CLI run's output; `must_succeed` refuses an error a row could
/// otherwise read as rendered. `doctor` exits non-zero on its own findings.
fn cli(config: &std::path::Path, args: &[&str], must_succeed: bool) -> String {
    let output = crate::gateway_bin::command(
        config.parent().expect("the config sits in a temp dir"),
        crate::gateway_bin::Inherit::Nothing,
    )
    .args(args)
    .arg("--config")
    .arg(config)
    .output()
    .expect("run mcp-gateway");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !must_succeed || output.status.success(),
        "{args:?} failed: {stdout}{stderr}"
    );
    // Rows match stdout only; stderr is still searched for a leak.
    format!("{stdout}\n--- stderr ---\n{stderr}")
}

#[tokio::test]
async fn no_surface_shows_a_resolved_secret_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_file = dir.path().join("tavily.key");
    write_owner_only(&key_file, FILE_SECRET).expect("write the key file");
    let env_file = dir.path().join("surface.env");
    write_owner_only(&env_file, format!("{ENV_NAME}={ENV_SECRET}\n")).expect("env file");
    let file_ref = format!("file:{}", key_file.display());
    let env_ref = format!("env:{ENV_NAME}");
    let config_path = dir.path().join("gateway.yaml");
    write_owner_only(
        &config_path,
        format!(
            "env_files:\n  - {}\nbackends:\n  tavily:\n    command: 'tavily-mcp'\n    env:\n      TAVILY_API_KEY: {}\n      SEARCH_TOKEN: {}\n",
            crate::windows_paths::yaml_single_quoted(&env_file.display().to_string()),
            crate::windows_paths::yaml_single_quoted(&file_ref),
            crate::windows_paths::yaml_single_quoted(&env_ref),
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
    let references = &read["secret_references"];
    assert_eq!(
        references["backends.tavily.env.TAVILY_API_KEY"],
        file_ref.as_str()
    );
    assert_eq!(
        references["backends.tavily.env.SEARCH_TOKEN"],
        env_ref.as_str()
    );

    // (surface, what it printed, the stdout lines proving it rendered).
    // Doctor checks only a server's required variables, here TAVILY_API_KEY.
    let surfaces = [
        (
            "get",
            cli(&config_path, &["get", "tavily"], true),
            vec![
                format!("TAVILY_API_KEY={file_ref}"),
                format!("SEARCH_TOKEN={env_ref}"),
            ],
        ),
        (
            "list",
            cli(&config_path, &["list"], true),
            vec!["tavily (stdio)".to_owned()],
        ),
        (
            "doctor",
            cli(&config_path, &["doctor"], false),
            vec![format!("is set as {file_ref}")],
        ),
        ("web UI config read", read.to_string(), Vec::new()),
    ];
    for (surface, shown, rendered) in &surfaces {
        let stdout = shown.split("\n--- stderr ---\n").next().unwrap_or_default();
        for line in rendered {
            assert!(
                stdout.contains(line.as_str()),
                "{surface} did not render {line:?}: {shown}"
            );
        }
        for secret in [FILE_SECRET, ENV_SECRET] {
            assert!(
                !shown.contains(secret),
                "{surface} showed {secret}: {shown}"
            );
        }
    }
}
