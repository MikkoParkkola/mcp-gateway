//! What a UI edit writes back to `gateway.yaml`.
//!
//! A UI edit reads the file, changes one thing, and writes the whole struct
//! back. Whatever the read did to the rest of the file is written too, so the
//! read must leave references as written and must not stand in defaults for a
//! file it could not load.

use std::sync::Arc;
use std::time::Duration;

use super::{ConfigMutation, LiveConfig, ReloadContext};
use crate::config::{BackendConfig, Config, TransportConfig};

fn http_backend() -> BackendConfig {
    BackendConfig {
        transport: TransportConfig::Http {
            http_url: "http://127.0.0.1:9/mcp".to_string(),
            streamable_http: false,
            protocol_version: None,
        },
        ..BackendConfig::default()
    }
}

fn context(path: &std::path::Path) -> ReloadContext {
    ReloadContext::new(
        path.to_path_buf(),
        Arc::new(LiveConfig::new(Config::default())),
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    )
}

async fn add_backend(ctx: &ReloadContext, path: &std::path::Path, name: &str) -> String {
    let name = name.to_string();
    match ctx
        .mutate_and_reload_outcome(path, move |config: &mut Config| {
            config.backends.insert(name, http_backend());
            Ok::<(), ()>(())
        })
        .await
    {
        Ok(ConfigMutation::Applied(..)) => "applied".to_string(),
        Ok(ConfigMutation::Rejected(())) => "rejected".to_string(),
        Err(e) => format!("error: {e}"),
    }
}

/// A header that names a variable must still name it after an unrelated UI
/// edit. Reading the file with references resolved writes the resolved value
/// back, so the secret lands in the file in plain text and the reference is
/// gone.
#[tokio::test]
async fn a_ui_edit_keeps_a_variable_reference_as_written() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    let mut config = Config::default();
    let mut alpha = http_backend();
    alpha.headers.insert(
        "Authorization".to_string(),
        "Bearer ${UI_WRITE_TEST_TOKEN:-s3cret-value}".to_string(),
    );
    config.backends.insert("alpha".to_string(), alpha);
    crate::config_persistence::write_config(&path, &config).unwrap();

    let result = add_backend(&context(&path), &path, "beta").await;

    // An unexpanded reference must still validate, or the edit is refused and
    // the file is left as it was, which would pass the checks below too.
    assert_eq!(result, "applied");
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(
        written.contains("beta:"),
        "the edit was not written:\n{written}"
    );
    assert!(
        written.contains("${UI_WRITE_TEST_TOKEN:-s3cret-value}"),
        "the reference was replaced ({result}):\n{written}"
    );
    assert!(
        !written.contains("Bearer s3cret-value"),
        "the resolved secret was written in plain text ({result}):\n{written}"
    );
}

/// A file the loader cannot read is the operator's to fix. A UI edit that
/// stands in the built-in defaults for it and writes them back erases every
/// backend and setting the file held.
#[tokio::test]
async fn a_ui_edit_leaves_a_file_it_cannot_load_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    let mut config = Config::default();
    config.backends.insert("alpha".to_string(), http_backend());
    crate::config_persistence::write_config(&path, &config).unwrap();
    let mut broken = std::fs::read_to_string(&path).unwrap();
    broken.push_str("\n: [this line does not parse\n");
    std::fs::write(&path, &broken).unwrap();

    let result = add_backend(&context(&path), &path, "beta").await;

    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        broken,
        "a file that does not load was rewritten ({result})"
    );
    assert!(
        result.contains("does not load, so it was not changed"),
        "the edit was not refused for the file not loading: {result}"
    );
}

const ENV_TOKEN: &str = "ui-write-env-only-token-5e1c";
const ENV_PORT: &str = "39464";
const CHILD: &str = "UI_WRITE_ENV_OVERRIDE_CHILD";
const CHILD_DONE: &str = "UI_WRITE_ENV_OVERRIDE_CHECKED";

/// A value set through an `MCP_GATEWAY_*` variable lives in the environment,
/// not in gateway.yaml. An edit that loads the file with those overrides
/// merged writes them back, so an environment-only token lands on disk.
///
/// The variable is set on a re-run of this test in a child process, because
/// setting it in the shared test process is unsafe.
#[tokio::test]
async fn a_ui_edit_keeps_an_environment_override_out_of_gateway_yaml() {
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "config_reload::ui_write_tests::a_ui_edit_keeps_an_environment_override_out_of_gateway_yaml",
                "--exact",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("MCP_GATEWAY_AUTH__BEARER_TOKEN", ENV_TOKEN)
            .env("MCP_GATEWAY_SERVER__PORT", ENV_PORT)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("re-run the test with the override set");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains(CHILD_DONE),
            "the child run failed:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gateway.yaml");
    let mut config = Config::default();
    config.backends.insert("alpha".to_string(), http_backend());
    crate::config_persistence::write_config(&path, &config).unwrap();

    let result = add_backend(&context(&path), &path, "beta").await;

    assert_eq!(result, "applied");
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(
        written.contains("beta:"),
        "the edit was not written:\n{written}"
    );
    assert!(
        !written.contains(ENV_TOKEN),
        "the environment-only token was written to disk:\n{written}"
    );
    assert!(
        !written.contains(ENV_PORT),
        "the environment-only port was written to disk:\n{written}"
    );
    println!("{CHILD_DONE}");
}
