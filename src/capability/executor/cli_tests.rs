// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7782 (T14, T15): path parameters stay inside their configured root,
//! network-destination parameters are refused, and `token_env` carries the
//! resolved credential into the child and never into an error.

use std::path::Path;

use serde_json::{Value, json};

use super::confine;
use crate::capability::definition::ProcessConfig;
use crate::capability::executor::CapabilityExecutor;
use crate::capability::{CapabilityDefinition, CapabilityExecutionContext, parse_capability};
use crate::config::FileRoots;

fn roots(uploads: &Path) -> FileRoots {
    FileRoots {
        uploads: Some(uploads.to_path_buf()),
        ..FileRoots::default()
    }
}

#[test]
fn a_path_inside_the_root_resolves_to_its_canonical_form() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("report.pdf"), b"x").unwrap();
    let got = confine("report.pdf", "uploads", &roots(dir.path())).unwrap();
    assert_eq!(
        got,
        std::fs::canonicalize(dir.path().join("report.pdf")).unwrap()
    );
}

#[test]
fn escapes_and_lookalike_siblings_are_refused() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("uploads");
    let evil = parent.path().join("uploads_evil");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&evil).unwrap();
    std::fs::write(evil.join("secret"), b"x").unwrap();
    std::fs::write(parent.path().join("outside"), b"x").unwrap();
    let roots = roots(&root);
    for bad in [
        evil.join("secret").display().to_string(),
        "../outside".to_owned(),
        "../uploads_evil/secret".to_owned(),
    ] {
        let err = confine(&bad, "uploads", &roots).unwrap_err();
        assert!(err.contains("outside"), "{bad}: {err}");
    }
}

#[cfg(unix)]
#[test]
fn a_symlink_inside_the_root_pointing_out_is_refused() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("uploads");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(parent.path().join("id_ed25519"), b"x").unwrap();
    std::os::unix::fs::symlink(parent.path().join("id_ed25519"), root.join("innocent")).unwrap();
    let err = confine("innocent", "uploads", &roots(&root)).unwrap_err();
    assert!(err.contains("outside"), "{err}");
}

#[test]
fn an_unconfigured_root_is_named_in_the_refusal() {
    let err = confine("x", "uploads", &FileRoots::default()).unwrap_err();
    assert!(err.contains("capabilities.files.uploads"), "{err}");
}

fn python() -> String {
    let name = if cfg!(windows) { "python" } else { "python3" };
    let path = std::env::var_os("PATH");
    let pathext = std::env::var_os("PATHEXT");
    super::super::cli_run::resolve_command(name, path.as_deref(), pathext.as_deref())
        .expect("python on PATH in CI")
        .display()
        .to_string()
}

fn probe(
    mode: &str,
    schema_props: &str,
    extra_auth: &str,
    token_env: &str,
) -> CapabilityDefinition {
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cap_exec/argv_echo.py")
        .display()
        .to_string();
    let yaml = format!(
        "name: auth_probe\ndescription: Auth probe.\nschema:\n  input:\n    type: object\n    \
         properties:\n{schema_props}\n{extra_auth}providers:\n  primary:\n    service: cli\n    \
         config:\n      command: '{python}'\n      args: ['{script}', {mode}, '1']\n{token_env}",
        python = python(),
    );
    parse_capability(&yaml).expect("probe parses")
}

async fn call(cap: &CapabilityDefinition) -> crate::Result<Value> {
    let Some(ProcessConfig::Cli(config)) = cap.providers.process.get("primary") else {
        panic!("not a cli provider");
    };
    CapabilityExecutor::new()
        .execute_cli(
            cap,
            config,
            &json!({}),
            &CapabilityExecutionContext::default(),
        )
        .await
}

#[tokio::test]
async fn a_network_destination_parameter_is_refused() {
    let cap = probe(
        "echo",
        "      url:\n        type: string\n        format: uri\n        egress: true",
        "",
        "",
    );
    let err = call(&cap).await.unwrap_err().to_string();
    assert!(err.contains("MIK-7788"), "{err}");
}

/// A 0600 credential file the `file:` key reads.
#[cfg(unix)]
fn token_file(dir: &Path, token: &str) -> String {
    let path = dir.join("cred.json");
    std::fs::write(&path, json!({ "token": token }).to_string()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    format!("file:{}:token", path.display())
}

// Unix only: the `file:` credential source enforces POSIX owner-only modes.
#[cfg(unix)]
#[tokio::test]
async fn the_resolved_credential_reaches_token_env_and_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let token = "tok-7782-redact-me";
    let key = token_file(dir.path(), token);
    let auth = format!("auth:\n  required: true\n  type: bearer\n  key: '{key}'\n");
    let token_env = "      token_env: CAP_EXEC_TEST_TOKEN\n";
    let props = "      x:\n        type: string";

    let ok = call(&probe("echo", props, &auth, token_env)).await.unwrap();
    assert_eq!(ok["test_values"]["CAP_EXEC_TEST_TOKEN"], token);
    assert!(
        !ok["argv"].to_string().contains(token),
        "the token never travels in argv"
    );

    let err = call(&probe("fail", props, &auth, token_env))
        .await
        .unwrap_err()
        .to_string();
    assert!(!err.contains(token), "token leaked into the error: {err}");
}
