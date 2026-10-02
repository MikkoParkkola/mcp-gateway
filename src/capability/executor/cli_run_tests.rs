// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7782 CLI.1 through a real spawn: argv arrives exactly as built, the
//! child sees only its private directory and allowlisted names, and timeout,
//! output cap and exit status are enforced. The child is `argv_echo.py`.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use super::resolve_command;
use crate::capability::definition::{CliConfig, ProcessConfig};
use crate::capability::executor::CapabilityExecutor;
use crate::capability::{CapabilityDefinition, parse_capability};

fn python() -> PathBuf {
    let name = if cfg!(windows) { "python" } else { "python3" };
    let path = std::env::var_os("PATH");
    let pathext = std::env::var_os("PATHEXT");
    resolve_command(name, path.as_deref(), pathext.as_deref()).expect("python on PATH in CI")
}

fn script() -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cap_exec/argv_echo.py")
        .display()
        .to_string()
}

/// A capability running `python argv_echo.py <mode> <args...>`.
fn capability(mode: &str, args: &str, extra: &str, timeout: u64) -> CapabilityDefinition {
    let yaml = format!(
        "name: echo_probe\ndescription: Echo probe.\nschema:\n  input:\n    type: object\n\
         providers:\n  primary:\n    service: cli\n    timeout: {timeout}\n    config:\n      \
         command: '{python}'\n      args: ['{script}', {mode}, {args}]\n{extra}",
        python = python().display(),
        script = script(),
    );
    parse_capability(&yaml).expect("probe capability parses")
}

fn config(cap: &CapabilityDefinition) -> &CliConfig {
    match cap.providers.process.get("primary") {
        Some(ProcessConfig::Cli(c)) => c,
        other => panic!("not a cli provider: {other:?}"),
    }
}

async fn call(cap: &CapabilityDefinition, params: Value) -> crate::Result<Value> {
    CapabilityExecutor::new()
        .execute_cli(cap, config(cap), &params)
        .await
}

const HOSTILE: &[&str] = &[
    "--attach=/etc/passwd",
    "--draft",
    "; rm -rf ~",
    "$(id)",
    "`id`",
    "%PATH%",
    "\"q\" 'q'",
    "^&|<>",
    "@/etc/passwd",
    "naïve ✓",
];

#[tokio::test]
async fn hostile_values_arrive_as_exactly_the_built_elements() {
    let cap = capability("echo", "\"--to={to}\", \"--\", \"{file}\"", "", 30);
    for hostile in HOSTILE {
        let out = call(&cap, json!({"to": hostile, "file": hostile}))
            .await
            .unwrap_or_else(|e| panic!("{hostile:?}: {e}"));
        assert_eq!(
            out["argv"],
            json!([format!("--to={hostile}"), "--", hostile]),
            "{hostile:?}"
        );
    }
}

#[tokio::test]
async fn stdin_text_reaches_stdin_and_not_argv() {
    let cap = capability("echo", "--json", "      stdin: '{text}'\n", 30);
    let out = call(&cap, json!({"text": "@/etc/passwd"})).await.unwrap();
    assert_eq!(out["argv"], json!(["--json"]));
    assert_eq!(out["stdin"], "@/etc/passwd");
}

#[tokio::test]
async fn the_child_sees_only_its_private_directory_and_allowed_names() {
    let cap = capability("echo", "x", "", 30);
    let out = call(&cap, json!({})).await.unwrap();
    let cwd = out["cwd"].as_str().unwrap().to_owned();
    let keys: Vec<&str> = out["env_keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let home = Path::new(out["home"].as_str().unwrap());
    // By name: getcwd reports the resolved path (/private/var on macOS) and
    // the directory is gone by now, so it cannot be canonicalized.
    assert_eq!(
        home.file_name(),
        Path::new(&cwd).file_name(),
        "HOME is the private cwd"
    );
    let allowed = [
        "HOME",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
        "TMPDIR",
        "PATH",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
        "SYSTEMROOT",
        "COMSPEC",
        "PATHEXT",
    ];
    for key in keys {
        // Python itself may add these: PEP 538 locale coercion, and the macOS
        // xcrun python3 shim, which sets its SDK paths in the child it starts.
        let added_by_runtime = key.starts_with("__")
            || [
                "LC_CTYPE",
                "PWD",
                "CPATH",
                "LIBRARY_PATH",
                "MANPATH",
                "SDKROOT",
            ]
            .contains(&key);
        assert!(
            allowed.contains(&key) || added_by_runtime,
            "unexpected variable {key} reached the child"
        );
    }
    assert!(
        !Path::new(&cwd).exists(),
        "work directory removed after the call"
    );
}

#[tokio::test]
async fn a_failed_child_maps_to_an_error_without_caller_values() {
    let canary = "CANARY-7782-secretish";
    let cap = capability("fail", "\"3\", \"--to={to}\"", "", 30);
    let err = call(&cap, json!({"to": canary}))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("status 3"), "{err}");
    assert!(
        err.contains("bad request"),
        "gws-style message surfaces: {err}"
    );
    assert!(!err.contains(canary), "caller value leaked: {err}");
}

#[tokio::test]
async fn output_past_the_cap_fails_the_call() {
    let cap = capability("flood", "x", "      max_output_bytes: 65536\n", 30);
    let err = call(&cap, json!({})).await.unwrap_err().to_string();
    assert!(err.contains("byte limit"), "{err}");
}

#[cfg(unix)]
#[tokio::test]
async fn a_timeout_kills_the_child_and_its_grandchild() {
    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("grandchild.pid");
    let cap = capability("grandchild", &format!("'{}'", pidfile.display()), "", 5);
    let err = call(&cap, json!({})).await.unwrap_err().to_string();
    assert!(err.contains("did not finish"), "{err}");
    let pid: i32 = std::fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let mut alive = true;
    for _ in 0..50 {
        let status = std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .unwrap();
        if !status.success() {
            alive = false;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(!alive, "grandchild {pid} outlived the timeout");
}

#[test]
fn a_relative_command_is_refused() {
    for bad in ["./tool", "bin/tool", "..\\tool", ""] {
        assert!(resolve_command(bad, None, None).is_err(), "{bad:?}");
    }
}

#[test]
fn redaction_removes_secrets_at_any_length_and_caller_values_from_four_bytes() {
    let text = "token=abc caller=VALUE1 tiny=ab key=sk";
    let out = super::super::cli::redact(
        text,
        &["abc".to_owned(), "sk".to_owned()],
        &["VALUE1".to_owned(), "ab".to_owned()],
    );
    assert!(!out.contains("abc") && !out.contains("=sk"), "{out}");
    assert!(!out.contains("VALUE1"), "{out}");
    assert!(out.contains("tiny=ab"), "short caller values stay: {out}");
}
