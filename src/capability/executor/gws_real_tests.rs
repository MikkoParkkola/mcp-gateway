// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7782 CAT.1: every shipped `gws_*` capability's built argv is accepted by
//! the real `gws` binary in its `--dry-run` mode, which needs no credentials
//! and sends nothing. Ignored by default (it needs `gws` on PATH); the CI job
//! `gws-dry-run` installs the pinned version and runs it with `--ignored`.

use std::io::Write as _;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

use super::cli_argv::build_cli_invocation;
use crate::capability::CapabilityLoader;
use crate::capability::definition::ProcessConfig;

/// One plausible value for a schema property.
fn sample(prop: &Value, file: &str) -> Value {
    if prop.get("path_root").is_some() {
        return json!(file);
    }
    if let Some(default) = prop.get("default") {
        return default.clone();
    }
    if let Some(first) = prop
        .get("enum")
        .and_then(Value::as_array)
        .and_then(|e| e.first())
    {
        return first.clone();
    }
    match prop.get("type").and_then(Value::as_str) {
        Some("integer" | "number") => json!(1),
        Some("boolean") => json!(true),
        Some("array") => json!([prop
            .get("items")
            .map_or(json!("sample"), |i| sample(i, file))]),
        Some("object") => json!({}),
        _ => json!("sample"),
    }
}

#[tokio::test]
#[ignore = "runs the real gws binary; the gws-dry-run CI job runs it"]
async fn every_gws_capability_is_accepted_by_the_real_binary_in_dry_run() {
    let scratch = tempfile::tempdir().unwrap();
    let file = scratch.path().join("upload.txt");
    std::fs::write(&file, b"hello").unwrap();
    let dir = format!("{}/capabilities", env!("CARGO_MANIFEST_DIR"));
    let defs = CapabilityLoader::load_directory(&dir).await.unwrap();
    let mut checked = 0;
    let mut failures = Vec::new();
    for def in defs.iter().filter(|d| d.name.starts_with("gws_")) {
        let Some(ProcessConfig::Cli(config)) = def.providers.process.get("primary") else {
            continue;
        };
        let props = def
            .schema
            .input
            .get("properties")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let params: serde_json::Map<String, Value> = props
            .iter()
            .map(|(k, v)| (k.clone(), sample(v, &file.to_string_lossy())))
            .collect();
        let invocation =
            build_cli_invocation(config, &Value::Object(params), &def.schema.input).unwrap();
        let mut child = Command::new(&invocation.command)
            .arg("--dry-run")
            .args(&invocation.args)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", scratch.path())
            .current_dir(scratch.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("gws must be on PATH");
        if let Some(text) = &invocation.stdin {
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap();
        }
        drop(child.stdin.take());
        let out = child.wait_with_output().unwrap();
        checked += 1;
        if !out.status.success() {
            failures.push(format!(
                "{}: exit {:?}: {}",
                def.name,
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
                    .lines()
                    .last()
                    .unwrap_or("")
            ));
        }
    }
    assert!(
        checked >= 18,
        "expected the 18 gws capabilities, ran {checked}"
    );
    assert!(failures.is_empty(), "gws rejected: {failures:#?}");
}
