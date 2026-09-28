// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1909: a command asked for a machine-readable format writes exactly one
//! document to stdout. Hints, progress and empty-state text go to stderr.
#![cfg(unix)]

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

struct Home {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Home {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().canonicalize().expect("canonical tempdir");
        Self { _dir: dir, root }
    }

    /// Run the binary in this home. `found` publishes one server through the
    /// `MCP_SERVER_*_URL` scan, so discovery has something to list.
    fn run(&self, args: &[&str], found: bool) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mcp-gateway"));
        command
            .env_clear()
            .env("HOME", &self.root)
            .env("XDG_CONFIG_HOME", self.root.join("xdg"))
            // Process discovery calls `ps` by name; an empty PATH keeps host
            // processes out of the discovered set.
            .env("PATH", self.root.join("no-system-programs"))
            .current_dir(&self.root)
            .stdin(Stdio::null())
            .args(args);
        if found {
            command.env("MCP_SERVER_PROBE_URL", "http://127.0.0.1:9/mcp");
        }
        if let Ok(profile) = std::env::var("LLVM_PROFILE_FILE") {
            command.env("LLVM_PROFILE_FILE", profile);
        }
        command.output().expect("run mcp-gateway")
    }
}

/// Parse the whole of `stdout` as one document in `format`.
fn parse_whole(format: &str, stdout: &str) -> Result<serde_json::Value, String> {
    match format {
        "json" => serde_json::from_str(stdout).map_err(|e| e.to_string()),
        "yaml" => serde_yaml::from_str(stdout).map_err(|e| e.to_string()),
        other => unreachable!("not a machine-readable format: {other}"),
    }
}

struct Case {
    label: &'static str,
    args: Vec<&'static str>,
    found: bool,
    /// The document must be exactly this (e.g. `[]` for nothing found).
    expect: Option<serde_json::Value>,
    /// Text the document must contain, so a row cannot pass on an empty result.
    stdout_has: Option<&'static str>,
    /// Human text that must still reach the user, on stderr.
    stderr_has: &'static str,
    /// A file the command must have written, relative to the home.
    writes: Option<&'static str>,
}

fn cases(format: &'static str) -> Vec<Case> {
    vec![
        Case {
            label: "cap discover, servers found",
            args: vec!["cap", "discover", "--format", format],
            found: true,
            expect: None,
            stdout_has: Some("probe"),
            stderr_has: "mcp-gateway cap discover --write-config",
            writes: None,
        },
        Case {
            label: "cap discover, nothing found",
            args: vec!["cap", "discover", "--format", format],
            found: false,
            expect: Some(serde_json::json!([])),
            stdout_has: None,
            stderr_has: "No MCP servers found.",
            writes: None,
        },
        Case {
            label: "cap discover --write-config",
            args: vec![
                "cap",
                "discover",
                "--format",
                format,
                "--write-config",
                "--config-path",
                "discovered.yaml",
            ],
            found: true,
            expect: None,
            stdout_has: Some("probe"),
            stderr_has: "Config written to",
            writes: Some("discovered.yaml"),
        },
        Case {
            label: "cap discover --shadow",
            args: vec!["cap", "discover", "--shadow", "--format", format],
            found: true,
            expect: None,
            stdout_has: None,
            stderr_has: "",
            writes: None,
        },
    ]
}

#[test]
fn every_machine_readable_format_writes_one_document_to_stdout() {
    let mut failures = Vec::new();
    for format in ["json", "yaml"] {
        for case in cases(format) {
            let home = Home::new();
            let out = home.run(&case.args, case.found);
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let row = format!("{} --format {format}", case.label);
            if !out.status.success() {
                failures.push(format!(
                    "{row}: exit {:?}, stderr: {stderr}",
                    out.status.code()
                ));
                continue;
            }
            match parse_whole(format, &stdout) {
                Err(e) => failures.push(format!(
                    "{row}: stdout is not one document ({e}):\n{stdout}"
                )),
                Ok(doc) => {
                    if let Some(want) = &case.expect
                        && &doc != want
                    {
                        failures.push(format!("{row}: expected {want}, got {doc}"));
                    }
                }
            }
            if let Some(text) = case.stdout_has
                && !stdout.contains(text)
            {
                failures.push(format!("{row}: stdout lacks {text:?}:\n{stdout}"));
            }
            if !stderr.contains(case.stderr_has) {
                failures.push(format!(
                    "{row}: stderr lacks {:?}:\n{stderr}",
                    case.stderr_has
                ));
            }
            if let Some(file) = case.writes
                && !home.root.join(file).is_file()
            {
                failures.push(format!("{row}: did not write {file}"));
            }
        }
    }

    // Other commands with a machine-readable format. Their exit status
    // reflects what they check, so only stdout's shape is asserted.
    let capability = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capabilities/automation/agent_search.yaml"
    );
    let others: [(&str, &[&str]); 4] = [
        ("json", &["list", "--json"]),
        ("json", &["doctor", "--format", "json"]),
        ("yaml", &["doctor", "--shadow", "--shadow-format", "yaml"]),
        ("json", &["validate", capability, "--format", "json"]),
    ];
    for (format, args) in others {
        let home = Home::new();
        let out = home.run(args, false);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let row = args.join(" ");
        if stdout.trim().is_empty() {
            failures.push(format!(
                "{row}: empty stdout, exit {:?}, stderr: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            ));
        } else if let Err(e) = parse_whole(format, &stdout) {
            failures.push(format!(
                "{row}: stdout is not one document ({e}):\n{stdout}"
            ));
        }
    }
    let out = Home::new().run(&["list", "--json"], false);
    if !out.status.success() {
        failures.push(format!("list --json: exit {:?}", out.status.code()));
    }

    assert!(failures.is_empty(), "{}", failures.join("\n---\n"));
}

#[test]
fn table_mode_keeps_its_hint_on_stdout() {
    let home = Home::new();
    let out = home.run(&["cap", "discover"], true);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{out:?}");
    assert!(
        stdout.contains("mcp-gateway cap discover --write-config"),
        "table mode hint moved off stdout:\n{stdout}"
    );
}
