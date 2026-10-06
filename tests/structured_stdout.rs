// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1909: a command asked for a machine-readable format writes exactly one
//! document to stdout. Hints, progress and empty-state text go to stderr.

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
            .env("USERPROFILE", &self.root)
            // Debug-build seam: Windows `dirs::home_dir()` ignores HOME (#2368).
            .env("MCP_GATEWAY_TEST_HOME_DIR", &self.root)
            .env("APPDATA", self.root.join("AppData/Roaming"))
            .env("XDG_CONFIG_HOME", self.root.join("xdg"))
            // Process discovery calls `ps` by name; an empty PATH keeps host
            // processes out of the discovered set.
            .env("PATH", self.root.join("no-system-programs"))
            .current_dir(&self.root)
            .stdin(Stdio::null())
            .args(args);
        // A cleared environment loses the Windows system root the process needs to start.
        if let Some(root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", root);
        }
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
    let resources = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml"
    );
    let capabilities = concat!(env!("CARGO_MANIFEST_DIR"), "/capabilities");
    // `tool`, `import`, `ranking eval`, `trust inspect|validate|lab` and
    // `identity grants` need a running gateway or input fixtures; each prints
    // its document through one `println!` and nothing else to stdout.
    let others: [(&str, &[&str]); 8] = [
        ("json", &["list", "--json"]),
        ("json", &["doctor", "--format", "json"]),
        ("yaml", &["doctor", "--shadow", "--shadow-format", "yaml"]),
        ("json", &["validate", capability, "--format", "json"]),
        (
            "json",
            &["kubernetes", "plan", resources, "--format", "json"],
        ),
        (
            "json",
            &["kubernetes", "controller", resources, "--format", "json"],
        ),
        (
            "json",
            &["kubernetes", "apply-plan", resources, "--format", "json"],
        ),
        (
            "json",
            &["trust", "generate", "-C", capabilities, "--format", "json"],
        ),
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

/// `kubernetes controller --watch -f json` never exits, so its stdout is a
/// stream: one compact JSON document per line (NDJSON), one line per cycle.
#[test]
fn controller_watch_json_writes_one_document_per_line() {
    use std::io::{BufRead, BufReader};

    let resources = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml"
    );
    let home = Home::new();
    let mut command = Command::new(env!("CARGO_BIN_EXE_mcp-gateway"));
    command
        .env_clear()
        .env("HOME", &home.root)
        .current_dir(&home.root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .args([
            "kubernetes",
            "controller",
            resources,
            "--watch",
            "--interval-seconds",
            "1",
            "--format",
            "json",
        ]);
    if let Ok(profile) = std::env::var("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", profile);
    }
    let mut child = command.spawn().expect("spawn mcp-gateway");
    let stdout = child.stdout.take().expect("piped stdout");
    // Two cycles; the reader ends at EOF if the process exits early.
    let reader = std::thread::spawn(move || {
        BufReader::new(stdout)
            .lines()
            .take(2)
            .map(|line| line.expect("utf-8 stdout"))
            .collect::<Vec<_>>()
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !reader.is_finished() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    let lines = reader.join().expect("reader thread");

    assert_eq!(lines.len(), 2, "expected two cycles, got {lines:?}");
    for line in &lines {
        let doc: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("stdout line is not one JSON document ({e}): {line}"));
        assert!(
            doc.get("completed_cycles").is_some(),
            "not a controller report: {line}"
        );
    }
}

/// MIK-7817: `list --available` prints the built-in library. Its JSON form is
/// one array whose entries carry what the text form prints, and the text form
/// counts and names those same entries.
#[test]
fn list_available_prints_the_built_in_library_in_both_forms() {
    let home = Home::new();
    let json = home.run(&["list", "--available", "--json"], false);
    assert!(json.status.success(), "list --available --json: {json:?}");
    let document = parse_whole("json", &String::from_utf8_lossy(&json.stdout))
        .expect("--json writes one JSON document");
    let entries = document.as_array().expect("an array of library entries");
    assert!(!entries.is_empty(), "the built-in library is listed");
    for entry in entries {
        for field in ["name", "category", "transport", "description", "login"] {
            assert!(
                entry
                    .get(field)
                    .and_then(serde_json::Value::as_str)
                    .is_some(),
                "{field} missing: {entry}"
            );
        }
    }

    let text = home.run(&["list", "--available"], false);
    assert!(text.status.success(), "list --available: {text:?}");
    let stdout = String::from_utf8_lossy(&text.stdout);
    let heading = format!("{} servers in the built-in library.", entries.len());
    assert!(stdout.starts_with(&heading), "{stdout}");
    for entry in entries {
        let name = entry["name"].as_str().expect("a name");
        assert!(
            stdout.contains(&format!("  {name} (")),
            "{name} is missing from the text listing"
        );
    }
}
