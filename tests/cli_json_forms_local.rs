// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! JSON forms of the local data commands, through the built binary: under `--json` stdout is one document or
//! nothing; without it the output is today's text. Expected values are literals (test plan r2, A8).

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::io::Write as _;
use std::path::Path;
use std::process::Stdio;

use serde_json::{Value, json};

/// What one run printed.
struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// The binary with `args` in `home`, nothing inherited, `stdin` piped in.
fn run<S: AsRef<std::ffi::OsStr>>(home: &Path, args: &[S], stdin: &[u8]) -> Out {
    let mut command = gateway_bin::command(home, gateway_bin::Inherit::Nothing);
    // Info log lines carry timestamps, so two runs' stderr would never match; the rows compare command output.
    command
        .env("MCP_GATEWAY_LOG_LEVEL", "warn")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn"); // spawn-check: waits for exit: one-shot CLI, reaped by wait_with_output
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin)
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    Out {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// The one document a `--json` run printed: exit 0, exactly one line ending in one newline.
fn document(out: &Out) -> Value {
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
    let line = out
        .stdout
        .strip_suffix('\n')
        .unwrap_or_else(|| panic!("no single trailing newline: {:?}", out.stdout));
    assert!(!line.contains('\n'), "more than one line: {:?}", out.stdout);
    serde_json::from_str(line).unwrap_or_else(|e| panic!("not one JSON document ({e}): {line:?}"))
}

// ── get (J2, G1, F) ─────────────────────────────────────────────────────────

const ALPHA_SECRET: &str = "literal-alpha-secret-6c1f";
const BETA_SECRET: &str = "literal-beta-secret-91d0";

/// A config with three backends: stdio `alpha` (a literal, a reference and an empty env value), http `beta`
/// (a literal and a reference header) and disabled, described `gamma`.
fn get_config(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("gateway.yaml");
    let yaml = format!(
        "backends:\n  \
         alpha:\n    command: \"printf a b\"\n    env:\n      API_KEY: \"{ALPHA_SECRET}\"\n      \
         REGION: \"env:ALPHA_REGION\"\n      EMPTY: \"\"\n  \
         beta:\n    url: \"https://beta.example.test/mcp\"\n    headers:\n      \
         Authorization: \"{BETA_SECRET}\"\n      X-Ref: \"env:BETA_TOKEN\"\n  \
         gamma:\n    command: \"printf\"\n    description: \"Gamma backend\"\n    enabled: false\n"
    );
    mcp_gateway::gateway::test_helpers::write_owner_only(&path, yaml).expect("config");
    path
}

#[test]
fn get_prints_one_document_and_keeps_its_text() {
    let home = tempfile::tempdir().expect("home");
    let config = get_config(home.path());
    let config = config.to_str().expect("utf-8 path");

    let plain = run(home.path(), &["--config", config, "get", "alpha"], b"");
    assert_eq!(
        (plain.code, plain.stdout.as_str(), plain.stderr.as_str()),
        (
            Some(0),
            "Name:        alpha\nTransport:   stdio\nDescription: (none)\nEnabled:     true\n\
             Command:     printf (2 argument(s) redacted)\nEnvironment:\n  API_KEY=<set>\n  EMPTY=<empty>\n  \
             REGION=env:ALPHA_REGION\n",
            ""
        )
    );
    let alpha = run(
        home.path(),
        &["--config", config, "get", "alpha", "--json"],
        b"",
    );
    assert_eq!(
        document(&alpha),
        json!({
            "schema_version": 1, "name": "alpha", "transport": "stdio", "description": "", "enabled": true,
            "command": {"executable": "printf", "argument_count": 2}, "url": null,
            "env": {"API_KEY": "<set>", "EMPTY": "<empty>", "REGION": "env:ALPHA_REGION"}, "headers": {}
        })
    );
    assert_eq!(alpha.stderr, plain.stderr);

    let beta = run(
        home.path(),
        &["--config", config, "get", "beta", "--json"],
        b"",
    );
    assert_eq!(
        document(&beta),
        json!({
            "schema_version": 1, "name": "beta", "transport": "http", "description": "", "enabled": true,
            "command": null, "url": "https://beta.example.test", "env": {},
            "headers": {"Authorization": "<set>", "X-Ref": "env:BETA_TOKEN"}
        })
    );
    let gamma = run(
        home.path(),
        &["--config", config, "get", "gamma", "--json"],
        b"",
    );
    assert_eq!(
        document(&gamma),
        json!({
            "schema_version": 1, "name": "gamma", "transport": "stdio", "description": "Gamma backend",
            "enabled": false, "command": {"executable": "printf", "argument_count": 0}, "url": null,
            "env": {}, "headers": {}
        })
    );
}

/// G1: neither literal secret reaches either stream in either form; only `secret_slot` can hide them.
#[test]
fn get_never_prints_a_literal_secret() {
    let home = tempfile::tempdir().expect("home");
    let config = get_config(home.path());
    let config = config.to_str().expect("utf-8 path");
    for name in ["alpha", "beta"] {
        for args in [vec!["get", name], vec!["get", name, "--json"]] {
            let mut argv = vec!["--config", config];
            argv.extend(args.iter().copied());
            let out = run(home.path(), &argv, b"");
            assert_eq!(out.code, Some(0), "{argv:?}: {}", out.stderr);
            for secret in [ALPHA_SECRET, BETA_SECRET] {
                assert!(
                    !out.stdout.contains(secret),
                    "{argv:?} stdout: {}",
                    out.stdout
                );
                assert!(
                    !out.stderr.contains(secret),
                    "{argv:?} stderr: {}",
                    out.stderr
                );
            }
        }
    }
}

/// F: an unknown backend under `--json` prints nothing on stdout; stderr and exit are the plain form's.
#[test]
fn get_json_failure_prints_no_document() {
    let home = tempfile::tempdir().expect("home");
    let config = get_config(home.path());
    let config = config.to_str().expect("utf-8 path");
    let plain = run(home.path(), &["--config", config, "get", "missing"], b"");
    let json = run(
        home.path(),
        &["--config", config, "get", "missing", "--json"],
        b"",
    );
    assert_eq!(plain.code, Some(1), "{}", plain.stderr);
    assert_eq!(
        (json.code, json.stdout.as_str(), json.stderr.as_str()),
        (plain.code, "", plain.stderr.as_str())
    );
}

// ── hash-key (J3, X1) ───────────────────────────────────────────────────────

const KEY: &[u8] = b"json-forms-test-key-0123456789";
/// sha256 of KEY, computed offline (`printf %s KEY | shasum -a 256`).
const KEY_DIGEST: &str = "sha256:f8488b8a7f66465c9467599a30e1167a2bf2841549ef80d1fc9a98b7987c5720";

#[test]
fn hash_key_prints_one_document_and_keeps_its_line() {
    let home = tempfile::tempdir().expect("home");
    let plain = run(home.path(), &["hash-key"], KEY);
    assert_eq!(
        (plain.code, plain.stdout.as_str(), plain.stderr.as_str()),
        (Some(0), &*format!("{KEY_DIGEST}\n"), "")
    );
    let json = run(home.path(), &["hash-key", "--json"], KEY);
    assert!(
        json.stdout.starts_with("{\"schema_version\":1,"),
        "field order: {:?}",
        json.stdout
    );
    assert_eq!(
        document(&json),
        json!({"schema_version": 1, "key_sha256": KEY_DIGEST})
    );
    assert_eq!(json.stderr, "");
}

/// X1: `--json` with `--verify` is a usage error. hash-key never repeats what was typed (argv may hold a mistyped
/// key), so the redaction layer words the conflict without naming the flags; the literal is that wording. At the base
/// the exit is 2 too, with clap's message for a flag it does not know.
#[test]
fn hash_key_json_refuses_verify() {
    let home = tempfile::tempdir().expect("home");
    let out = run(
        home.path(),
        &["hash-key", "--json", "--verify", KEY_DIGEST],
        KEY,
    );
    assert_eq!((out.code, out.stdout.as_str()), (Some(2), ""));
    assert!(
        out.stderr
            .contains("error: an argument cannot be used with one or more of the other specified arguments; what was typed is not repeated here."),
        "stderr: {}",
        out.stderr
    );
}

// ── skills (J4-J6, F) ───────────────────────────────────────────────────────

/// 85 characters: longer than the text form's 70-byte cut, so the document proves it is untruncated.
const ALPHA_DESC: &str =
    "Deploys the service to staging, waits for every health probe, then posts the summary.";
const BETA_DESC: &str = "Bumps the version and tags a release.";

/// A registry file holding `alpha-skill` (every field set) and `beta-skill` (only name, description, body and one
/// trigger), at `dir/skills.json`.
fn registry(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("skills.json");
    let body = json!({
        "schema": 1,
        "skills": {
            "alpha-skill": {
                "name": "alpha-skill", "description": ALPHA_DESC, "version": "1.2.0", "effort": "low",
                "allowed_tools": ["Read"], "triggers": ["deploy"], "keywords": ["ci"],
                "body": "Run the deploy.", "code_blocks": [{"lang": "sh", "content": "echo deploy"}],
                "source_path": "/skills/alpha/SKILL.md",
                "auxiliary_files": ["/skills/alpha/run.sh", "/skills/alpha/notes.md"]
            },
            "beta-skill": {
                "name": "beta-skill", "description": BETA_DESC, "triggers": ["release"], "body": "Tag it."
            }
        }
    });
    std::fs::write(&path, body.to_string()).expect("registry");
    path
}

fn list_item(name: &str, version: Option<&str>, description: &str) -> Value {
    json!({"name": name, "version": version, "description": description})
}

#[test]
fn skills_list_and_search_print_one_document_and_keep_their_text() {
    let home = tempfile::tempdir().expect("home");
    let reg = registry(home.path());
    let reg = reg.to_str().expect("utf-8 path");

    let plain = run(home.path(), &["skills", "list", "--registry", reg], b"");
    let alpha_cut = &ALPHA_DESC[..70];
    assert_eq!(
        (plain.code, plain.stdout.as_str(), plain.stderr.as_str()),
        (
            Some(0),
            &*format!(
                "2 skill(s) in {reg}:\n\n  {:<32} {:<10} {alpha_cut}…\n  {:<32} {:<10} {BETA_DESC}\n",
                "alpha-skill", "1.2.0", "beta-skill", "-"
            ),
            ""
        )
    );
    let list = run(
        home.path(),
        &["skills", "list", "--registry", reg, "--json"],
        b"",
    );
    assert_eq!(
        document(&list),
        json!({"schema_version": 1, "registry": reg, "skills": [
            list_item("alpha-skill", Some("1.2.0"), ALPHA_DESC),
            list_item("beta-skill", None, BETA_DESC),
        ]})
    );
    assert_eq!(list.stderr, plain.stderr);

    let deploy = run(
        home.path(),
        &["skills", "search", "deploy", "--registry", reg, "--json"],
        b"",
    );
    assert_eq!(
        document(&deploy),
        json!({"schema_version": 1, "query": "deploy", "skills": [
            list_item("alpha-skill", Some("1.2.0"), ALPHA_DESC),
        ]})
    );
    let release = run(
        home.path(),
        &["skills", "search", "release", "--registry", reg, "--json"],
        b"",
    );
    assert_eq!(
        document(&release),
        json!({"schema_version": 1, "query": "release", "skills": [
            list_item("beta-skill", None, BETA_DESC),
        ]})
    );
}

#[test]
fn skills_on_an_empty_registry_give_empty_lists() {
    let home = tempfile::tempdir().expect("home");
    let reg = home.path().join("skills.json");
    std::fs::write(&reg, json!({"schema": 1, "skills": {}}).to_string()).expect("registry");
    let reg = reg.to_str().expect("utf-8 path");
    let plain = run(home.path(), &["skills", "list", "--registry", reg], b"");
    assert_eq!(
        (plain.code, plain.stdout.as_str()),
        (
            Some(0),
            "No skills imported. Use `mcp-gateway skills import <path>` to add one.\n"
        )
    );
    let list = run(
        home.path(),
        &["skills", "list", "--registry", reg, "--json"],
        b"",
    );
    assert_eq!(
        document(&list),
        json!({"schema_version": 1, "registry": reg, "skills": []})
    );
    let search = run(
        home.path(),
        &["skills", "search", "deploy", "--registry", reg, "--json"],
        b"",
    );
    assert_eq!(
        document(&search),
        json!({"schema_version": 1, "query": "deploy", "skills": []})
    );
}

#[test]
fn skills_show_prints_every_field() {
    let home = tempfile::tempdir().expect("home");
    let reg = registry(home.path());
    let reg = reg.to_str().expect("utf-8 path");

    let plain = run(
        home.path(),
        &["skills", "show", "alpha-skill", "--registry", reg],
        b"",
    );
    assert_eq!(
        (plain.code, plain.stdout.as_str(), plain.stderr.as_str()),
        (
            Some(0),
            &*format!(
                "Name:        alpha-skill\nDescription: {ALPHA_DESC}\nVersion:     1.2.0\nEffort:      low\n\
                 Tools:       Read\nTriggers:    deploy\nKeywords:    ci\nSource:      /skills/alpha/SKILL.md\n\
                 Auxiliary files:\n  - /skills/alpha/run.sh\n  - /skills/alpha/notes.md\n\n\
                 Embedded code blocks (1): read-only, not executed.\n  [0] lang=sh (11 bytes)\n\n\
                 --- Body ---\nRun the deploy.\n"
            ),
            ""
        )
    );
    let alpha = run(
        home.path(),
        &["skills", "show", "alpha-skill", "--registry", reg, "--json"],
        b"",
    );
    assert_eq!(
        document(&alpha),
        json!({
            "schema_version": 1, "name": "alpha-skill", "description": ALPHA_DESC, "version": "1.2.0",
            "effort": "low", "allowed_tools": ["Read"], "triggers": ["deploy"], "keywords": ["ci"],
            "source_path": "/skills/alpha/SKILL.md",
            "auxiliary_files": ["/skills/alpha/run.sh", "/skills/alpha/notes.md"],
            "code_blocks": [{"lang": "sh", "bytes": 11}], "body": "Run the deploy."
        })
    );
    let beta = run(
        home.path(),
        &["skills", "show", "beta-skill", "--registry", reg, "--json"],
        b"",
    );
    assert_eq!(
        document(&beta),
        json!({
            "schema_version": 1, "name": "beta-skill", "description": BETA_DESC, "version": null,
            "effort": null, "allowed_tools": [], "triggers": ["release"], "keywords": [], "source_path": null,
            "auxiliary_files": [], "code_blocks": [], "body": "Tag it."
        })
    );
}

/// F: an unreadable registry and an unknown skill under `--json` print nothing on stdout.
#[test]
fn skills_json_failures_print_no_document() {
    let home = tempfile::tempdir().expect("home");
    let broken = home.path().join("broken.json");
    std::fs::write(&broken, "not json").expect("registry");
    let broken = broken.to_str().expect("utf-8 path");
    let reg = registry(home.path());
    let reg = reg.to_str().expect("utf-8 path");
    for args in [
        vec!["skills", "list", "--registry", broken],
        vec!["skills", "show", "no-such-skill", "--registry", reg],
    ] {
        let plain = run(home.path(), &args, b"");
        let mut flagged = args.clone();
        flagged.push("--json");
        let json = run(home.path(), &flagged, b"");
        assert_eq!(plain.code, Some(1), "{args:?}: {}", plain.stderr);
        assert_eq!(
            (json.code, json.stdout.as_str(), json.stderr.as_str()),
            (plain.code, "", plain.stderr.as_str()),
            "{args:?}"
        );
    }
}

/// D4: a registry path that is not UTF-8 is printed lossily, as the text form prints it, instead of failing.
/// Skipped on macOS: APFS rejects a directory name with invalid UTF-8 bytes (errno 92, EILSEQ), so the
/// directory this row needs can never be created there. Linux still runs it.
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn skills_list_prints_a_non_utf8_path_lossily() {
    use std::os::unix::ffi::OsStrExt as _;
    let home = tempfile::tempdir().expect("home");
    let dir = home.path().join(std::ffi::OsStr::from_bytes(b"reg-\xff"));
    std::fs::create_dir(&dir).expect("dir");
    let reg = registry(&dir);
    let args = [
        std::ffi::OsStr::new("skills"),
        std::ffi::OsStr::new("list"),
        std::ffi::OsStr::new("--registry"),
        reg.as_os_str(),
        std::ffi::OsStr::new("--json"),
    ];
    let out = run(home.path(), &args, b"");
    let doc = document(&out);
    let shown = doc["registry"].as_str().expect("registry string");
    assert!(
        shown.ends_with("reg-\u{fffd}/skills.json"),
        "registry: {shown}"
    );
}

// ── cap (J7-J11, F): cli_json_forms_local/cap.rs ─────────────────────────────────────
// An integration test file is a crate root, so a bare `mod cap;` would look for tests/cap.rs.
#[path = "cli_json_forms_local/cap.rs"]
mod cap;
