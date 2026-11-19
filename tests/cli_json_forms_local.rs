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
#[cfg(unix)]
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

// ── cap (J7-J11, F) ─────────────────────────────────────────────────────────

/// One capability file `dir/<name>.yaml`: a REST provider, `auth` when `key_var` is given.
fn capability(dir: &Path, name: &str, description: &str, key_var: Option<&str>, tags: &[&str]) {
    let auth = key_var.map_or_else(String::new, |var| {
        format!("auth:\n  required: true\n  type: bearer\n  key: \"env:{var}\"\n")
    });
    let tags = tags
        .iter()
        .map(|t| format!("\"{t}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let yaml = format!(
        "name: {name}\ndescription: {description}\nproviders:\n  primary:\n    service: rest\n    config:\n      \
         base_url: https://api.example.test\n      path: /v1/{name}\n      method: GET\n{auth}\
         metadata:\n  tags: [{tags}]\n"
    );
    std::fs::write(dir.join(format!("{name}.yaml")), yaml).expect("capability");
}

/// A config whose env file holds `GAMMA_CAP_KEY` only.
fn cap_config(root: &Path) -> std::path::PathBuf {
    let env_file = root.join("keys.env");
    mcp_gateway::gateway::test_helpers::write_owner_only(&env_file, "GAMMA_CAP_KEY=present\n")
        .expect("env file");
    let config = root.join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &config,
        format!(
            "env_files:\n  - '{}'\n",
            env_file.display().to_string().replace('\'', "''")
        ),
    )
    .expect("config");
    config
}

fn list_cap(
    name: &str,
    description: &str,
    auth_type: Option<&str>,
    missing: Option<&str>,
) -> Value {
    json!({"name": name, "description": description, "auth_type": auth_type, "missing_credential": missing})
}

#[test]
fn cap_list_prints_one_document_and_keeps_its_text() {
    let root = tempfile::tempdir().expect("root");
    let caps = root.path().join("caps");
    std::fs::create_dir_all(&caps).expect("caps");
    capability(&caps, "alpha_cap", "Alpha", Some("ALPHA_CAP_KEY"), &[]);
    capability(&caps, "beta_cap", "Beta", None, &[]);
    capability(&caps, "gamma_cap", "Gamma", Some("GAMMA_CAP_KEY"), &[]);
    let config = cap_config(root.path());
    let (config, caps) = (
        config.to_str().expect("utf-8"),
        caps.to_str().expect("utf-8"),
    );

    // The loader lists in directory-read order, which differs between filesystems: lines and items are compared as
    // sets, and the document must keep the text form's order.
    let plain = run(root.path(), &["--config", config, "cap", "list", caps], b"");
    assert_eq!(plain.code, Some(0), "{}", plain.stderr);
    let header = format!("Found 3 capabilities in {caps}:\n\n");
    let listed = plain
        .stdout
        .strip_prefix(header.as_str())
        .unwrap_or_else(|| panic!("header: {:?}", plain.stdout));
    let mut lines: Vec<&str> = listed.lines().collect();
    let text_order: Vec<String> = lines
        .iter()
        .map(|l| l.trim_start().split(' ').next().unwrap_or("").to_owned())
        .collect();
    lines.sort_unstable();
    assert_eq!(
        lines,
        [
            "  alpha_cap - Alpha [bearer] off: needs ALPHA_CAP_KEY",
            "  beta_cap - Beta",
            "  gamma_cap - Gamma [bearer]",
        ]
    );
    let json = run(
        root.path(),
        &["--config", config, "cap", "list", caps, "--json"],
        b"",
    );
    let mut doc = document(&json);
    let json_order: Vec<String> = doc["capabilities"]
        .as_array()
        .expect("capabilities")
        .iter()
        .map(|c| c["name"].as_str().unwrap_or("").to_owned())
        .collect();
    assert_eq!(
        json_order, text_order,
        "the document keeps the text form's order"
    );
    doc["capabilities"]
        .as_array_mut()
        .expect("capabilities")
        .sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    assert_eq!(
        doc,
        json!({"schema_version": 1, "directory": caps, "capabilities": [
            list_cap("alpha_cap", "Alpha", Some("bearer"), Some("ALPHA_CAP_KEY")),
            list_cap("beta_cap", "Beta", None, None),
            list_cap("gamma_cap", "Gamma", Some("bearer"), None),
        ]})
    );
    assert_eq!(json.stderr, plain.stderr);

    let empty = root.path().join("empty");
    std::fs::create_dir_all(&empty).expect("empty");
    let empty = empty.to_str().expect("utf-8");
    let none = run(
        root.path(),
        &["--config", config, "cap", "list", empty, "--json"],
        b"",
    );
    assert_eq!(
        document(&none),
        json!({"schema_version": 1, "directory": empty, "capabilities": []})
    );
}

fn indexed(name: &str, description: &str, requires_key: bool, tags: &[&str]) -> Value {
    json!({"name": name, "description": description, "requires_key": requires_key, "tags": tags})
}

#[test]
fn cap_search_and_registry_list_print_one_document() {
    let root = tempfile::tempdir().expect("root");
    let caps = root.path().join("caps");
    std::fs::create_dir_all(&caps).expect("caps");
    capability(
        &caps,
        "stock_quote",
        "Quotes a stock",
        Some("STOCK_KEY"),
        &["finance"],
    );
    capability(
        &caps,
        "weather_now",
        "Current conditions",
        None,
        &["weather", "free"],
    );
    let caps = caps.to_str().expect("utf-8");
    let weather = indexed(
        "weather_now",
        "Current conditions",
        false,
        &["weather", "free"],
    );
    let stock = indexed("stock_quote", "Quotes a stock", true, &["finance"]);

    let hit = run(
        root.path(),
        &["cap", "search", "weather", "-C", caps, "--json"],
        b"",
    );
    assert_eq!(
        document(&hit),
        json!({"schema_version": 1, "query": "weather", "capabilities": [weather.clone()]})
    );
    let miss = run(
        root.path(),
        &["cap", "search", "nothing-matches", "-C", caps, "--json"],
        b"",
    );
    assert_eq!(
        document(&miss),
        json!({"schema_version": 1, "query": "nothing-matches", "capabilities": []})
    );
    let all = run(
        root.path(),
        &["cap", "registry-list", "-C", caps, "--json"],
        b"",
    );
    // The index may follow directory-read order: entries compared as a set, and the text form checked per entry.
    let mut doc = document(&all);
    doc["capabilities"]
        .as_array_mut()
        .expect("capabilities")
        .sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    assert_eq!(
        doc,
        json!({"schema_version": 1, "capabilities": [stock, weather]})
    );
    let plain = run(root.path(), &["cap", "registry-list", "-C", caps], b"");
    assert_eq!(plain.code, Some(0), "{}", plain.stderr);
    for part in [
        "Available capabilities (2):\n\n",
        "  stock_quote - Quotes a stock 🔑\n    Tags: finance\n\n",
        "  weather_now - Current conditions\n    Tags: weather, free\n\n",
    ] {
        assert!(
            plain.stdout.contains(part),
            "{part:?} in {:?}",
            plain.stdout
        );
    }
    assert!(
        plain
            .stdout
            .ends_with("\nAll capabilities are available in the capabilities directory.\n"),
        "{:?}",
        plain.stdout
    );

    let empty = root.path().join("empty");
    std::fs::create_dir_all(&empty).expect("empty");
    let none = run(
        root.path(),
        &[
            "cap",
            "registry-list",
            "-C",
            empty.to_str().expect("utf-8"),
            "--json",
        ],
        b"",
    );
    assert_eq!(
        document(&none),
        json!({"schema_version": 1, "capabilities": []})
    );
}

#[test]
fn cap_validate_prints_provider_auth_and_warnings() {
    let root = tempfile::tempdir().expect("root");
    let file = root.path().join("validate_cap.yaml");
    std::fs::write(
        &file,
        "name: validate_cap\ndescription: Validate now\nproviders:\n  primary:\n    service: rest\n    config:\n      \
         base_url: https://api.example.test\n      path: /v1/now\n      method: GET\n\
         auth:\n  required: true\n  type: bearer\n  key: \"env:VALIDATE_TOKEN\"\n",
    )
    .expect("capability");
    let file = file.to_str().expect("utf-8");
    let plain = run(root.path(), &["cap", "validate", file], b"");
    assert_eq!(
        (plain.code, plain.stdout.as_str(), plain.stderr.as_str()),
        (
            Some(0),
            "✅ validate_cap - valid\n   Validate now\n   Provider: rest (GET)\n   \
             URL: https://api.example.test/v1/now\n   Auth: bearer (env:VALIDATE_TOKEN)\n",
            ""
        )
    );
    let json = run(root.path(), &["cap", "validate", file, "--json"], b"");
    assert_eq!(
        document(&json),
        json!({
            "schema_version": 1, "name": "validate_cap", "description": "Validate now",
            "provider": {"service": "rest", "method": "GET", "base_url": "https://api.example.test",
                         "path": "/v1/now"},
            "auth": {"type": "bearer", "key": "env:VALIDATE_TOKEN"}, "warnings": []
        })
    );

    // One warning (CAP-012, an unread provider key): in the document, and still on stderr in both forms.
    let warned = root.path().join("warned_cap.yaml");
    std::fs::write(
        &warned,
        "name: warned_cap\ndescription: Reads one endpoint.\nproviders:\n  primary:\n    config:\n      \
         base_url: https://api.example.com\n      path: /v1\n      methd: POST\n",
    )
    .expect("capability");
    let warned = warned.to_str().expect("utf-8");
    let plain = run(root.path(), &["cap", "validate", warned], b"");
    let json = run(root.path(), &["cap", "validate", warned, "--json"], b"");
    let warning = plain.stderr.trim_end_matches('\n');
    assert!(
        warning.contains("CAP-012")
            && warning.contains("providers.primary.config.methd")
            && !warning.contains('\n'),
        "one CAP-012 line on stderr: {}",
        plain.stderr
    );
    let doc = document(&json);
    assert_eq!(doc["auth"], Value::Null);
    assert_eq!(doc["warnings"], json!([warning]));
    assert_eq!(json.stderr, plain.stderr);

    // A webhook-only capability has no primary provider: provider is null.
    let hook = root.path().join("hook_cap.yaml");
    std::fs::write(
        &hook,
        "name: hook_cap\ndescription: Hooks only.\nproviders: {}\nwebhooks:\n  ping:\n    path: /hook/ping\n    \
         method: POST\n    transform:\n      event_type: \"hook.ping\"\n      data: {}\n",
    )
    .expect("capability");
    let json = run(
        root.path(),
        &["cap", "validate", hook.to_str().expect("utf-8"), "--json"],
        b"",
    );
    let doc = document(&json);
    assert_eq!(doc["provider"], Value::Null, "{doc}");
    assert_eq!(doc["name"], json!("hook_cap"));
}

/// J11 (binary half), X2: an execution failure under `--json` prints nothing on stdout, not even the banner the
/// text form prints before executing; stderr and exit are the text form's.
#[test]
fn cap_test_json_failure_prints_no_banner() {
    let root = tempfile::tempdir().expect("root");
    // A loopback target: the CLI's executor refuses loopback egress, so the call fails before any connection.
    let file = root.path().join("now_cap.yaml");
    std::fs::write(
        &file,
        "name: now_cap\ndescription: Now\nproviders:\n  primary:\n    service: rest\n    config:\n      \
         base_url: http://127.0.0.1:9\n      path: /now\n      method: GET\n",
    )
    .expect("capability");
    let file = file.to_str().expect("utf-8");
    let args = ["cap", "test", file, "--args", "{\"city\": \"Oulu\"}"];
    let plain = run(root.path(), &args, b"");
    assert_eq!(plain.code, Some(1), "{}", plain.stderr);
    assert!(
        plain.stdout.starts_with("Testing capability: now_cap\n"),
        "{}",
        plain.stdout
    );
    let mut flagged = args.to_vec();
    flagged.push("--json");
    let json = run(root.path(), &flagged, b"");
    assert_eq!(
        (json.code, json.stdout.as_str(), json.stderr.as_str()),
        (Some(1), "", plain.stderr.as_str())
    );
}

/// F: an unloadable config (cap list) and a structural error (cap validate) under `--json` print nothing on stdout.
#[test]
fn cap_json_failures_print_no_document() {
    let root = tempfile::tempdir().expect("root");
    let caps = root.path().join("caps");
    std::fs::create_dir_all(&caps).expect("caps");
    capability(&caps, "alpha_cap", "Alpha", None, &[]);
    let broken = root.path().join("broken.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&broken, "server: [this is: not, valid\n")
        .expect("config");
    let structural = root.path().join("structural_cap.yaml");
    std::fs::write(
        &structural,
        "name: structural_cap\ndescription: No base URL.\nproviders:\n  primary:\n    config:\n      path: /v1\n",
    )
    .expect("capability");
    let (broken, caps, structural) = (
        broken.to_str().expect("utf-8"),
        caps.to_str().expect("utf-8"),
        structural.to_str().expect("utf-8"),
    );
    for args in [
        vec!["--config", broken, "cap", "list", caps],
        vec!["cap", "validate", structural],
    ] {
        let plain = run(root.path(), &args, b"");
        let mut flagged = args.clone();
        flagged.push("--json");
        let json = run(root.path(), &flagged, b"");
        assert_eq!(plain.code, Some(1), "{args:?}: {}", plain.stderr);
        assert_eq!(
            (json.code, json.stdout.as_str(), json.stderr.as_str()),
            (plain.code, "", plain.stderr.as_str()),
            "{args:?}"
        );
    }
}
