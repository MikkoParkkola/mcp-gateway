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
        super::canonical(&dir.path().join("report.pdf")).unwrap()
    );
}

/// MIK-7911: only a verbatim drive path has a plain spelling to try.
#[test]
fn only_a_verbatim_drive_path_has_a_plain_spelling() {
    for (verbatim, plain) in [
        (r"\\?\C:\x\design.fig", Some(r"C:\x\design.fig")),
        (r"\\?\d:\", Some(r"d:\")),
        (r"\\?\UNC\server\share\x", None),
        (r"\\?\Volume{0}\x", None),
        (r"C:\x", None),
        ("/srv/uploads/x", None),
    ] {
        assert_eq!(super::plain(verbatim), plain, "{verbatim}");
    }
}

/// MIK-7911: on Windows a confined path reaches the child in the plain drive
/// form, not the verbatim one `canonicalize` returns, so a server that
/// resolves only one side of its prefix check still agrees.
#[cfg(windows)]
#[test]
fn a_confined_path_has_no_verbatim_prefix_on_windows() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("report.pdf"), b"x").unwrap();
    let got = confine("report.pdf", "uploads", &roots(dir.path())).unwrap();
    let shown = got.display().to_string();
    assert!(!shown.starts_with(r"\\?\"), "{shown}");
}

/// MIK-7911: a name the plain form reads differently (here a trailing dot,
/// which the plain form drops) is confined and handed on verbatim, so the
/// child gets the file that was checked.
#[cfg(windows)]
#[test]
fn a_name_the_plain_form_reads_differently_stays_verbatim_on_windows() {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    std::fs::write(root.join("name."), b"x").unwrap();
    let got = confine("name.", "uploads", &roots(dir.path())).unwrap();
    assert_eq!(got, root.join("name."), "the checked file, verbatim");
    // Only the verbatim form can remove it; the temp dir's cleanup cannot.
    std::fs::remove_file(root.join("name.")).unwrap();
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

    // MIK-7882.REDACT.1: the child received the token (it echoes it), and the
    // caller receives the answer without it.
    let ok = call(&probe("echo", props, &auth, token_env)).await.unwrap();
    assert_eq!(ok["test_values"]["CAP_EXEC_TEST_TOKEN"], "[redacted]");
    assert!(!ok.to_string().contains(token), "success leaked it: {ok}");
    assert!(
        !ok["argv"].to_string().contains(token),
        "the token never travels in argv"
    );

    // The same under `output: text`, which wraps the whole stdout.
    let text = call(&probe(
        "echo",
        props,
        &auth,
        &format!("{token_env}      output: text\n"),
    ))
    .await
    .unwrap();
    let text = text["text"].as_str().unwrap();
    assert!(!text.contains(token), "text output leaked it: {text}");
    assert!(text.contains("[redacted]"), "{text}");

    // And a long answer is returned whole, not cut to a 2 KiB excerpt.
    let big = call(&probe(
        "big",
        props,
        &auth,
        &format!("{token_env}      output: text\n"),
    ))
    .await
    .unwrap();
    let big = big["text"].as_str().unwrap();
    assert!(!big.contains(token), "{big}");
    assert_eq!(big.len(), 6000 + "[redacted]".len(), "no truncation");

    let err = call(&probe("fail", props, &auth, token_env))
        .await
        .unwrap_err()
        .to_string();
    assert!(!err.contains(token), "token leaked into the error: {err}");
}

/// An executor whose env overlay holds `body` (one `NAME=value` per line).
fn executor_with_env(body: &str) -> (tempfile::TempDir, CapabilityExecutor) {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(".env");
    crate::gateway::test_helpers::write_owner_only(&file, body).unwrap();
    let overlay = std::sync::Arc::new(crate::config::EnvOverlay::from_paths(&[file]));
    let env = std::sync::Arc::new(crate::config::LiveEnv::new(
        overlay,
        crate::config::ResolvedEnvFiles::default(),
    ));
    (dir, CapabilityExecutor::new().with_env(env))
}

/// MIK-7953: a reserved name in `env` (HOME) never reaches the child, so its
/// value is no secret of the call and stays in the result; a declared name the
/// child does receive is still scrubbed.
#[tokio::test]
async fn a_reserved_env_name_is_not_scrubbed_from_the_result() {
    let home = "/home-7953-operator";
    let secret = "tok-7953-declared";
    let (_dir, executor) =
        executor_with_env(&format!("HOME={home}\nCAP_EXEC_TEST_TOKEN={secret}\n"));
    let cap = probe(
        &format!("echo, '{home}'"),
        "      x:\n        type: string",
        "",
        "      env: [HOME, CAP_EXEC_TEST_TOKEN]\n",
    );
    let Some(ProcessConfig::Cli(config)) = cap.providers.process.get("primary") else {
        panic!("not a cli provider");
    };
    let ok = executor
        .execute_cli(
            &cap,
            config,
            &json!({}),
            &CapabilityExecutionContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(ok["argv"][0], home, "{ok}");
    assert_eq!(
        ok["test_values"]["CAP_EXEC_TEST_TOKEN"], "[redacted]",
        "{ok}"
    );
    assert!(!ok.to_string().contains(secret), "{ok}");
}

/// MIK-7953's safety claim: a reserved name declared in `env` never delivers
/// the operator's value to the child; the child sees the value the gateway
/// sets. Unscrubbing HOME from results rests on this.
#[tokio::test]
async fn a_reserved_env_name_never_delivers_the_operator_value() {
    let home = "/home-7953-operator";
    let (_dir, executor) = executor_with_env(&format!("HOME={home}\n"));
    let cap = probe(
        "echo",
        "      x:\n        type: string",
        "",
        "      env: [HOME]\n",
    );
    let Some(ProcessConfig::Cli(config)) = cap.providers.process.get("primary") else {
        panic!("not a cli provider");
    };
    let ok = executor
        .execute_cli(
            &cap,
            config,
            &json!({}),
            &CapabilityExecutionContext::default(),
        )
        .await
        .unwrap();
    let seen = ok["home"].as_str().expect("the probe reports HOME");
    assert!(!seen.is_empty(), "{ok}");
    assert_ne!(seen, home, "the child got the operator's HOME: {ok}");
}

/// MIK-7955.FIX.1: no secret survives in the output, whether it is part of
/// the marker or formed where the marker meets the text around it.
#[test]
fn the_marker_never_reproduces_a_secret() {
    let secrets = ["redacted".to_owned()];
    let out = super::redact_untruncated("x redacted y", &secrets, &[]);
    assert!(!out.contains("redacted"), "{out}");

    // `]x` is not in the input; a marker ending in `]` would create it.
    let secrets = ["SECRET-1".to_owned(), "]x".to_owned()];
    let out = super::redact_untruncated("SECRET-1x", &secrets, &[]);
    assert!(!out.contains("]x") && !out.contains("SECRET-1"), "{out}");

    let secrets = ["redacted".to_owned()];
    let mut value = json!({"k": "redacted", "redacted": 1, "pin": 12_345_678});
    super::redact_value(&mut value, &secrets);
    assert!(!value.to_string().contains("redacted"), "{value}");
}

/// MIK-7955.FIX.2: many short matches cannot grow the output past the input
/// by more than one marker.
#[test]
fn redacted_output_is_capped_relative_to_the_input() {
    let text = "sX".repeat(1000);
    let secrets = ["s".to_owned()];
    let out = super::redact_untruncated(&text, &secrets, &[]);
    assert!(!out.contains('s'), "{out}");
    assert!(
        out.len() <= text.len() + "[redacted]".len(),
        "{}",
        out.len()
    );

    let mut value = json!({ "k": text });
    super::redact_value(&mut value, &secrets);
    let got = value["k"].as_str().unwrap();
    assert!(
        got.len() <= text.len() + "[redacted]".len(),
        "{}",
        got.len()
    );
}

/// MIK-7955.FIX.1 on the other paths: a redacted number takes a marker free of
/// every secret, a renamed key skips a suffix that forms one, and text whose
/// every marker holds a secret is dropped whole.
#[test]
fn every_marker_path_avoids_the_secrets() {
    let secrets = ["redacted".to_owned(), "12345678".to_owned()];
    let mut value = json!({"pin": 12_345_678});
    super::redact_value(&mut value, &secrets);
    let text = value.to_string();
    assert!(
        !text.contains("redacted") && !text.contains("12345678"),
        "{text}"
    );

    // Both keys collapse to `x[redacted]`; the second may not become `#2`.
    let secrets = ["k1".to_owned(), "k2".to_owned(), "#2".to_owned()];
    let mut value = json!({"xk1": 1, "xk2": 2});
    super::redact_value(&mut value, &secrets);
    let keys: Vec<&String> = value.as_object().unwrap().keys().collect();
    assert_eq!(keys.len(), 2, "{value}");
    assert!(keys.iter().all(|k| !k.contains("#2")), "{value}");

    let secrets = ["redacted", "removed", "hidden"].map(str::to_owned);
    let out = super::redact_untruncated("a redacted b", &secrets, &[]);
    assert!(secrets.iter().all(|s| !out.contains(s.as_str())), "{out}");
}
