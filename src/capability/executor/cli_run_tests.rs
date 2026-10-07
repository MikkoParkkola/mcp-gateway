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
use crate::capability::{CapabilityDefinition, CapabilityExecutionContext, parse_capability};

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
        .execute_cli(
            cap,
            config(cap),
            &params,
            &CapabilityExecutionContext::default(),
        )
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

/// Whether `pid` names a running process.
#[cfg(unix)]
fn alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap()
        .success()
}

/// Whether `pid` names a running process.
#[cfg(windows)]
fn alive(pid: u32) -> bool {
    let out = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
        .output()
        .unwrap();
    // A failed query is not evidence that the process is gone.
    assert!(out.status.success(), "tasklist failed: {out:?}");
    let pid = pid.to_string();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .any(|row| row.split(',').nth(1).map(|f| f.trim_matches('"')) == Some(pid.as_str()))
}

/// Whether `pid` is gone within five seconds.
async fn gone_within_five_seconds(pid: u32) -> bool {
    for _ in 0..50 {
        if !alive(pid) {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    false
}

/// The grandchild's pid, once `argv_echo.py grandchild` has written it.
async fn grandchild_pid(pidfile: &Path) -> u32 {
    for _ in 0..200 {
        if let Some(pid) = std::fs::read_to_string(pidfile)
            .ok()
            .and_then(|text| text.trim().parse().ok())
        {
            return pid;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("no grandchild pid in {}", pidfile.display());
}

#[cfg(unix)]
#[tokio::test]
async fn a_timeout_kills_the_child_and_its_grandchild() {
    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("grandchild.pid");
    let cap = capability("grandchild", &format!("'{}'", pidfile.display()), "", 5);
    let err = call(&cap, json!({})).await.unwrap_err().to_string();
    assert!(err.contains("did not finish"), "{err}");
    let pid = grandchild_pid(&pidfile).await;
    assert!(
        gone_within_five_seconds(pid).await,
        "grandchild {pid} outlived the timeout"
    );
}

/// MIK-7815.FIX.2 and FIX.3: a call aborted while its child runs tears down
/// the whole tree, the grandchild included: the process group on Unix, the
/// Job on Windows.
#[tokio::test]
async fn an_aborted_call_kills_the_child_and_its_grandchild() {
    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("grandchild.pid");
    let cap = capability("grandchild", &format!("'{}'", pidfile.display()), "", 60);
    let task = tokio::spawn(async move { call(&cap, json!({})).await });
    let pid = grandchild_pid(&pidfile).await;
    assert!(
        alive(pid),
        "premise: grandchild {pid} runs before the abort"
    );
    task.abort();
    assert!(
        task.await.unwrap_err().is_cancelled(),
        "the call was aborted"
    );
    assert!(
        gone_within_five_seconds(pid).await,
        "grandchild {pid} outlived the aborted call"
    );
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

#[test]
fn an_allowlisted_name_cannot_override_the_private_directories() {
    let workdir = Path::new("/private-workdir");
    let lookup = |_: &str| Some(std::ffi::OsString::from("/operator/home"));
    let allowed = [
        "HOME".to_owned(),
        "xdg_config_home".to_owned(),
        "TmpDir".to_owned(),
    ];
    let env = super::child_env(workdir, &allowed, &lookup, Some(("HOME", "x")));
    let home: Vec<_> = env.iter().filter(|(k, _)| k == "HOME").collect();
    assert_eq!(home.len(), 1, "{env:?}");
    assert_eq!(home[0].1.as_os_str(), workdir.as_os_str());
    // The platform baseline (PATH, SYSTEMROOT) is resolved through the same
    // lookup and legitimately carries its value; only the directories the
    // gateway makes private must not.
    for (key, value) in &env {
        if [
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "XDG_DATA_HOME",
            "TMPDIR",
            "TMP",
            "TEMP",
        ]
        .contains(&key.to_string_lossy().as_ref())
        {
            assert_ne!(value, "/operator/home", "{key:?} was overridden: {env:?}");
        }
    }
}

#[tokio::test]
async fn a_refused_credential_is_the_typed_unauthorized_error() {
    let cap = capability("unauthorized", "x", "", 30);
    let err = call(&cap, json!({})).await.unwrap_err();
    assert!(
        crate::security::http_diagnostics::is_upstream_unauthorized(&err),
        "{err}"
    );
}

#[test]
fn a_typed_process_config_survives_serialization() {
    let cap = capability("echo", "x", "", 30);
    let out = serde_json::to_value(&cap.providers).unwrap();
    assert_eq!(
        out["named"]["primary"]["config"]["command"],
        python().display().to_string()
    );
}

/// T6: a `.cmd` shim (how npm installs gws on Windows) is resolved and run
/// through std's batch-argument escaping: a hostile value arrives intact or the
/// call is refused, and is never expanded or split by cmd.exe.
#[cfg(windows)]
#[tokio::test]
async fn a_cmd_shim_receives_hostile_values_literally_or_refuses_them() {
    let dir = tempfile::tempdir().unwrap();
    let shim = dir.path().join("probe.cmd");
    std::fs::write(
        &shim,
        format!("@\"{}\" \"{}\" echo %*\r\n", python().display(), script()),
    )
    .unwrap();
    let yaml = format!(
        "name: cmd_probe\ndescription: Cmd probe.\nschema:\n  input:\n    type: object\n\
         providers:\n  primary:\n    service: cli\n    timeout: 30\n    config:\n      \
         command: '{}'\n      args: [\"--to={{to}}\", \"--\", \"{{file}}\"]\n",
        shim.display()
    );
    let cap = parse_capability(&yaml).expect("cmd probe parses");
    let plain = call(&cap, json!({"to": "plain", "file": "plain"}))
        .await
        .expect("a benign call through the shim succeeds");
    assert_eq!(plain["argv"], json!(["--to=plain", "--", "plain"]));
    for hostile in ["%PATH%", "^&|<>", "\"q\" 'q'", "a b", "!VAR!", "--draft"] {
        match call(&cap, json!({"to": hostile, "file": hostile})).await {
            Ok(out) => assert_eq!(
                out["argv"],
                json!([format!("--to={hostile}"), "--", hostile]),
                "{hostile:?} was altered on its way through the shim"
            ),
            Err(e) => assert!(
                e.to_string().contains("invalid input"),
                "{hostile:?}: unexpected failure {e}"
            ),
        }
    }
}

#[test]
fn a_secret_straddling_the_excerpt_cut_is_removed_whole() {
    let secret = "SECRET-straddles-the-cut-7782";
    // Before the fix the excerpt was cut first, at 2 KiB from the end: this
    // places the secret across that boundary.
    let text = format!("{}{secret}{}", "x".repeat(3000), "y".repeat(2040));
    let out = super::super::cli::redact(&text, &[secret.to_owned()], &[]);
    assert!(
        !out.contains("SECRET-str") && !out.contains("cut-7782"),
        "{out}"
    );
}

/// MIK-7882.REDACT.3: a redacted success keeps its structure and its length.
#[test]
fn success_redaction_keeps_json_valid_and_does_not_truncate() {
    let secret = "SECRET-7882-value";
    let long = format!("{}{secret}{}", "x".repeat(5000), "y".repeat(5000));
    let mut value = json!({
        "n": 7,
        "ok": true,
        "nested": [{"s": long.clone()}, secret, null],
        secret: "key carries it",
    });
    super::super::cli::redact_value(&mut value, &[secret.to_owned()]);
    let text = value.to_string();
    assert!(!text.contains(secret), "{text}");
    let back: Value = serde_json::from_str(&text).expect("still a JSON document");
    assert_eq!(back["n"], 7);
    assert_eq!(back["ok"], true);
    assert!(back["nested"][1].is_string(), "a string stays a string");
    assert_eq!(back["nested"][1], "[redacted]");
    assert_eq!(
        back["nested"][0]["s"].as_str().unwrap().len(),
        10_000 + "[redacted]".len(),
        "no 2 KiB cut"
    );
    assert_eq!(back["[redacted]"], "key carries it");
}

#[test]
fn a_renamed_key_never_takes_the_name_of_one_that_stays() {
    // `SECRET` becomes `[redacted]`; the key that already had that name keeps
    // its own value, and the renamed one gets the next free name.
    let mut value = json!({"[redacted]": 1, "SECRET": 2});
    super::super::cli::redact_value(&mut value, &["SECRET".to_owned()]);
    assert_eq!(value["[redacted]"], 1, "{value}");
    assert_eq!(value["[redacted]#2"], 2, "{value}");
    assert_eq!(value.as_object().unwrap().len(), 2);
}

#[test]
fn a_renamed_key_skips_every_name_already_taken() {
    let mut value = json!({"[redacted]": 1, "[redacted]#2": 2, "SECRET": 3});
    super::super::cli::redact_value(&mut value, &["SECRET".to_owned()]);
    assert_eq!(value["[redacted]#2"], 2, "{value}");
    assert_eq!(value["[redacted]#3"], 3, "{value}");
    assert_eq!(value.as_object().unwrap().len(), 3);
}

#[test]
fn many_keys_that_collapse_to_the_marker_all_survive() {
    // Fifty secrets, each also a key: every key renames to the same marker.
    let secrets: Vec<String> = (0..50).map(|i| format!("SECRET-{i:02}")).collect();
    let map: serde_json::Map<String, Value> =
        secrets.iter().map(|s| (s.clone(), json!(s))).collect();
    let mut value = Value::Object(map);
    super::super::cli::redact_value(&mut value, &secrets);
    assert_eq!(value.as_object().unwrap().len(), 50, "{value}");
    assert!(!value.to_string().contains("SECRET-"), "{value}");
}

#[test]
fn an_all_digit_credential_does_not_survive_as_a_json_number() {
    let mut value = json!({"pin": 4_815_162_342_u64, "count": 3, "nested": [4_815_162_342_u64]});
    super::super::cli::redact_value(&mut value, &["4815162342".to_owned()]);
    assert_eq!(value["pin"], "[redacted]", "{value}");
    assert_eq!(value["nested"][0], "[redacted]", "{value}");
    assert_eq!(value["count"], 3, "an unrelated number is untouched");

    // A short needle would hit every number: numbers are only checked from 4 bytes.
    let mut value = json!({"n": 1234});
    super::super::cli::redact_value(&mut value, &["1".to_owned()]);
    assert_eq!(value["n"], 1234);
}

#[test]
fn untruncated_redaction_keeps_the_whole_text() {
    let text = format!("{}tok{}", "a".repeat(4000), "b".repeat(4000));
    let out = super::super::cli::redact_untruncated(&text, &["tok".to_owned()], &[]);
    assert_eq!(out.len(), 8000 + "[redacted]".len());
}

#[test]
fn overlapping_credentials_leave_no_fragment_of_either() {
    let secrets = ["abcdef".to_owned(), "cdefgh".to_owned()];
    let out = super::super::cli::redact_untruncated("x abcdefgh y", &secrets, &[]);
    assert_eq!(out, "x [redacted] y");
    let mut value = json!({"k": "abcdefgh"});
    super::super::cli::redact_value(&mut value, &secrets);
    assert_eq!(value["k"], "[redacted]");

    // A value that overlaps itself: no tail of it survives.
    let out = super::super::cli::redact_untruncated("xabababy", &["abab".to_owned()], &[]);
    assert_eq!(out, "x[redacted]y");
}

/// A multi-line injected credential (a PEM key) is removed whole: the scanner
/// must not get to cut its header out first and leave the body matchable by
/// nobody.
#[test]
fn an_injected_multi_line_key_is_removed_whole() {
    let key = format!(
        "-----BEGIN {0} KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nabcdef0123456789\n-----END {0} KEY-----",
        "PRIVATE"
    );
    let text = format!("echo: {key} done");
    let out = super::super::cli::redact_untruncated(&text, std::slice::from_ref(&key), &[]);
    assert!(!out.contains("MIIEvQIBADANBg"), "{out}");
    assert!(!out.contains("abcdef0123456789"), "{out}");
    let mut value = json!({ "k": text });
    super::super::cli::redact_value(&mut value, &[key]);
    assert!(!value.to_string().contains("abcdef0123456789"), "{value}");
}

/// A one-character needle matches at every position of a long text (the case
/// that made one span per match costly): the whole run is one marker, and
/// not `[redacted]`, which holds the needle (MIK-7955).
#[test]
fn a_needle_that_matches_everywhere_collapses_to_one_marker() {
    let long = "a".repeat(1024 * 1024);
    let out = super::super::cli::redact_untruncated(&long, &["a".to_owned(), "a".to_owned()], &[]);
    assert_eq!(out, "<removed>");
}

/// An injected value equal to the word a credential pattern keys on does not
/// hide the credential it starts: the scanner's span, found in the original
/// text, goes with the literal.
#[cfg(feature = "firewall")]
#[test]
fn a_literal_inside_a_credential_takes_the_credential_with_it() {
    let token = "abcdef0123456789abcdef0123456789";
    let text = format!("auth: Bearer {token} done");
    let secrets = ["Bearer".to_owned()];
    let out = super::super::cli::redact_untruncated(&text, &secrets, &[]);
    assert!(!out.contains(token), "{out}");
    assert!(out.ends_with(" done"), "{out}");
    let mut value = json!({ "k": text });
    super::super::cli::redact_value(&mut value, &secrets);
    assert!(!value.to_string().contains(token), "{value}");
}

/// A long needle that overlaps itself at every position: the search is linear,
/// so a megabyte of it ends as one marker without stalling the worker.
#[test]
fn a_long_self_overlapping_needle_collapses_to_one_marker() {
    let text = "a".repeat(1024 * 1024);
    let needle = "a".repeat(32 * 1024);
    let out = super::super::cli::redact_untruncated(&format!("x{text}y"), &[needle], &[]);
    assert_eq!(out, "x[redacted]y");
}

/// An all-digit credential past u64 comes back as a float in exponent form;
/// it is still matched, by value.
#[test]
fn a_digit_credential_past_u64_is_redacted_as_a_number() {
    let secret = "18446744073709551616".to_owned();
    let mut value: Value = serde_json::from_str(r#"{"n": 18446744073709551616}"#).unwrap();
    super::super::cli::redact_value(&mut value, &[secret]);
    assert_eq!(value["n"], "[redacted]", "{value}");
}

/// An all-digit credential with leading zeros loses them when the child prints
/// it as a JSON number: it is matched by value, not by its text.
#[test]
fn a_digit_credential_with_leading_zeros_is_redacted_as_a_number() {
    let mut value = json!({"pin": 12_345, "neg": -12_345, "other": 123_456});
    super::super::cli::redact_value(&mut value, &["012345".to_owned()]);
    assert_eq!(value["pin"], "[redacted]", "{value}");
    assert_eq!(value["neg"], "[redacted]", "{value}");
    assert_eq!(value["other"], 123_456, "a different value is untouched");

    // Past u64 the number is a float; leading zeros still do not hide it.
    let mut value: Value = serde_json::from_str(r#"{"n": 18446744073709551616}"#).unwrap();
    super::super::cli::redact_value(&mut value, &["0018446744073709551616".to_owned()]);
    assert_eq!(value["n"], "[redacted]", "{value}");

    // A float carries its sign as well: -12345.0, a negative past i64 and
    // -0.0 are the needle's value too.
    let mut value: Value =
        serde_json::from_str(r#"{"a": -12345.0, "b": -18446744073709551616, "z": -0.0}"#).unwrap();
    super::super::cli::redact_value(
        &mut value,
        &[
            "012345".to_owned(),
            "0018446744073709551616".to_owned(),
            "0000".to_owned(),
        ],
    );
    assert_eq!(value["a"], "[redacted]", "{value}");
    assert_eq!(value["b"], "[redacted]", "{value}");
    assert_eq!(value["z"], "[redacted]", "{value}");

    // The floor applies to the needle as given; once its zeros go, a short
    // value matches only a number equal to it, never one that contains it.
    let mut value = json!({"n": 7, "m": 1_771, "z": 0});
    super::super::cli::redact_value(&mut value, &["0007".to_owned(), "0000".to_owned()]);
    assert_eq!(value["n"], "[redacted]", "{value}");
    assert_eq!(value["m"], 1_771, "{value}");
    assert_eq!(value["z"], "[redacted]", "{value}");

    // A positive float and exponent input are the same value; a neighbour is not.
    let mut value: Value =
        serde_json::from_str(r#"{"f": 12345.0, "e": 1.2345e4, "near": 12346}"#).unwrap();
    super::super::cli::redact_value(&mut value, &["012345".to_owned()]);
    assert_eq!(value["f"], "[redacted]", "{value}");
    assert_eq!(value["e"], "[redacted]", "{value}");
    assert_eq!(value["near"], 12_346, "{value}");

    // Any length: a short credential is matched by value too (MIK-8065 ruling:
    // a leak is worse than blanking an equal number; the floor was meant for
    // caller values, which never reach this function).
    let mut value = json!({"n": 7});
    super::super::cli::redact_value(&mut value, &["007".to_owned()]);
    assert_eq!(value["n"], "[redacted]", "{value}");
}

/// A credential injected in number form other than plain digits, such as a
/// leading "+" or an exponent, comes back as the same number printed
/// differently. It is matched by value.
#[test]
fn a_plus_signed_credential_is_redacted_as_a_number() {
    let mut value = json!({"pin": 12_345, "neg": -12_345, "other": 12_346});
    super::super::cli::redact_value(&mut value, &["+12345".to_owned()]);
    assert_eq!(value["pin"], "[redacted]", "{value}");
    assert_eq!(value["neg"], "[redacted]", "{value}");
    assert_eq!(value["other"], 12_346, "a different value is untouched");
}

#[test]
fn an_exponent_form_credential_is_redacted_as_a_number() {
    let mut value: Value =
        serde_json::from_str(r#"{"a": 1.5e10, "b": 15000000000, "c": 1.5e11}"#).unwrap();
    super::super::cli::redact_value(&mut value, &["1.5e10".to_owned()]);
    assert_eq!(value["a"], "[redacted]", "{value}");
    // Equal in value, so it is redacted too: over-redaction is accepted.
    assert_eq!(value["b"], "[redacted]", "{value}");
    assert_ne!(
        value["c"], "[redacted]",
        "a different value is untouched: {value}"
    );
}

/// A "+" before leading zeros still names the all-digit credential.
#[test]
fn a_plus_signed_credential_with_leading_zeros_is_redacted_as_a_number() {
    let mut value = json!({"pin": 12_345, "other": 12_346});
    super::super::cli::redact_value(&mut value, &["+012345".to_owned()]);
    assert_eq!(value["pin"], "[redacted]", "{value}");
    assert_eq!(value["other"], 12_346, "a different value is untouched");
}

/// Integers past f64 precision are compared exactly, never through a float.
#[test]
fn a_large_integer_credential_redacts_only_its_own_value() {
    let mut value: Value =
        serde_json::from_str(r#"{"near": 9007199254740992, "same": 9007199254740993}"#).unwrap();
    super::super::cli::redact_value(&mut value, &["+9007199254740993".to_owned()]);
    assert_eq!(value["same"], "[redacted]", "{value}");
    assert_ne!(
        value["near"], "[redacted]",
        "an adjacent integer is untouched: {value}"
    );
}

/// "+1e5" is 4 characters as injected, so unlike "1e5" it is looked for.
#[test]
fn a_four_character_number_form_credential_is_redacted() {
    let mut value: Value = serde_json::from_str(r#"{"n": 1e5}"#).unwrap();
    super::super::cli::redact_value(&mut value, &["+1e5".to_owned()]);
    assert_eq!(value["n"], "[redacted]", "{value}");
}

/// "00.5" loses all of its leading zeros to the trim; one zero goes back
/// before the "." so it parses, and the child's 0.5 is redacted. The needle
/// is not a substring of "0.5", so only the value comparison can find it.
#[test]
fn a_credential_of_only_zeros_before_its_point_is_redacted_as_a_number() {
    let mut value: Value = serde_json::from_str(r#"{"n": 0.5}"#).unwrap();
    super::super::cli::redact_value(&mut value, &["00.5".to_owned()]);
    assert_eq!(value["n"], "[redacted]", "{value}");
}

/// The covered grammar, by construction rather than by example: an injected
/// credential in JSON number form with at most one leading sign, crossed
/// with leading zeros, integer, decimal and exponent forms, and magnitudes
/// below i64, past i64 and past u64. Each needle redacts its own value as
/// the child prints it and never the adjacent value. Adjacent values past
/// i64 and u64 sit one f64 step away, so they stay distinct after parsing.
#[test]
fn every_covered_number_form_redacts_only_its_own_value() {
    // (form, magnitude) -> (needle body, own value, adjacent value)
    let shapes = [
        ("12345", "12345", "12346"),
        (
            "9223372036854775809",
            "9223372036854775809",
            "9223372036854775808",
        ),
        (
            "18446744073709551616",
            "18446744073709551616",
            "18446744073709555712",
        ),
        ("12.5", "12.5", "12.25"),
        (
            "9223372036854775809.5",
            "9223372036854775809.5",
            "9223372036854777856.0",
        ),
        (
            "18446744073709551616.5",
            "18446744073709551616.5",
            "18446744073709555712.0",
        ),
        ("1.5e4", "1.5e4", "1.6e4"),
        ("9.3e18", "9.3e18", "9.4e18"),
        ("1.9e19", "1.9e19", "2.0e19"),
    ];
    let mut failures = Vec::new();
    for sign in ["", "+", "-"] {
        for zeros in ["", "00"] {
            for (body, own, adjacent) in shapes {
                let needle = format!("{sign}{zeros}{body}");
                let value_sign = if sign == "-" { "-" } else { "" };
                let text =
                    format!(r#"{{"own": {value_sign}{own}, "adjacent": {value_sign}{adjacent}}}"#);
                let mut value: Value = serde_json::from_str(&text).unwrap();
                super::super::cli::redact_value(&mut value, std::slice::from_ref(&needle));
                if value["own"] != "[redacted]" || value["adjacent"] == "[redacted]" {
                    failures.push(format!("{needle}: {value}"));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of 54 cases wrong:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Below the 4-character floor a needle is matched by exact JSON equality
/// only: "1e5" redacts the float 1e5 (MIK-7954), never 100000 or 1e50.
#[test]
fn a_number_form_credential_below_the_floor_matches_its_exact_value() {
    let mut value: Value = serde_json::from_str(r#"{"n": 1e5, "m": 1e50}"#).unwrap();
    super::super::cli::redact_value(&mut value, &["1e5".to_owned()]);
    assert_eq!(value["n"], "[redacted]", "{value}");
    assert_ne!(value["m"], "[redacted]", "{value}");
}

/// A digit credential past u64 is compared after the same float parse that
/// read the result. `serde_json` without `float_roundtrip` truncates past u64
/// and scales, so for this 25-digit value it lands one ULP from the correctly
/// rounded `str::parse`: a needle parsed the other way would miss the number.
/// The feature is on in every build today (jsonschema enables it), so this row
/// guards the invariant rather than reproducing a live leak.
#[test]
fn a_long_digit_credential_is_compared_with_the_result_parser() {
    let secret = "3057986828288072902227918";
    let mut value: Value =
        serde_json::from_str(&format!(r#"{{"n": {secret}, "neg": -{secret}}}"#)).unwrap();
    super::super::cli::redact_value(&mut value, &[format!("00{secret}")]);
    assert_eq!(value["n"], "[redacted]", "{value}");
    assert_eq!(value["neg"], "[redacted]", "{value}");
}
