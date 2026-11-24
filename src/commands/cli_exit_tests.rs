// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test plan T9a (the secret gate, unit level) and T10 (the emitter). Every expected output is written
//! out by hand from the redactor's rule (`src/security/secret_redaction.rs:124`: each covered run becomes
//! `[redacted]`) and the gate's (redact each field; if the printed text still holds a secret, the fixed sentence;
//! if that holds one too, nothing). No expected value is computed by the code under test.

use super::*;

const UNPRINTABLE: &str =
    "error: The error report could not be printed without exposing the credential.\n";

/// One secret's error: the message and the remedy both hold it; HTTP 404 so the JSON form's fixed fields can.
fn planted(secret: &str) -> CliError {
    let mut error = CliError::new(
        CliExit::NotFound,
        format!("The gateway said {secret}."),
        format!("Check {secret}, then retry."),
    );
    error.http_status = Some(404);
    error
}

/// The JSON form of [`planted`]'s error with the message and remedy given, as a literal document.
fn planted_json(message: &str, remedy: &str) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "error": {
            "kind": "NotFound",
            "message": message,
            "remedy": remedy,
            "http_status": 404,
            "request_id": null,
        }
    })
}

/// What stderr must be: exact text, or one JSON document (parsed, so key order is not pinned) and a newline.
#[derive(Debug)]
enum Want {
    Text(&'static str),
    Json(serde_json::Value),
}

fn matches(stderr: &str, want: &Want) -> bool {
    match want {
        Want::Text(text) => stderr == *text,
        Want::Json(value) => {
            stderr.ends_with('\n')
                && stderr.matches('\n').count() == 1
                && serde_json::from_str::<serde_json::Value>(stderr)
                    .ok()
                    .as_ref()
                    == Some(value)
        }
    }
}

const HUMAN_REDACTED: &str = "error: The gateway said [redacted].\nCheck [redacted], then retry.\n";

/// T9a: each corpus secret through `CliError::outcome`, human and JSON; the exit is always the error's own.
#[test]
fn the_error_gate_redacts_or_falls_back_per_secret() {
    let redacted = || {
        planted_json(
            "The gateway said [redacted].",
            "Check [redacted], then retry.",
        )
    };
    let cases: Vec<(&str, Want, Want)> = vec![
        // 404 is the JSON form's http_status, which is never redacted.
        ("404", Want::Text(HUMAN_REDACTED), Want::Text(UNPRINTABLE)),
        (
            "Not Found",
            Want::Text(HUMAN_REDACTED),
            Want::Json(redacted()),
        ),
        ("OK", Want::Text(HUMAN_REDACTED), Want::Json(redacted())),
        // "error" is the human prefix and the JSON key, and a word of the fixed sentence: nothing prints.
        ("error", Want::Text(""), Want::Text("")),
        (
            "schema_version",
            Want::Text(HUMAN_REDACTED),
            Want::Text(UNPRINTABLE),
        ),
        ("{", Want::Text(HUMAN_REDACTED), Want::Text(UNPRINTABLE)),
        ("\"", Want::Text(HUMAN_REDACTED), Want::Text(UNPRINTABLE)),
        (
            "retry",
            Want::Text("error: The gateway said [redacted].\nCheck [redacted], then [redacted].\n"),
            Want::Json(planted_json(
                "The gateway said [redacted].",
                "Check [redacted], then [redacted].",
            )),
        ),
        ("tok\n", Want::Text(HUMAN_REDACTED), Want::Json(redacted())),
        (
            "to\u{7}k",
            Want::Text(HUMAN_REDACTED),
            Want::Json(redacted()),
        ),
    ];
    let mut misses = Vec::new();
    for (secret, human, json) in cases {
        for (form, want) in [(false, human), (true, json)] {
            let out = planted(secret).outcome(form, &[secret]);
            if !(matches(out.stderr(), &want)
                && out.exit() == CliExit::NotFound
                && out.stdout().is_empty())
            {
                misses.push(format!(
                    "{secret:?} json={form}: exit {:?}, stderr {:?}, want {want:?}",
                    out.exit(),
                    out.stderr()
                ));
            }
        }
    }
    assert!(misses.is_empty(), "{}", misses.join("\n"));
}

/// T9a, two secrets (gpt r2): every secret is redacted, and the fallback is checked against every secret.
#[test]
fn the_error_gate_checks_every_secret() {
    let mut misses = Vec::new();
    // The email is redacted as the token is.
    let out = CliError::new(
        CliExit::AuthRefused,
        "No lookup for person@corp.test with tok-a.",
        "Retry later.",
    )
    .outcome(false, &["tok-a", "person@corp.test"]);
    if out.stderr() != "error: No lookup for [redacted] with [redacted].\nRetry later.\n" {
        misses.push(format!("email redacted: {:?}", out.stderr()));
    }
    // The token forces the JSON form's fallback; the cursor is a word of the fixed sentence: nothing prints.
    let out = CliError::new(CliExit::AuthRefused, "refused", "Retry later.")
        .outcome(true, &["schema_version", "credential"]);
    if (out.stderr(), out.exit()) != ("", CliExit::AuthRefused) {
        misses.push(format!(
            "unsafe fallback: {:?} {:?}",
            out.stderr(),
            out.exit()
        ));
    }
    assert!(misses.is_empty(), "{}", misses.join("\n"));
}

const UNSAFE_WHAT: &str = "The response could not be printed safely.";
const UNSAFE_REMEDY: &str = "The response was received but could not be printed safely; inspect the gateway state before sending the request again.";

/// T9a, successes: the stderr note is redacted per secret under either rule; stdout is printed as given.
#[test]
fn the_success_note_is_redacted_per_secret() {
    let corpus = [
        "404",
        "Not Found",
        "OK",
        "error",
        "schema_version",
        "{",
        "\"",
        "retry",
        "tok\n",
        "to\u{7}k",
    ];
    let mut misses = Vec::new();
    for secret in corpus {
        for rule in [StdoutRule::RefuseToken, StdoutRule::RedactedJsonBody] {
            let note = format!("Note {secret} here.\n");
            let out = CliOutcome::success(b"data\n".to_vec(), &note, false, &[secret], rule);
            let got = (out.exit(), out.stdout(), out.stderr());
            if got != (CliExit::Ok, &b"data\n"[..], "Note [redacted] here.\n") {
                misses.push(format!("{secret:?} {rule:?}: {got:?}"));
            }
        }
    }
    assert!(misses.is_empty(), "{}", misses.join("\n"));
}

/// T9a, D6: `RefuseToken` refuses stdout still holding the token, in both forms; it does not refuse the email (data);
/// `RedactedJsonBody` (api) prints its already-checked body as given.
#[test]
fn stdout_rules_refuse_only_the_token() {
    let mut misses = Vec::new();
    let held = b"{\"a\":\"tok-a\"}\n".to_vec();
    let out = CliOutcome::success(held.clone(), "", false, &["tok-a"], StdoutRule::RefuseToken);
    let human = format!("error: {UNSAFE_WHAT}\n{UNSAFE_REMEDY}\n");
    if (out.exit(), out.stdout(), out.stderr()) != (CliExit::LocalFailure, &b""[..], human.as_str())
    {
        misses.push(format!(
            "refused human: {:?} {:?}",
            out.exit(),
            out.stderr()
        ));
    }
    let out = CliOutcome::success(held.clone(), "", true, &["tok-a"], StdoutRule::RefuseToken);
    let want = Want::Json(serde_json::json!({
        "schema_version": 1,
        "error": {
            "kind": "LocalFailure",
            "message": UNSAFE_WHAT,
            "remedy": UNSAFE_REMEDY,
            "http_status": null,
            "request_id": null,
        }
    }));
    if !(out.exit() == CliExit::LocalFailure
        && out.stdout().is_empty()
        && matches(out.stderr(), &want))
    {
        misses.push(format!("refused json: {:?} {:?}", out.exit(), out.stderr()));
    }
    let email = b"{\"rows\":[\"person@corp.test\"]}\n".to_vec();
    let out = CliOutcome::success(
        email.clone(),
        "",
        false,
        &["tok-a", "person@corp.test"],
        StdoutRule::RefuseToken,
    );
    if (out.exit(), out.stdout(), out.stderr()) != (CliExit::Ok, email.as_slice(), "") {
        misses.push(format!(
            "email is data: {:?} {:?}",
            out.exit(),
            out.stdout()
        ));
    }
    let out = CliOutcome::success(
        held.clone(),
        "",
        false,
        &["tok-a"],
        StdoutRule::RedactedJsonBody,
    );
    if (out.exit(), out.stdout(), out.stderr()) != (CliExit::Ok, held.as_slice(), "") {
        misses.push(format!(
            "api body as given: {:?} {:?}",
            out.exit(),
            out.stdout()
        ));
    }
    assert!(misses.is_empty(), "{}", misses.join("\n"));
}

/// A writer that fails every write with `kind`.
struct Failing(std::io::ErrorKind);

impl std::io::Write for Failing {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from(self.0))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `emit_to` with a stdout failing with `kind`: the exit and what reached stderr.
fn emitted_with_stdout(kind: std::io::ErrorKind, json: bool, token: &str) -> (CliExit, String) {
    let ok = CliOutcome::success(
        b"data\n".to_vec(),
        "",
        json,
        &[token],
        StdoutRule::RefuseToken,
    );
    let mut stderr = Vec::new();
    let exit = emit_to(&ok, json, &[token], &mut Failing(kind), &mut stderr);
    (exit, String::from_utf8(stderr).expect("utf-8"))
}

const WRITE_FAILED: &str = "error: Could not write command output.\nCheck the output destination before repeating the command.\n";

/// T10: a closed reader ends quietly with 0; any other stdout failure is the gated write error, exit 1.
#[test]
fn the_emitter_maps_write_failures() {
    use std::io::ErrorKind::{BrokenPipe, Other};
    let mut misses = Vec::new();
    for (case, got, want) in [
        ("broken pipe", emitted_with_stdout(BrokenPipe, false, "tok-9680"), (CliExit::Ok, String::new())),
        ("other", emitted_with_stdout(Other, false, "tok-9680"), (CliExit::LocalFailure, WRITE_FAILED.to_string())),
        // A word of the remedy only is redacted; no fixed field holds it, so the report still prints.
        (
            "remedy word",
            emitted_with_stdout(Other, false, "destination"),
            (
                CliExit::LocalFailure,
                "error: Could not write command output.\nCheck the output [redacted] before repeating the command.\n"
                    .to_string(),
            ),
        ),
        (
            "message and remedy word",
            emitted_with_stdout(Other, false, "output"),
            (
                CliExit::LocalFailure,
                "error: Could not write command [redacted].\nCheck the [redacted] destination before repeating the command.\n"
                    .to_string(),
            ),
        ),
        // "error" is the human prefix and a word of the fixed sentence: nothing prints, the exit stands.
        ("prefix word", emitted_with_stdout(Other, false, "error"), (CliExit::LocalFailure, String::new())),
        // The JSON form's kind is never redacted: the fixed sentence instead.
        (
            "kind word",
            emitted_with_stdout(Other, true, "LocalFailure"),
            (CliExit::LocalFailure, UNPRINTABLE.to_string()),
        ),
    ] {
        if got != want {
            misses.push(format!("{case}: {got:?}, want {want:?}"));
        }
    }
    // stderr failing on an outcome that exits 3 (api_stream.rs:155-157 before the move): exit 1.
    let refused = CliError::new(
        CliExit::AuthRefused,
        "The gateway rejected this credential.",
        "Retry.",
    )
    .outcome(false, &["tok-9680"]);
    let exit = emit_to(
        &refused,
        false,
        &["tok-9680"],
        &mut Vec::new(),
        &mut Failing(Other),
    );
    if exit != CliExit::LocalFailure {
        misses.push(format!("stderr failure: {exit:?}"));
    }
    // dashboard-link's note with the token "once", a word of it (its link holds no token): the note is redacted.
    let note = CliOutcome::success(
        b"https://gw.test/x\n".to_vec(),
        "Opens once, from this machine only.\n",
        false,
        &["once"],
        StdoutRule::RefuseToken,
    );
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let exit = emit_to(&note, false, &["once"], &mut stdout, &mut stderr);
    let got = (exit, stdout, String::from_utf8(stderr).expect("utf-8"));
    let want = (
        CliExit::Ok,
        b"https://gw.test/x\n".to_vec(),
        "Opens [redacted], from this machine only.\n".to_string(),
    );
    if got != want {
        misses.push(format!("note: {got:?}"));
    }
    assert!(misses.is_empty(), "{}", misses.join("\n"));
}

/// U2 (MIK-9764.JSONF.1, the JSON forms design D9): with `json` the gate also scans the decoded document. A token holding `"` or `\` is
/// escaped by JSON, so the byte search alone cannot see it: each case first proves the raw token is absent from the
/// bytes, then that the gate still refuses it in a nested object value, an array item and an object key (each
/// alone), and that the same shapes without it pass.
#[test]
fn the_json_gate_scans_decoded_strings() {
    let mut misses = Vec::new();
    for token in ["tok\"quoted-0123456789", "tok\\slashed-0123456789"] {
        let mut keyed = serde_json::Map::new();
        keyed.insert(token.to_owned(), serde_json::json!(1));
        let cases = [
            (
                "nested value",
                serde_json::json!({"schema_version": 1, "a": {"b": format!("x{token}y")}}),
            ),
            (
                "array item",
                serde_json::json!({"schema_version": 1, "a": [1, token]}),
            ),
            (
                "object key",
                serde_json::json!({"schema_version": 1, "a": keyed}),
            ),
        ];
        for (place, doc) in cases {
            let bytes = format!("{doc}\n").into_bytes();
            assert!(
                !bytes.windows(token.len()).any(|w| w == token.as_bytes()),
                "{place}: the raw token is in the bytes, so this case would not need the decoded scan"
            );
            let out = CliOutcome::success(bytes, "", true, &[token], StdoutRule::RefuseToken);
            if !(out.exit() == CliExit::LocalFailure && out.stdout().is_empty()) {
                misses.push(format!("{token:?} in a {place} passed: {:?}", out.exit()));
            }
        }
        let clean = format!(
            "{}\n",
            serde_json::json!({"schema_version": 1, "a": {"b": "x"}, "c": ["y"], "d": {"k": 1}})
        )
        .into_bytes();
        let out = CliOutcome::success(clean.clone(), "", true, &[token], StdoutRule::RefuseToken);
        if (out.exit(), out.stdout()) != (CliExit::Ok, clean.as_slice()) {
            misses.push(format!(
                "{token:?}: a document without it was refused: {:?}",
                out.stderr()
            ));
        }
    }
    let plain = b"https://gw.test/#k=tok-plain-0123456789\n".to_vec();
    let out = CliOutcome::success(
        plain,
        "",
        false,
        &["tok-plain-0123456789"],
        StdoutRule::RefuseToken,
    );
    if out.exit() != CliExit::LocalFailure {
        misses.push(format!(
            "text mode: the byte search passed a plain token: {:?}",
            out.exit()
        ));
    }
    assert!(misses.is_empty(), "{}", misses.join("\n"));
}

// The three local exits (rows U1-U9). Every expected value is a literal.

/// U1: every line break becomes one space, so content cannot split the two-line shape.
#[test]
fn one_line_writes_a_line_break_as_a_space() {
    assert_eq!(one_line("a\nb"), "a b", "LF");
    assert_eq!(one_line("a\r\nb"), "a b", "CR LF is one break");
    assert_eq!(one_line("a\n\nb"), "a  b", "one space per break");
    assert_eq!(one_line("a b"), "a b", "no break, no change");
    assert_eq!(one_line(""), "", "empty stays empty");
    assert_eq!(one_line("a\rb"), "a b", "a lone CR");
}

/// U2: the usage remedy names the command's own help; two commands, so a fixed sentence fails.
#[test]
fn the_usage_remedy_names_the_commands_help() {
    assert_eq!(
        usage_remedy("cap list"),
        "Run 'mcp-gateway cap list --help' for usage."
    );
    assert_eq!(
        usage_remedy("doctor"),
        "Run 'mcp-gateway doctor --help' for usage."
    );
}

/// U3: an empty remedy is a bug at the call site, caught before anything is written.
#[test]
#[should_panic(expected = "remedy")]
fn fail_refuses_an_empty_remedy() {
    let _ = fail(CliExit::LocalFailure, "m", "");
}

/// U4: the local codes are the literals 0, 1 and 2.
#[test]
fn the_local_codes_are_zero_one_and_two() {
    assert_eq!(CliExit::Ok.code(), 0);
    assert_eq!(CliExit::LocalFailure.code(), 1);
    assert_eq!(CliExit::Usage.code(), 2);
}

/// U5: the remote commands' error text is not folded: `outcome` writes what it is given.
#[test]
fn the_remote_error_text_is_not_folded() {
    let out = CliError::new(CliExit::Usage, "a\nb", "r").outcome(false, &[]);
    assert_eq!(out.stderr(), "error: a\nb\nr\n");
}

/// U6: `fail`'s outcome folds both lines and keeps the kind it is given.
#[test]
fn fail_builds_the_two_line_outcome() {
    let out = error_outcome(CliExit::LocalFailure, "m\nx", "r\ny");
    assert_eq!(out.stderr(), "error: m x\nr y\n", "both fields folded");
    assert!(out.stdout().is_empty(), "nothing on stdout");
    assert_eq!(out.exit(), CliExit::LocalFailure);
    let usage_kind = error_outcome(CliExit::Usage, "m", "r");
    assert_eq!(usage_kind.exit(), CliExit::Usage, "the kind passes through");
}

/// U7: `usage`'s outcome is exit 2 with the help remedy.
#[test]
fn usage_builds_the_usage_outcome() {
    let out = usage_outcome("tls issue-server", "bad");
    assert_eq!(
        out.stderr(),
        "error: bad\nRun 'mcp-gateway tls issue-server --help' for usage.\n"
    );
    assert_eq!(out.exit(), CliExit::Usage);
}

/// U8: `verdict` returns the code it is given (compared as the repo does, by Debug text).
#[test]
fn verdict_returns_its_code() {
    let code = |exit: std::process::ExitCode| format!("{exit:?}");
    assert_eq!(code(verdict(3)), code(std::process::ExitCode::from(3)));
    assert_eq!(code(verdict(1)), code(std::process::ExitCode::from(1)));
    assert_ne!(code(verdict(1)), code(verdict(3)), "two codes stay apart");
}

/// U9: `fail` returns its kind's code: 2 for usage, 1 for a local failure.
#[test]
fn fail_returns_the_kinds_code() {
    let code = |exit: std::process::ExitCode| format!("{exit:?}");
    assert_eq!(
        code(fail(CliExit::Usage, "m", "r")),
        code(std::process::ExitCode::from(2))
    );
    assert_eq!(
        code(fail(CliExit::LocalFailure, "m", "r")),
        code(std::process::ExitCode::from(1))
    );
}
