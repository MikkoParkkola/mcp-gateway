// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test plan T9a (the secret gate, unit level) and T10 (the emitter). Every expected output is written
//! out by hand from the redactor's rule (src/security/secret_redaction.rs:124: each covered run becomes
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
            let out = CliOutcome::success(b"data\n".to_vec(), note, false, &[secret], rule);
            let got = (out.exit(), out.stdout(), out.stderr());
            if got != (CliExit::Ok, &b"data\n"[..], "Note [redacted] here.\n") {
                misses.push(format!("{secret:?} {rule:?}: {got:?}"));
            }
        }
    }
    assert!(misses.is_empty(), "{}", misses.join("\n"));
}

/// T9a, D6: RefuseToken refuses stdout still holding the token, in both forms; it does not refuse the email (data);
/// RedactedJsonBody (api) prints its already-checked body as given.
#[test]
fn stdout_rules_refuse_only_the_token() {
    let mut misses = Vec::new();
    let held = b"{\"a\":\"tok-a\"}\n".to_vec();
    let out = CliOutcome::success(
        held.clone(),
        String::new(),
        false,
        &["tok-a"],
        StdoutRule::RefuseToken,
    );
    let human = format!("error: {UNSAFE_WHAT}\n{UNSAFE_REMEDY}\n");
    if (out.exit(), out.stdout(), out.stderr()) != (CliExit::LocalFailure, &b""[..], human.as_str())
    {
        misses.push(format!(
            "refused human: {:?} {:?}",
            out.exit(),
            out.stderr()
        ));
    }
    let out = CliOutcome::success(
        held.clone(),
        String::new(),
        true,
        &["tok-a"],
        StdoutRule::RefuseToken,
    );
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
        String::new(),
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
        String::new(),
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
        String::new(),
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
        "Opens once, from this machine only.\n".to_string(),
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
