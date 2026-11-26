// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway audit`: verify the transparency log's chain, check an
//! Activity export offline, or show one session's entries.

use crate::cli::stdout::println;

use std::process::ExitCode;

use super::{CliExit, check_config_command, fail, verdict};

use mcp_gateway::cli::AuditCommand;
use mcp_gateway::cli_support::shown;
use mcp_gateway::config::Config;

use crate::cli::output::Render;

/// Resolve the audit log path: use the provided `--path` flag, or fall back to
/// the default `~/.mcp-gateway/transparency/transparency.jsonl`.
fn resolve_audit_log_path(path: Option<std::path::PathBuf>) -> std::path::PathBuf {
    use std::path::PathBuf;
    path.unwrap_or_else(|| {
        crate::home_dir::home_dir().map_or_else(
            || PathBuf::from("transparency.jsonl"),
            |h| {
                h.join(".mcp-gateway")
                    .join("transparency")
                    .join("transparency.jsonl")
            },
        )
    })
}

/// `audit verify`: every segment of the log, live or archive mode (D6). Under `--json` a verdict, pass or fail, is
/// one document on stdout with the exit it has today; stderr is the same in both forms.
fn run_audit_verify(
    log_path: &std::path::Path,
    archive: bool,
    anchor: Option<&std::path::Path>,
    config_path: Option<&std::path::Path>,
    render: Render,
) -> ExitCode {
    use mcp_gateway::security::transparency_log::{FailedCheck, VerifyMode, verify_audit_log};
    let resolve_log_config = Config::audit_verify_config;
    let verify_mode = if archive {
        VerifyMode::Archive
    } else {
        VerifyMode::Live
    };
    let log_config = match resolve_log_config(config_path) {
        Ok(c) => c,
        Err(e) => {
            // Fail closed: a config we cannot load must NOT downgrade to
            // hash-only and report success.
            return fail(
                CliExit::LocalFailure,
                &format!(
                    "could not load gateway config for signed verification: {e}. Refusing to verify (a load failure must not silently downgrade to hash-only)."
                ),
                &format!(
                    "Run '{}' to see why.",
                    config_path
                        .map_or_else(|| "mcp-gateway doctor".to_owned(), check_config_command)
                ),
            );
        }
    };
    let signed = !log_config.shared_secret.is_empty();
    // Fail closed on the root danger: a log that WAS signed, verified
    // without a secret, would silently degrade to hash-only and pass a
    // stale-sig forgery with exit 0 — regardless of why the secret is
    // absent (no config discovered, wrong config, unset env). This check
    // refuses early; the verifying pass below is the guard that holds.
    if !signed {
        match mcp_gateway::security::transparency_log::log_contains_signed_entry(log_path) {
            Ok(true) => {
                return unsigned_refusal(log_path);
            }
            Ok(false) => {}
            Err(e) => {
                return log_unreadable(log_path, &e);
            }
        }
    }
    #[cfg(all(test, unix))]
    race_tests::between_passes();
    match verify_audit_log(log_path, &log_config, verify_mode, anchor) {
        // Neither the log nor any sealed segment exists (D6: sealed segments
        // alone are still a log to verify).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => log_not_found(log_path),
        Err(e) => log_unreadable(log_path, &e),
        // The pass itself saw a signature it could not check: refuse, however
        // the check above came out. Records written between that check and
        // this pass are covered only here. A chain that failed is reported
        // as a failure below, with this note added.
        Ok(result) if !signed && result.signed_entry_seen && result.ok => {
            unsigned_refusal(log_path)
        }
        Ok(result) if result.ok => {
            if render == Render::Json {
                print_findings(&result);
                return print_verdict(&result, signed, verify_mode, ExitCode::SUCCESS);
            }
            print_pass(&result, signed, verify_mode);
            ExitCode::SUCCESS
        }
        Ok(result) => {
            let at = result
                .error_at_counter
                .map_or_else(|| "?".to_string(), |n| n.to_string());
            let msg = result
                .error_message
                .clone()
                .unwrap_or_else(|| "unknown error".to_string());
            match result.failed_check() {
                // The message names the rule, the counter and the token.
                FailedCheck::Pairing => {
                    eprintln!("✗ Pairing verification FAILED: {}", shown(&msg));
                }
                FailedCheck::Chain => {
                    eprintln!(
                        "✗ Chain verification FAILED at counter {at}: {}",
                        shown(&msg)
                    );
                }
            }
            // A failing log can still name what it replaced: never drop that.
            print_findings(&result);
            if !signed && result.signed_entry_seen {
                eprintln!(
                    "note: the log has signed entries but no shared secret is configured; their HMAC was not checked."
                );
            }
            if render == Render::Json {
                return print_verdict(&result, signed, verify_mode, verdict(1));
            }
            verdict(1)
        }
    }
}

/// The passing verdict's text: the check that ran, the scope, the counts, then every finding on stderr.
fn print_pass(
    result: &mcp_gateway::security::transparency_log::VerifyResult,
    signed: bool,
    verify_mode: mcp_gateway::security::transparency_log::VerifyMode,
) {
    use mcp_gateway::security::transparency_log::VerifyMode;
    let mode = if signed {
        "hash chain + per-entry HMAC"
    } else {
        "hash chain (no secret configured; HMAC not checked)"
    };
    let scope = match verify_mode {
        VerifyMode::Live => "live log",
        VerifyMode::Archive => "archive copy; tail completeness not checked",
    };
    println!(
        "✓ Chain verified ({mode}; {scope}) — {} entries checked across {} \
         segments, {} expired by retention, no tampering detected.",
        result.entries_checked, result.segments_checked, result.segments_expired
    );
    print_findings(result);
}

/// `audit verify --json`'s document (MIK-9764.JSONF.1, design 3a): every field always present; text read from the
/// log goes through [`shown`], as on stderr.
#[derive(serde::Serialize)]
struct VerdictView {
    ok: bool,
    hmac_checked: bool,
    signed_entry_seen: bool,
    scope: &'static str,
    entries_checked: usize,
    segments_checked: usize,
    segments_expired: usize,
    failed_check: Option<&'static str>,
    failed_at_counter: Option<u64>,
    error: Option<String>,
    warnings: Vec<String>,
    notes: Vec<String>,
}

/// Print the verdict document of `result` on stdout (its stderr lines are already written) and return `exit`; a
/// document that cannot be built is an error on stderr, exit 1.
fn print_verdict(
    result: &mcp_gateway::security::transparency_log::VerifyResult,
    signed: bool,
    mode: mcp_gateway::security::transparency_log::VerifyMode,
    exit: ExitCode,
) -> ExitCode {
    use mcp_gateway::security::transparency_log::{FailedCheck, VerifyMode};
    let view = VerdictView {
        ok: result.ok,
        hmac_checked: signed,
        signed_entry_seen: result.signed_entry_seen,
        scope: match mode {
            VerifyMode::Live => "live",
            VerifyMode::Archive => "archive",
        },
        entries_checked: result.entries_checked,
        segments_checked: result.segments_checked,
        segments_expired: result.segments_expired,
        failed_check: (!result.ok).then(|| match result.failed_check() {
            FailedCheck::Chain => "chain",
            FailedCheck::Pairing => "pairing",
        }),
        failed_at_counter: if result.ok {
            None
        } else {
            result.error_at_counter
        },
        error: (!result.ok)
            .then(|| shown(result.error_message.as_deref().unwrap_or("unknown error")).to_string()),
        warnings: result
            .warnings
            .iter()
            .map(|w| shown(w).to_string())
            .collect(),
        notes: result
            .notes()
            .iter()
            .map(|n| shown(n).to_string())
            .collect(),
    };
    match crate::cli::output::document(&view) {
        Ok(doc) => {
            crate::cli::stdout::print!("{doc}");
            exit
        }
        Err(why) => fail(
            CliExit::LocalFailure,
            &format!("could not print the verdict: {why}"),
            "Rerun without --json for the text form, and report this as a bug.",
        ),
    }
}

/// Every verify warning and note, on stderr: the one place they are
/// rendered, on the passing and the failing path alike. They carry text read
/// from the log, so each goes through [`shown`], which escapes controls, bidi
/// and other format characters.
fn print_findings(result: &mcp_gateway::security::transparency_log::VerifyResult) {
    for warning in &result.warnings {
        eprintln!("warning: {}", shown(warning));
    }
    for note in result.notes() {
        eprintln!("info: {}", shown(note));
    }
}

/// No log at `log_path`: the remedy names the path, since `--path` or the default chose it.
fn log_not_found(log_path: &std::path::Path) -> ExitCode {
    fail(
        CliExit::LocalFailure,
        &format!("transparency log not found at {}", log_path.display()),
        &format!(
            "Check that {} exists, or pass --path naming the log.",
            log_path.display()
        ),
    )
}

/// The log at `log_path` exists but cannot be read.
fn log_unreadable(log_path: &std::path::Path, error: &impl std::fmt::Display) -> ExitCode {
    fail(
        CliExit::LocalFailure,
        &format!("could not read the log at {}: {error}", log_path.display()),
        &format!("Check that you can read {}.", log_path.display()),
    )
}

/// A log with signed entries and no shared secret configured: refused, since a hash-only pass would accept a
/// forged signature.
fn unsigned_refusal(log_path: &std::path::Path) -> ExitCode {
    fail(
        CliExit::LocalFailure,
        &format!(
            "log at {} has signed entries but no shared secret is configured — refusing hash-only verify (HMAC unauthenticated).",
            log_path.display()
        ),
        "Set security.transparency_log.shared_secret.",
    )
}

/// Dispatch an `audit` subcommand (transparency log chain verification / session query).
pub fn run_audit_command(cmd: AuditCommand, config_path: Option<&std::path::Path>) -> ExitCode {
    use mcp_gateway::security::transparency_log::show_session_entries;

    let resolve_path = resolve_audit_log_path;

    match cmd {
        AuditCommand::Verify {
            path,
            archive,
            anchor,
            export,
            jwk,
            json,
        } => {
            let render = crate::cli::output::Render::from_json_flag(json);
            match export {
                Some(file) => mcp_gateway::trust::run_verify_export(
                    &file,
                    jwk.as_deref(),
                    config_path,
                    render,
                ),
                None => run_audit_verify(
                    &resolve_path(path),
                    archive,
                    anchor.as_deref(),
                    config_path,
                    render,
                ),
            }
        }

        // Dispatched before this function (it needs the async runtime and
        // the gateway's address), so it never arrives here.
        AuditCommand::LookupEmail(_) => fail(
            CliExit::LocalFailure,
            "audit lookup-email must be run through the command entry",
            "Report this as a bug: the command entry dispatches it before this point.",
        ),

        AuditCommand::Show { session, path } => {
            let log_path = resolve_path(path);
            match show_session_entries(&log_path, &session) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => log_not_found(&log_path),
                Err(e) => log_unreadable(&log_path, &e),
                // One JSON array, `[]` when nothing matches (MIK-9764.JSONF.3, design D8): a script parses one
                // document. The entries are the log's own records, passed through.
                Ok(entries) => match serde_json::to_string_pretty(&entries) {
                    Ok(array) => {
                        println!("{array}");
                        ExitCode::SUCCESS
                    }
                    Err(e) => fail(
                        CliExit::LocalFailure,
                        &format!("could not print the entries: {e}"),
                        "Report this as a bug, with the command line.",
                    ),
                },
            }
        }
    }
}

#[cfg(all(test, unix))]
#[path = "audit_race_tests.rs"]
mod race_tests;
