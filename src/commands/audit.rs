// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway audit`: verify the transparency log's chain, check an
//! Activity export offline, or show one session's entries.

use std::process::ExitCode;

use mcp_gateway::cli::AuditCommand;
use mcp_gateway::config::Config;

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

/// `audit verify`: every segment of the log, live or archive mode (D6).
fn run_audit_verify(
    log_path: &std::path::Path,
    archive: bool,
    anchor: Option<&std::path::Path>,
    config_path: Option<&std::path::Path>,
) -> ExitCode {
    use mcp_gateway::security::transparency_log::{VerifyMode, verify_audit_log};
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
            eprintln!(
                "Error: could not load gateway config for signed verification: {e}. Refusing to verify (a load failure must not silently downgrade to hash-only)."
            );
            return ExitCode::FAILURE;
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
                eprintln!(
                    "Error: log at {} has signed entries but no shared secret is configured — refusing hash-only verify (HMAC unauthenticated). Set security.transparency_log.shared_secret.",
                    log_path.display()
                );
                return ExitCode::FAILURE;
            }
            Ok(false) => {}
            Err(e) => {
                eprintln!("Error reading log: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    #[cfg(all(test, unix))]
    race_tests::between_passes();
    match verify_audit_log(log_path, &log_config, verify_mode, anchor) {
        // Neither the log nor any sealed segment exists (D6: sealed segments
        // alone are still a log to verify).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "Error: transparency log not found at {}",
                log_path.display()
            );
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("Error reading log: {e}");
            ExitCode::FAILURE
        }
        // The pass itself saw a signature it could not check: refuse, however
        // the check above came out. Records written between that check and
        // this pass are covered only here. A chain that failed is reported
        // as a failure below, with this note added.
        Ok(result) if !signed && result.signed_entry_seen && result.ok => {
            eprintln!(
                "Error: log at {} has signed entries but no shared secret is configured — refusing hash-only verify (HMAC unauthenticated). Set security.transparency_log.shared_secret.",
                log_path.display()
            );
            ExitCode::FAILURE
        }
        Ok(result) if result.ok => {
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
            for warning in &result.warnings {
                eprintln!("warning: {warning}");
            }
            ExitCode::SUCCESS
        }
        Ok(result) => {
            let at = result
                .error_at_counter
                .map_or_else(|| "?".to_string(), |n| n.to_string());
            let msg = result
                .error_message
                .unwrap_or_else(|| "unknown error".to_string());
            eprintln!("✗ Chain verification FAILED at counter {at}: {msg}");
            if !signed && result.signed_entry_seen {
                eprintln!(
                    "note: the log has signed entries but no shared secret is configured; their HMAC was not checked."
                );
            }
            ExitCode::FAILURE
        }
    }
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
        } => match export {
            Some(file) => mcp_gateway::trust::run_verify_export(&file, jwk.as_deref(), config_path),
            None => run_audit_verify(&resolve_path(path), archive, anchor.as_deref(), config_path),
        },

        AuditCommand::Show { session, path } => {
            let log_path = resolve_path(path);
            match show_session_entries(&log_path, &session) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    eprintln!(
                        "Error: transparency log not found at {}",
                        log_path.display()
                    );
                    ExitCode::FAILURE
                }
                Err(e) => {
                    eprintln!("Error reading log: {e}");
                    ExitCode::FAILURE
                }
                Ok(entries) if entries.is_empty() => {
                    println!("No entries found for session '{session}'.");
                    ExitCode::SUCCESS
                }
                Ok(entries) => {
                    for entry in &entries {
                        match serde_json::to_string_pretty(entry) {
                            Ok(pretty) => println!("{pretty}"),
                            Err(e) => eprintln!("Serialisation error: {e}"),
                        }
                    }
                    ExitCode::SUCCESS
                }
            }
        }
    }
}

#[cfg(all(test, unix))]
#[path = "audit_race_tests.rs"]
mod race_tests;
