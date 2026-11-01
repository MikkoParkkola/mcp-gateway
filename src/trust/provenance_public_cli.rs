// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `provenance public-key` and `provenance verify` commands: their
//! output lines and the pinned refusal names.

use super::{
    ExitCode, NoDupValue, PROVENANCE_KEY_ID_ENV, PROVENANCE_SEED_ENV, TrustSet, TrustSetRefusal,
    VerifyRefusal, VerifyStatus, configured_signer, verify_public,
};

/// The `snake_case` refusal after `INVALID ` for a verify refusal.
fn verify_snake(refusal: VerifyRefusal) -> &'static str {
    match refusal {
        VerifyRefusal::NoPublicSignature => "no_public_signature",
        VerifyRefusal::BadEncoding => "bad_encoding",
        VerifyRefusal::DuplicateMember => "duplicate_member",
        VerifyRefusal::BadProfile => "bad_profile",
        VerifyRefusal::UnknownKid => "unknown_kid",
        VerifyRefusal::BadSignature => "bad_signature",
        VerifyRefusal::OuterReceiptMismatch => "outer_receipt_mismatch",
        VerifyRefusal::ResultMismatch => "result_mismatch",
        VerifyRefusal::ResultUnhashable => "result_unhashable",
    }
}

/// The `snake_case` refusal after `INVALID trust_` for a trust-set refusal.
fn trust_snake(refusal: TrustSetRefusal) -> &'static str {
    match refusal {
        TrustSetRefusal::Malformed => "malformed",
        TrustSetRefusal::DuplicateKid => "duplicate_kid",
        TrustSetRefusal::NotEd25519 => "not_ed25519",
        TrustSetRefusal::BadX => "bad_x",
        TrustSetRefusal::PrivateMember => "private_member",
        TrustSetRefusal::MissingKid => "missing_kid",
        TrustSetRefusal::MalformedKid => "malformed_kid",
    }
}

fn emit_line(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stdout().lock(), "{line}");
}

fn emit_fmt(args: std::fmt::Arguments<'_>) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stdout().lock(), "{args}");
}

/// Runs `provenance public-key` / `provenance verify`; prints its own stdout/stderr lines.
///
/// `config` is the global `--config` path `main` passes every 4.0 subcommand.
/// CLI refusal reasons, pinned `snake_case` after `INVALID `:
/// `unknown_kid`, `bad_signature`, `bad_encoding`, `duplicate_member`,
/// `bad_profile`, `outer_receipt_mismatch`, `result_mismatch`,
/// `result_unhashable`, `no_public_signature`.
pub fn run_provenance_command(
    cmd: &crate::cli::ProvenanceCommand,
    config: Option<&std::path::Path>,
) -> ExitCode {
    match cmd {
        crate::cli::ProvenanceCommand::PublicKey => run_public_key(config),
        crate::cli::ProvenanceCommand::Verify {
            trust,
            receipt,
            result,
            signature_only,
            accept_unbound,
        } => run_verify(
            trust,
            receipt,
            result.as_ref(),
            *signature_only,
            *accept_unbound,
        ),
    }
}

/// Export the gateway's public provenance JWK and thumbprint.
fn run_public_key(config: Option<&std::path::Path>) -> ExitCode {
    match configured_signer(config) {
        Ok(Some(signer)) => {
            let output = serde_json::json!({
                "jwk": signer.public_jwk(),
                "thumbprint": signer.jwk_thumbprint(),
            });
            if let Ok(line) = serde_json::to_string(&output) {
                emit_line(&line);
                ExitCode::from(0)
            } else {
                eprintln!("failed to render the public key");
                ExitCode::from(1)
            }
        }
        Ok(None) => {
            eprintln!(
                "{PROVENANCE_SEED_ENV} is not set: set it and {PROVENANCE_KEY_ID_ENV} to export the public key"
            );
            ExitCode::from(1)
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

/// Verify one receipt file against one trust file, with an optional result.
fn run_verify(
    trust_path: &std::path::Path,
    receipt_path: &std::path::Path,
    result_path: Option<&std::path::PathBuf>,
    signature_only: bool,
    accept_unbound: bool,
) -> ExitCode {
    let Ok(trust_text) = std::fs::read_to_string(trust_path) else {
        emit_line("INVALID unreadable_input");
        return ExitCode::from(1);
    };
    let trust = match TrustSet::from_json(&trust_text) {
        Ok(set) => set,
        Err(refusal) => {
            emit_fmt(format_args!("INVALID trust_{}", trust_snake(refusal)));
            return ExitCode::from(1);
        }
    };
    let Ok(receipt_text) = std::fs::read_to_string(receipt_path) else {
        emit_line("INVALID unreadable_input");
        return ExitCode::from(1);
    };
    let receipt_value: serde_json::Value = match serde_json::from_str::<NoDupValue>(&receipt_text) {
        Ok(wrapped) => wrapped.0,
        Err(error) if error.to_string().contains("duplicate member") => {
            emit_line("INVALID duplicate_member");
            return ExitCode::from(1);
        }
        Err(_) => {
            emit_line("INVALID unreadable_input");
            return ExitCode::from(1);
        }
    };
    let prov = match receipt_value.pointer("/_meta/provenance") {
        Some(inner) if inner.is_object() => inner.clone(),
        _ => receipt_value,
    };
    let result_value: Option<serde_json::Value> = match result_path {
        None => None,
        Some(path) => {
            let Ok(text) = std::fs::read_to_string(path) else {
                emit_line("INVALID unreadable_input");
                return ExitCode::from(1);
            };
            match serde_json::from_str::<NoDupValue>(&text) {
                Ok(wrapped) => Some(wrapped.0),
                Err(error) if error.to_string().contains("duplicate member") => {
                    emit_line("INVALID duplicate_member");
                    return ExitCode::from(1);
                }
                Err(_) => {
                    emit_line("INVALID unreadable_input");
                    return ExitCode::from(1);
                }
            }
        }
    };
    match verify_public(&prov, &trust, result_value.as_ref()) {
        Ok(verified) => match verified.status {
            VerifyStatus::Bound => {
                emit_fmt(format_args!("BOUND kid={}", verified.kid));
                ExitCode::from(0)
            }
            VerifyStatus::Unbound if accept_unbound => {
                emit_fmt(format_args!(
                    "UNBOUND kid={} (accepted: --accept-unbound)",
                    verified.kid
                ));
                ExitCode::from(0)
            }
            VerifyStatus::Unbound => {
                emit_fmt(format_args!("UNBOUND kid={}", verified.kid));
                ExitCode::from(1)
            }
            VerifyStatus::SignatureOnly if signature_only => {
                emit_fmt(format_args!(
                    "SIGNATURE-ONLY kid={} (accepted: --signature-only)",
                    verified.kid
                ));
                ExitCode::from(0)
            }
            VerifyStatus::SignatureOnly => {
                emit_fmt(format_args!("SIGNATURE-ONLY kid={}", verified.kid));
                ExitCode::from(1)
            }
        },
        Err(refusal) => {
            emit_fmt(format_args!("INVALID {}", verify_snake(refusal)));
            ExitCode::from(1)
        }
    }
}
