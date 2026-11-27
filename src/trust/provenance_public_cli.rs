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

/// Runs `provenance public-key` / `provenance verify`; prints its own stdout/stderr lines.
///
/// `config` is the global `--config` path `main` passes every 4.0 subcommand.
/// CLI refusal reasons, pinned `snake_case` after `INVALID `:
/// `unknown_kid`, `bad_signature`, `bad_encoding`, `duplicate_member`,
/// `bad_profile`, `outer_receipt_mismatch`, `result_mismatch`,
/// `result_unhashable`, `no_public_signature`.
pub(crate) fn run_provenance_command(
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
            json,
        } => run_verify(
            trust,
            receipt,
            result.as_ref(),
            *signature_only,
            *accept_unbound,
            crate::cli::output::Render::from_json_flag(*json),
        ),
    }
}

/// Export the gateway's public provenance JWK and thumbprint.
fn run_public_key(config: Option<&std::path::Path>) -> ExitCode {
    use crate::commands::{CliExit, fail, write_remedy};
    match configured_signer(config) {
        Ok(Some(signer)) => {
            let output = serde_json::json!({
                "jwk": signer.public_jwk(),
                "thumbprint": signer.jwk_thumbprint(),
            });
            if let Ok(line) = serde_json::to_string(&output) {
                emit_line(&line);
                ExitCode::SUCCESS
            } else {
                fail(
                    CliExit::LocalFailure,
                    "failed to render the public key",
                    "Report this as a bug, with the command line.",
                )
            }
        }
        Ok(None) => fail(
            CliExit::LocalFailure,
            &format!("{PROVENANCE_SEED_ENV} is not set"),
            &format!("Set it and {PROVENANCE_KEY_ID_ENV} to export the public key."),
        ),
        Err(error) => fail(
            CliExit::LocalFailure,
            &error,
            &write_remedy(config),
        ),
    }
}

/// Verify one receipt file against one trust file, with an optional result, and print the verdict once: its text
/// line, or one document under `--json` (MIK-9764.JSONF.1, design D6: every verdict, `INVALID` included, is a
/// document with the exit it has today).
fn run_verify(
    trust_path: &std::path::Path,
    receipt_path: &std::path::Path,
    result_path: Option<&std::path::PathBuf>,
    signature_only: bool,
    accept_unbound: bool,
    render: crate::cli::output::Render,
) -> ExitCode {
    verdict_printed(
        &verify_receipt(trust_path, receipt_path, result_path),
        signature_only,
        accept_unbound,
        render,
    )
    .emit(crate::cli::output::OnWriteFailure::Ignore)
}

/// The verdict of one receipt: the status and key id, or the `snake_case` reason printed after `INVALID `.
fn verify_receipt(
    trust_path: &std::path::Path,
    receipt_path: &std::path::Path,
    result_path: Option<&std::path::PathBuf>,
) -> Result<(VerifyStatus, String), String> {
    let unreadable = || "unreadable_input".to_owned();
    let trust_text = std::fs::read_to_string(trust_path).map_err(|_| unreadable())?;
    let trust = TrustSet::from_json(&trust_text)
        .map_err(|refusal| format!("trust_{}", trust_snake(refusal)))?;
    let receipt_text = std::fs::read_to_string(receipt_path).map_err(|_| unreadable())?;
    let parse = |text: &str| match serde_json::from_str::<NoDupValue>(text) {
        Ok(wrapped) => Ok(wrapped.0),
        Err(error) if error.to_string().contains("duplicate member") => {
            Err("duplicate_member".to_owned())
        }
        Err(_) => Err(unreadable()),
    };
    let receipt_value = parse(&receipt_text)?;
    let prov = match receipt_value.pointer("/_meta/provenance") {
        Some(inner) if inner.is_object() => inner.clone(),
        _ => receipt_value,
    };
    let result_value = match result_path {
        None => None,
        Some(path) => Some(parse(
            &std::fs::read_to_string(path).map_err(|_| unreadable())?,
        )?),
    };
    verify_public(&prov, &trust, result_value.as_ref())
        .map(|verified| (verified.status, verified.kid))
        .map_err(|refusal| verify_snake(refusal).to_owned())
}

/// The one printer of a provenance verdict, text or document; the exit is 0 for an accepted verdict, 1 otherwise.
fn verdict_printed(
    verdict: &Result<(VerifyStatus, String), String>,
    signature_only: bool,
    accept_unbound: bool,
    render: crate::cli::output::Render,
) -> crate::cli::output::Printed {
    use crate::cli::output::{Printed, Render};
    let (status, accepted, kid, reason) = match verdict {
        Ok((VerifyStatus::Bound, kid)) => ("bound", true, Some(kid.as_str()), None),
        Ok((VerifyStatus::Unbound, kid)) => ("unbound", accept_unbound, Some(kid.as_str()), None),
        Ok((VerifyStatus::SignatureOnly, kid)) => {
            ("signature_only", signature_only, Some(kid.as_str()), None)
        }
        Err(reason) => ("invalid", false, None, Some(reason.as_str())),
    };
    let stdout = match render {
        Render::Text => match verdict {
            Ok((VerifyStatus::Bound, kid)) => format!("BOUND kid={kid}\n"),
            Ok((VerifyStatus::Unbound, kid)) if accept_unbound => {
                format!("UNBOUND kid={kid} (accepted: --accept-unbound)\n")
            }
            Ok((VerifyStatus::Unbound, kid)) => format!("UNBOUND kid={kid}\n"),
            Ok((VerifyStatus::SignatureOnly, kid)) if signature_only => {
                format!("SIGNATURE-ONLY kid={kid} (accepted: --signature-only)\n")
            }
            Ok((VerifyStatus::SignatureOnly, kid)) => format!("SIGNATURE-ONLY kid={kid}\n"),
            Err(reason) => format!("INVALID {reason}\n"),
        },
        Render::Json => {
            /// The provenance verdict's document (design 3a).
            #[derive(serde::Serialize)]
            struct View<'a> {
                status: &'a str,
                accepted: bool,
                kid: Option<&'a str>,
                reason: Option<&'a str>,
            }
            match crate::cli::output::document(&View {
                status,
                accepted,
                kid,
                reason,
            }) {
                Ok(doc) => doc,
                Err(why) => {
                    return Printed::error(
                        crate::commands::CliExit::LocalFailure,
                        &format!("could not print the verdict: {why}"),
                        "Rerun without --json for the text form, and report this as a bug.",
                    );
                }
            }
        }
    };
    // The verdict, accepted or not: what it printed, and its code.
    Printed::verdict(u8::from(!accepted), stdout, String::new())
}
