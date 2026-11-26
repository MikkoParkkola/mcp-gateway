// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway audit verify --export <file> [--jwk <file>]`: check an
//! Activity export offline. The manifest's Ed25519 signature must verify under
//! the public key, and the manifest's SHA-256 must name every byte before it,
//! so a changed row, a changed manifest field, a removed or torn manifest, or
//! another key's export each fail.
//!
//! What this does not check: each row's own HMAC (`sig`) authenticates the
//! original log entry's hash and needs the gateway's secret, and a projected
//! row is not the original entry. The export signature says these rows are
//! what this gateway exported, nothing more.

use std::path::Path;
use std::process::ExitCode;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::provenance_public::{
    ACTIVITY_EXPORT_DOMAIN, TrustSet, VerifyRefusal, configured_signer, from_slice_no_dup,
};

/// Why an export did not verify, naming the rule and never the data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExportRefusal {
    /// The file is empty.
    Empty,
    /// The last line is cut short: no final newline.
    Torn,
    /// The last line is not a manifest.
    NoManifest,
    /// The manifest repeats a member.
    DuplicateMember,
    /// The manifest's digest does not name the bytes before it.
    DigestMismatch,
    /// The manifest's key id is not in the trust set.
    UnknownKid,
    /// The signature is missing, malformed, or does not verify.
    BadSignature,
}

impl ExportRefusal {
    fn snake(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Torn => "torn",
            Self::NoManifest => "no_manifest",
            Self::DuplicateMember => "duplicate_member",
            Self::DigestMismatch => "digest_mismatch",
            Self::UnknownKid => "unknown_kid",
            Self::BadSignature => "bad_signature",
        }
    }
}

/// What a verified export says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExportReport {
    pub(crate) rows: u64,
    pub(crate) truncated: String,
    pub(crate) integrity_failed: u64,
    pub(crate) kid: String,
}

pub(crate) fn verify_export(bytes: &[u8], trust: &TrustSet) -> Result<ExportReport, ExportRefusal> {
    let Some((&last, body)) = bytes.split_last() else {
        return Err(ExportRefusal::Empty);
    };
    if last != b'\n' {
        return Err(ExportRefusal::Torn);
    }
    let start = body.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    let (rows, manifest) = body.split_at(start);
    // A repeated member could verify under one value and be read as another.
    let mut manifest: serde_json::Map<String, Value> = match from_slice_no_dup(manifest) {
        Ok(Value::Object(m)) if m.get("kind").and_then(Value::as_str) == Some("manifest") => m,
        Err(e) if e.to_string().contains("duplicate member") => {
            return Err(ExportRefusal::DuplicateMember);
        }
        _ => return Err(ExportRefusal::NoManifest),
    };
    let digest = hex::encode(Sha256::digest(rows));
    if manifest.get("sha256").and_then(Value::as_str) != Some(digest.as_str()) {
        return Err(ExportRefusal::DigestMismatch);
    }
    let Some(Value::String(sig)) = manifest.remove("public_signature") else {
        return Err(ExportRefusal::BadSignature);
    };
    let kid = manifest
        .get("kid")
        .and_then(Value::as_str)
        .ok_or(ExportRefusal::UnknownKid)?
        .to_string();
    let signed = serde_json_canonicalizer::to_vec(&Value::Object(manifest.clone()))
        .map_err(|_| ExportRefusal::BadSignature)?;
    trust
        .verify_bytes(&kid, ACTIVITY_EXPORT_DOMAIN, &signed, &sig)
        .map_err(|refusal| match refusal {
            VerifyRefusal::UnknownKid => ExportRefusal::UnknownKid,
            _ => ExportRefusal::BadSignature,
        })?;
    let count = |k: &str| manifest.get(k).and_then(Value::as_u64).unwrap_or(0);
    Ok(ExportReport {
        rows: count("rows"),
        truncated: manifest
            .get("truncated")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        integrity_failed: count("integrity_failed"),
        kid,
    })
}

/// The trust set: the `--jwk` file, else the gateway's own configured key.
fn trust_set(jwk: Option<&Path>, config: Option<&Path>) -> Result<TrustSet, String> {
    let text = match jwk {
        Some(path) => String::from_utf8(read_bounded(path, MAX_JWK_BYTES)?)
            .map_err(|_| "the --jwk file is not UTF-8".to_string())?,
        None => match configured_signer(config)? {
            Some(signer) => signer.public_jwk().to_string(),
            None => return Err("no public key: pass --jwk (from `provenance public-key`)".into()),
        },
    };
    // `provenance public-key` prints `{"jwk": ..., "thumbprint": ...}`: its
    // output is taken as it is, as well as a bare JWK or a JWKS.
    let text = match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(mut printed)) if printed.contains_key("thumbprint") => {
            printed.remove("jwk").map_or(text, |jwk| jwk.to_string())
        }
        _ => text,
    };
    TrustSet::from_json(&text).map_err(|_| "the --jwk file is not a public Ed25519 JWK".into())
}

/// The largest export the gateway writes (64 MiB of rows plus its manifest),
/// with room to spare; a bigger file is not one of its exports.
const MAX_EXPORT_BYTES: u64 = 65 << 20;
/// A JWK or JWKS file is a few hundred bytes per key.
const MAX_JWK_BYTES: u64 = 1 << 20;

/// Read `path` whole, refusing a file over `max` before reading it.
fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let file = std::fs::File::open(path).map_err(|_| "unreadable_input".to_string())?;
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "unreadable_input".to_string())?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max {
        return Err("too_large".into());
    }
    Ok(bytes)
}

/// The verdict `audit verify --export` reached, before it is printed.
enum ExportVerdict {
    Valid(ExportReport),
    /// The text after `INVALID `: a `snake_case` refusal, or the read failure's sentence.
    Invalid(String),
}

/// What `audit verify --export` prints and exits with: `VALID ...` or `INVALID <reason>` as text, or one verdict
/// document under `--json` (MIK-9764.JSONF.1, design D6: a failed verdict is still a document, exit 1). A trust
/// set that does not load is not a verdict: its error goes to stderr, stdout stays empty.
pub(crate) fn export_verdict(
    file: &Path,
    jwk: Option<&Path>,
    config: Option<&Path>,
    render: crate::cli::output::Render,
) -> crate::cli::output::Printed {
    use crate::cli::output::{Printed, Render};
    use crate::commands::CliExit;
    let trust = match trust_set(jwk, config) {
        Ok(t) => t,
        Err(why) => {
            return Printed::error(
                CliExit::LocalFailure,
                &why,
                "Pass --jwk naming the key 'mcp-gateway provenance public-key' printed, or fix the gateway's signing key.",
            );
        }
    };
    let verdict = match read_bounded(file, MAX_EXPORT_BYTES) {
        Err(why) => ExportVerdict::Invalid(why),
        Ok(bytes) => match verify_export(&bytes, &trust) {
            Ok(report) => ExportVerdict::Valid(report),
            Err(refusal) => ExportVerdict::Invalid(refusal.snake().to_owned()),
        },
    };
    let exit = match verdict {
        ExportVerdict::Valid(_) => 0,
        ExportVerdict::Invalid(_) => 1,
    };
    let stdout = match (render, &verdict) {
        (Render::Text, ExportVerdict::Valid(r)) => format!(
            "VALID export: {} rows, truncated={}, integrity_failed={}, key {}\nEach row's own sig authenticates \
             its original log entry and needs the gateway's secret; this check covers the bundle as exported.\n",
            r.rows, r.truncated, r.integrity_failed, r.kid
        ),
        (Render::Text, ExportVerdict::Invalid(why)) => format!("INVALID {why}\n"),
        (Render::Json, verdict) => {
            /// The export verdict's document (design 3a): the report fields null unless valid.
            #[derive(serde::Serialize)]
            struct View<'a> {
                valid: bool,
                reason: Option<&'a str>,
                rows: Option<u64>,
                truncated: Option<&'a str>,
                integrity_failed: Option<u64>,
                kid: Option<&'a str>,
            }
            let view = match verdict {
                ExportVerdict::Valid(r) => View {
                    valid: true,
                    reason: None,
                    rows: Some(r.rows),
                    truncated: Some(&r.truncated),
                    integrity_failed: Some(r.integrity_failed),
                    kid: Some(&r.kid),
                },
                ExportVerdict::Invalid(why) => View {
                    valid: false,
                    reason: Some(why),
                    rows: None,
                    truncated: None,
                    integrity_failed: None,
                    kid: None,
                },
            };
            match crate::cli::output::document(&view) {
                Ok(doc) => doc,
                Err(why) => {
                    return Printed::error(
                        CliExit::LocalFailure,
                        &format!("could not print the verdict: {why}"),
                        "Rerun without --json for the text form, and report this as a bug.",
                    );
                }
            }
        }
    };
    // The verdict, valid or not: what it printed, and its code.
    Printed::verdict(exit, stdout, String::new())
}

/// Runs `audit verify --export`: [`export_verdict`], printed once.
pub(crate) fn run_verify_export(
    file: &Path,
    jwk: Option<&Path>,
    config: Option<&Path>,
    render: crate::cli::output::Render,
) -> ExitCode {
    export_verdict(file, jwk, config, render).emit(crate::cli::output::OnWriteFailure::Ignore)
}

#[cfg(tp4)]
#[cfg(test)]
#[path = "export_verify_tests.rs"]
mod tests;
