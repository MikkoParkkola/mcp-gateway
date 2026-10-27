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

fn say(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stdout().lock(), "{line}");
}

/// Runs `audit verify --export`; prints `VALID ...` or `INVALID <reason>`.
pub fn run_verify_export(file: &Path, jwk: Option<&Path>, config: Option<&Path>) -> ExitCode {
    let trust = match trust_set(jwk, config) {
        Ok(t) => t,
        Err(why) => {
            eprintln!("{why}");
            return ExitCode::FAILURE;
        }
    };
    let bytes = match read_bounded(file, MAX_EXPORT_BYTES) {
        Ok(b) => b,
        Err(why) => {
            say(&format!("INVALID {why}"));
            return ExitCode::FAILURE;
        }
    };
    match verify_export(&bytes, &trust) {
        Ok(r) => {
            say(&format!(
                "VALID export: {} rows, truncated={}, integrity_failed={}, key {}",
                r.rows, r.truncated, r.integrity_failed, r.kid
            ));
            say(
                "Each row's own sig authenticates its original log entry and needs the gateway's secret; this check covers the bundle as exported.",
            );
            ExitCode::SUCCESS
        }
        Err(refusal) => {
            say(&format!("INVALID {}", refusal.snake()));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
#[path = "export_verify_tests.rs"]
mod tests;
