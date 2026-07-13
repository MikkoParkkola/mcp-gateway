// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `provenance-eval` — offline scorer for MIK-6908 rung 3.
//!
//! Reads a JSONL corpus of [`CorpusRecord`]s (one per line), joins each
//! record's claim to its receipt on `call_id`, verifies the receipt's
//! signature, scores the claim against the receipt's observed facts, and
//! prints a human-readable [`EvalReport`]. All judgement logic — the join
//! check, the signature verification, the scoring rules — lives in
//! [`mcp_gateway::trust::provenance_eval`]; this binary is a thin CLI shell
//! around [`score_corpus`].
//!
//! Offline / shadow only: no network, no wiring into any request path.
//!
//! # Usage
//!
//! ```text
//! provenance-eval <path-to-corpus.jsonl>
//! ```
//!
//! Signing key material is read from the same environment variables the
//! gateway's live attestation wiring uses
//! ([`mcp_gateway::attestation::ATTESTATION_SIGNING_KEY_ENV`],
//! [`mcp_gateway::attestation::ATTESTATION_KEY_ID_ENV`]), so a corpus
//! captured against a running gateway's signing key replays without
//! re-keying anything.
//!
//! A malformed corpus line is a hard failure: this binary reports the line
//! number and the parse error to stderr and exits non-zero rather than
//! silently dropping the line, because a scorer that silently drops input
//! could silently drop exactly the cases that would move the metric.

#![forbid(unsafe_code)]

use std::io::BufRead as _;
use std::process::ExitCode;

use mcp_gateway::attestation::wiring::DEFAULT_KEY_ID;
use mcp_gateway::attestation::{
    ATTESTATION_KEY_ID_ENV, ATTESTATION_SIGNING_KEY_ENV, AttestationValidator,
    BnautAttestationSigner,
};
use mcp_gateway::trust::provenance_eval::{CorpusRecord, EvalReport, score_corpus};

fn main() -> ExitCode {
    let Some(corpus_path) = std::env::args().nth(1) else {
        eprintln!("usage: provenance-eval <path-to-corpus.jsonl>");
        return ExitCode::FAILURE;
    };

    let records = match load_corpus(&corpus_path) {
        Ok(records) => records,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::FAILURE;
        }
    };

    let validator = match validator_from_env() {
        Ok(validator) => validator,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::FAILURE;
        }
    };
    let (report, mis_joined) = score_corpus(&records, &validator);
    print_report(&report, mis_joined);
    ExitCode::SUCCESS
}

/// Build the attestation validator from the same env vars the gateway's live
/// wiring reads.
///
/// An unset or empty signing key is refused outright: HMAC-SHA256 accepts an
/// empty key, so silently falling back to `b""` would let a corpus whose
/// receipts were signed with the empty key verify as "trusted" and get
/// scored as real evidence. Since this offline tool's entire output IS the
/// trust metric, that would make a forged empty-key corpus indistinguishable
/// from a genuine one. This binary hard-fails instead of continuing —
/// unlike the gateway's live boundary-call path, which only warns in
/// observe-mode; there is no equivalent availability constraint here that
/// would justify scoring against a key nobody configured.
fn validator_from_env() -> Result<AttestationValidator, String> {
    let key = std::env::var(ATTESTATION_SIGNING_KEY_ENV).unwrap_or_default();
    if key.is_empty() {
        return Err(format!(
            "refusing to score: {ATTESTATION_SIGNING_KEY_ENV} is unset or empty. \
             Scoring against an empty HMAC key would trust any receipt signed with \
             an empty key, silently defeating signature verification. Set \
             {ATTESTATION_SIGNING_KEY_ENV} to the signing key the corpus's receipts \
             were captured with and re-run."
        ));
    }
    let key_id =
        std::env::var(ATTESTATION_KEY_ID_ENV).unwrap_or_else(|_| DEFAULT_KEY_ID.to_string());
    Ok(AttestationValidator::new(BnautAttestationSigner::new(
        key.into_bytes(),
        key_id,
    )))
}

/// Parse a JSONL corpus file into [`CorpusRecord`]s.
///
/// A malformed line is a hard failure: returns `Err` naming the 1-indexed
/// line number and the parse error rather than skipping the line, so a
/// broken fixture is never mistaken for a clean one. Blank lines are
/// tolerated (not counted as records) so trailing newlines don't trip this.
fn load_corpus(path: &str) -> Result<Vec<CorpusRecord>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("failed to open {path}: {e}"))?;
    let mut records = Vec::new();
    for (idx, line) in std::io::BufReader::new(file).lines().enumerate() {
        let line_no = idx + 1;
        let line = line.map_err(|e| format!("{path}:{line_no}: read error: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let record = serde_json::from_str::<CorpusRecord>(&line)
            .map_err(|e| format!("{path}:{line_no}: malformed corpus record: {e}"))?;
        records.push(record);
    }
    Ok(records)
}

/// Print the human-readable report, including a sample-size note on the
/// unsupported rate so a reader never mistakes a thin sample for a solid one.
fn print_report(report: &EvalReport, mis_joined: usize) {
    let adjudicated = report.supported + report.unsupported;
    println!("provenance-eval report");
    println!("  total:        {}", report.total);
    println!("  supported:    {}", report.supported);
    println!("  unsupported:  {}", report.unsupported);
    println!("  abstained:    {}", report.abstained);
    println!("  rejected:     {}", report.rejected);
    println!("  mis-joined:   {mis_joined}");
    match report.unsupported_rate() {
        Some(rate) => println!(
            "  unsupported rate: {rate:.4} (adjudicated {adjudicated} of {} cases)",
            report.total
        ),
        None => println!(
            "  unsupported rate: n/a (0 adjudicated) (adjudicated {adjudicated} of {} cases)",
            report.total
        ),
    }
}
