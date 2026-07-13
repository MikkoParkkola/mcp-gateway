// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shadow claim-capture at the agent/tool boundary (MIK-6908, RUNG3.1).
//!
//! [`super::provenance_eval`] (rung 2) scores an agent-visible *claim* against
//! the gateway's signed [`super::result_provenance::RuntimeProvenanceReceipt`]
//! for the same call, but until now the only claims it could score were
//! hand-authored fixture literals — there was no real corpus, because nothing
//! captured "this call asserted X" at the moment the gateway actually saw the
//! result.
//!
//! This module is that capture point. [`ClaimCaptureSink`] writes one
//! [`CorpusRecord`] per observed call to an append-only NDJSON file — the
//! exact shape [`super::provenance_eval::score_corpus`] already consumes, so
//! feeding a captured file through the existing scorer (`provenance-eval
//! <captured-file.jsonl>`, RUNG3.4) requires no format translation.
//!
//! ## Why only `Claim::Succeeded` is captured
//!
//! The claim has to be *derived*, not asserted by the client — the MCP
//! protocol carries no "here is what I'm claiming about this result" channel,
//! so the gateway is the only party positioned to record it, and it can only
//! record what it can honestly observe at the stamping chokepoint
//! ([`crate::gateway::meta_mcp::support::augment_with_provenance`]).
//!
//! `backend_ok` (`!isError`) is observed directly there and needs no
//! interpretation, so [`Claim::Succeeded`] is always sound to derive.
//! [`Claim::AuthoritativeEmpty`] and [`Claim::FoundRows`] would require a
//! `row_count` — but the chokepoint is generic across 30+ heterogeneous
//! backends with no per-tool result schema. Guessing a row count from
//! whatever shape a given backend's JSON happens to have (a top-level array
//! length, a `"results"`/`"items"`/`"rows"` field, ...) is exactly the kind of
//! inferred-not-observed judgment [`super::result_provenance`]'s module
//! contract forbids: "facts, not judgments... an absent row count means 'not
//! observed', never zero". A wrong guess here would poison the eval corpus
//! with fabricated ground truth — the same failure mode the RUNG2 design
//! note (MIK-5854) already burned once. See `derive_claim` for the single
//! narrow point where this decision is made.
//!
//! ## Deployment
//!
//! Opt-in, off by default (`security.claim_capture.enabled`, default
//! `false`). Only takes effect when provenance stamping
//! (`security.provenance_stamping`) is also enabled — capture has nothing to
//! record without a signed receipt. Write failures are swallowed (this is
//! best-effort observability, not a hot-path dependency), mirroring
//! [`crate::security::firewall::audit::AuditLogger`]'s `Mutex<Box<dyn Write +
//! Send>>` idiom rather than inventing a new sink abstraction.

use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;

use serde_json::Value;

use super::SignedResultProvenance;
use super::provenance_eval::{Claim, CorpusRecord};

/// Append-only NDJSON sink for real `(call_id, claim, receipt)` triples
/// observed at the gateway's tool-result stamping chokepoint.
pub struct ClaimCaptureSink {
    writer: Mutex<Box<dyn Write + Send>>,
}

impl ClaimCaptureSink {
    /// Open a capture file for append-only writing.
    ///
    /// The parent directory is created if it does not exist.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the file cannot be opened or the parent
    /// directory cannot be created.
    pub fn open(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self::from_writer(BufWriter::new(file)))
    }

    /// Build a sink over an arbitrary writer (tests, or an alternate sink
    /// backend in future).
    #[must_use]
    pub fn from_writer(writer: impl Write + Send + 'static) -> Self {
        Self {
            writer: Mutex::new(Box::new(writer)),
        }
    }

    /// Record one shadow-capture line.
    ///
    /// Best-effort: a serialization or write failure is swallowed rather than
    /// propagated, because capture must never be able to fail a live tool
    /// call. Mirrors `AuditLogger::write_entry`.
    pub fn capture(&self, call_id: String, claim: Claim, receipt: SignedResultProvenance) {
        let record = CorpusRecord {
            call_id,
            claim,
            receipt,
        };
        if let Ok(json) = serde_json::to_string(&record)
            && let Ok(mut w) = self.writer.lock()
        {
            let _ = writeln!(w, "{json}");
            let _ = w.flush();
        }
    }
}

/// Derive the claim a shadow-capture record should carry for one observed
/// tool call, from exactly the facts already available at the provenance
/// stamping chokepoint.
///
/// Deliberately ignores the tool result body (`_result` is unused): see the
/// module doc for why a generic, backend-agnostic chokepoint cannot soundly
/// infer a row/item count, and therefore always derives [`Claim::Succeeded`]
/// — the one claim `backend_ok` alone supports without guessing at
/// domain-specific result shape. `Claim::Succeeded` is deliberately captured
/// even when `backend_ok` is `false`: scoring it `Unsupported` against a
/// failed receipt is the exact silent-failure signal RUNG2 exists to catch,
/// so suppressing capture on failure would hide the highest-value case.
#[must_use]
pub fn derive_claim(_result: &Value, _backend_ok: bool) -> Claim {
    Claim::Succeeded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::signer::BnautAttestationSigner;
    use crate::trust::provenance_eval::score_corpus;
    use crate::trust::{CacheOutcome, RuntimeProvenanceReceipt};
    use serde_json::json;
    use std::io::BufRead as _;

    const KEY: &[u8] = b"claim-capture-test-key";

    fn signer() -> BnautAttestationSigner {
        BnautAttestationSigner::new(KEY.to_vec(), "unit")
    }

    /// The receipt-domain subkey derived from the same raw key material as
    /// [`signer`]. Provenance receipts are signed with the HKDF receipt-domain
    /// subkey (`RESULT_PROVENANCE_DOMAIN_INFO`), not the raw key — mirroring
    /// production `resolve_provenance_signer`, which the validator's internal
    /// `receipt_signer` re-derives from the same base key when verifying
    /// (MIK-6909 domain separation). Signing receipts with the raw key would
    /// make them fail verification and score as `Rejected`.
    fn receipt_signer() -> BnautAttestationSigner {
        signer().derive_domain(crate::attestation::RESULT_PROVENANCE_DOMAIN_INFO)
    }

    fn signed_receipt(call_id: &str, backend_ok: bool) -> SignedResultProvenance {
        RuntimeProvenanceReceipt::observed(
            "demo",
            "search",
            "2026-07-13T10:15:30Z",
            CacheOutcome::Miss,
            backend_ok,
        )
        .with_call_id(call_id)
        .sign(&receipt_signer())
    }

    fn read_lines(path: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect()
    }

    /// `derive_claim` always returns `Succeeded` regardless of the result
    /// body shape — proving structurally (not just by doc comment) that this
    /// chokepoint never parses tool-result content to guess a row count.
    #[test]
    fn derive_claim_ignores_result_body_shape() {
        let array_like = json!({"content": [{"type": "text", "text": "[1,2,3]"}]});
        let object_like = json!({"content": [{"type": "text", "text": "{}"}]});
        assert_eq!(derive_claim(&array_like, true), Claim::Succeeded);
        assert_eq!(derive_claim(&object_like, true), Claim::Succeeded);
    }

    /// `derive_claim` still returns `Succeeded` on a failed backend call — the
    /// claim under scrutiny is "the call succeeded", and capturing it here is
    /// exactly what lets `score_corpus` later flag it `Unsupported`.
    #[test]
    fn derive_claim_on_failed_backend_is_still_succeeded_for_scoring() {
        let claim = derive_claim(&json!({"isError": true}), false);
        assert_eq!(claim, Claim::Succeeded);
    }

    /// A captured record is valid NDJSON and round-trips into the exact
    /// `CorpusRecord` shape `score_corpus` consumes (RUNG3.1 -> RUNG3.4 format
    /// compatibility, proven structurally rather than asserted in a comment).
    #[test]
    fn capture_writes_one_valid_corpus_record_line() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let sink = ClaimCaptureSink::open(tmp.path()).unwrap();
        let receipt = signed_receipt("gw-call-1", true);
        sink.capture("gw-call-1".to_string(), Claim::Succeeded, receipt.clone());

        let lines = read_lines(tmp.path());
        assert_eq!(lines.len(), 1);
        let record: CorpusRecord = serde_json::from_str(&lines[0]).expect("valid CorpusRecord");
        assert_eq!(record.call_id, "gw-call-1");
        assert_eq!(record.claim, Claim::Succeeded);
        assert_eq!(record.receipt, receipt);
    }

    /// Multiple captures append as separate lines (append-only contract).
    #[test]
    fn capture_appends_multiple_records_as_separate_lines() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let sink = ClaimCaptureSink::open(tmp.path()).unwrap();
        for i in 0..3 {
            let call_id = format!("gw-call-{i}");
            sink.capture(
                call_id.clone(),
                Claim::Succeeded,
                signed_receipt(&call_id, true),
            );
        }
        let lines = read_lines(tmp.path());
        assert_eq!(lines.len(), 3);
    }

    /// End-to-end RUNG3.1 -> RUNG3.4: records captured through the real sink,
    /// with real HMAC-signed receipts, feed directly into the real
    /// `score_corpus` scorer (RUNG3.2) and produce a correct, non-synthetic
    /// `EvalReport` — no fixture involved anywhere in this test.
    #[test]
    fn captured_records_score_correctly_through_score_corpus() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let sink = ClaimCaptureSink::open(tmp.path()).unwrap();

        // A genuinely successful call.
        sink.capture(
            "gw-call-ok".to_string(),
            derive_claim(&json!({"isError": false}), true),
            signed_receipt("gw-call-ok", true),
        );
        // A genuinely failed call — the claim is still `Succeeded` (that's
        // what "the call succeeded" asserts), and the receipt says otherwise.
        sink.capture(
            "gw-call-fail".to_string(),
            derive_claim(&json!({"isError": true}), false),
            signed_receipt("gw-call-fail", false),
        );

        let file = std::fs::File::open(tmp.path()).unwrap();
        let records: Vec<CorpusRecord> = std::io::BufReader::new(file)
            .lines()
            .map(|l| serde_json::from_str(&l.unwrap()).unwrap())
            .collect();
        assert_eq!(records.len(), 2);

        let validator = crate::attestation::validator::AttestationValidator::new(signer());
        let (report, mis_joined) = score_corpus(&records, &validator);
        assert_eq!(mis_joined, 0);
        assert_eq!(report.total, 2);
        assert_eq!(report.supported, 1, "the genuinely successful call");
        assert_eq!(
            report.unsupported, 1,
            "the failed call whose claim was still 'succeeded'"
        );
        assert_eq!(report.rejected, 0, "both receipts were validly signed");
    }
}
