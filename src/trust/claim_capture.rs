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
//! ## Ground truth vs claim-under-test (MIK-6914)
//!
//! RUNG3.1 could only capture [`Claim::Succeeded`], because the generic
//! stamping chokepoint has no per-tool result schema and guessing a row count
//! from whatever shape a backend's JSON happens to have would fabricate ground
//! truth — the MIK-5854 failure mode. MIK-6914 keeps that stop-line and splits
//! the two legs instead of collapsing them:
//!
//! - **Ground truth** is an *observed* authoritative count, produced only by a
//!   per-backend Option A extractor ([`super::extract_row_count`]) for a
//!   backend whose result shape genuinely carries one, and recorded in the
//!   signed receipt's
//!   [`row_count`](super::result_provenance::RuntimeProvenanceReceipt::row_count).
//!   Absent such an extractor the count stays `None` — "not observed", never
//!   zero.
//! - **Claim-under-test** is what the client said it rendered — an untrusted
//!   [`ClientClaim`] (Option B), captured verbatim by [`derive_claim`] and
//!   never used as the ground-truth leg. Absent a client claim, [`derive_claim`]
//!   still falls back to [`Claim::Succeeded`], the honest floor.
//!
//! Because the two legs are sourced independently, a client over-claim
//! (`FoundRows` over an authoritatively empty source) scores `Unsupported`, and
//! a claim the gateway could not check (`AuthoritativeEmpty` over a backend that
//! exposes no count) scores `Abstain` — the distinction this whole line of work
//! exists to make.
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

/// A claim about a tool result supplied by the client (the agent), joined to
/// the gateway's ground-truth receipt by `call_id`.
///
/// This is the *claim-under-test* — MIK-6914 Option B. It is **untrusted
/// input**: the client asserts what it intends to render about a result ("no
/// results", "found N rows"), and the offline eval scores that assertion
/// against the gateway-observed receipt. It is *never* the ground-truth leg.
/// The newtype exists precisely so a client-supplied claim cannot be mistaken
/// for an observed gateway fact at a call site — the ground truth is the
/// receipt's [`RuntimeProvenanceReceipt::row_count`](super::result_provenance::RuntimeProvenanceReceipt::row_count),
/// populated only by the gateway's Option A extractor
/// ([`super::extract_row_count`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientClaim {
    call_id: String,
    claim: Claim,
}

impl ClientClaim {
    /// Wrap a client-supplied claim as the untrusted claim-under-test for
    /// `call_id`. The name makes the trust boundary unmissable at the call site.
    #[must_use]
    pub fn untrusted(call_id: impl Into<String>, claim: Claim) -> Self {
        Self {
            call_id: call_id.into(),
            claim,
        }
    }

    /// The call this claim is about — the join key to the ground-truth receipt.
    #[must_use]
    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    /// The untrusted claim itself.
    #[must_use]
    pub fn claim(&self) -> &Claim {
        &self.claim
    }
}

/// Derive the *claim-under-test* to capture for one observed tool call.
///
/// MIK-6914 splits the ground truth from the claim under test, and this
/// function supplies only the latter. The ground truth — an authoritative row
/// count — is observed independently by the gateway's Option A extractor and
/// lives in the signed receipt ([`super::extract_row_count`] →
/// [`RuntimeProvenanceReceipt::row_count`](super::result_provenance::RuntimeProvenanceReceipt::row_count)).
///
/// When the client supplied a typed [`ClientClaim`] for this call (Option B),
/// that untrusted claim is captured verbatim as the claim-under-test. Absent a
/// client claim, the derivation falls back to [`Claim::Succeeded`] — the honest
/// floor that `backend_ok` alone supports without inspecting result shape, and
/// the same value the RUNG3.1 sink captured before richer claims existed.
///
/// The claim is never derived from the ground-truth count, so the two legs stay
/// independent — the property MIK-6914.AC.2 requires and the reason a client
/// over-claim can be scored `Unsupported` at all.
#[must_use]
pub fn derive_claim(client_claim: Option<&ClientClaim>) -> Claim {
    client_claim.map_or(Claim::Succeeded, |c| c.claim().clone())
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

    /// With no client claim, `derive_claim` falls back to the honest floor
    /// [`Claim::Succeeded`] — it never inspects a result body to guess a count.
    #[test]
    fn derive_claim_without_client_claim_is_succeeded_floor() {
        assert_eq!(derive_claim(None), Claim::Succeeded);
    }

    /// A client-supplied claim (Option B) is captured verbatim as the
    /// claim-under-test — this is the untrusted leg, not the ground truth.
    #[test]
    fn derive_claim_uses_client_claim_when_present() {
        let cc = ClientClaim::untrusted("gw-call-1", Claim::FoundRows { count: 5 });
        assert_eq!(derive_claim(Some(&cc)), Claim::FoundRows { count: 5 });
        assert_eq!(cc.call_id(), "gw-call-1");
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
            derive_claim(None),
            signed_receipt("gw-call-ok", true),
        );
        // A genuinely failed call — the claim is still `Succeeded` (that's
        // what "the call succeeded" asserts), and the receipt says otherwise.
        sink.capture(
            "gw-call-fail".to_string(),
            derive_claim(None),
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

    // === MIK-6914 AC.2: ground-truth (Option A) vs claim-under-test (Option B) ===

    const GH_TOOL: &str = "github_search_repos";

    /// A GitHub search result envelope carrying the backend's server-computed
    /// `total_count` and `incomplete_results` flag.
    fn github_result(total_count: u64, incomplete: bool) -> serde_json::Value {
        json!({
            "isError": false,
            "structuredContent": {
                "total_count": total_count,
                "incomplete_results": incomplete,
                "items": []
            }
        })
    }

    /// Build the *ground-truth* receipt exactly as the gateway does: run the
    /// Option A extractor ([`crate::trust::extract_row_count`]) over the real
    /// backend result and stamp the observed count onto the receipt. The
    /// claim-under-test never participates — proving the two legs are sourced
    /// independently.
    fn ground_truth_receipt(
        call_id: &str,
        backend_ok: bool,
        result: &serde_json::Value,
    ) -> SignedResultProvenance {
        let mut receipt = RuntimeProvenanceReceipt::observed(
            "caps",
            GH_TOOL,
            "2026-07-13T10:15:30Z",
            CacheOutcome::Miss,
            backend_ok,
        )
        .with_call_id(call_id);
        if let Some(n) = crate::trust::extract_row_count("caps", GH_TOOL, result, backend_ok) {
            receipt = receipt.with_row_count(n);
        }
        receipt.sign(&receipt_signer())
    }

    /// Capture one `(claim, receipt)` pair through the real sink and score it
    /// through the real `score_corpus` — the full RUNG3 path, no fixtures.
    fn capture_and_score(
        call_id: &str,
        claim: Claim,
        receipt: SignedResultProvenance,
    ) -> (crate::trust::provenance_eval::EvalReport, usize) {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let sink = ClaimCaptureSink::open(tmp.path()).unwrap();
        sink.capture(call_id.to_string(), claim, receipt);
        let records: Vec<CorpusRecord> = read_lines(tmp.path())
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let validator = crate::attestation::validator::AttestationValidator::new(signer());
        score_corpus(&records, &validator)
    }

    /// MIK-6914.AC.2 (the rejected case) — a genuine unsupported claim: the
    /// client claims it found rows, but the gateway-observed ground truth is an
    /// authoritative empty (`total_count == 0`). The claim is scored
    /// `Unsupported` — the claim-rejection outcome the metric exists to count.
    #[test]
    fn client_overclaim_over_authoritative_empty_scores_unsupported() {
        let result = github_result(0, false);
        let receipt = ground_truth_receipt("gw-oc", true, &result);
        // Ground truth read from the RESULT, not the claim: authoritative zero.
        assert_eq!(receipt.receipt.row_count, Some(0));

        let claim = derive_claim(Some(&ClientClaim::untrusted(
            "gw-oc",
            Claim::FoundRows { count: 5 },
        )));

        let (report, mis_joined) = capture_and_score("gw-oc", claim, receipt);
        assert_eq!(mis_joined, 0);
        assert_eq!(
            report.unsupported, 1,
            "found-rows over-claim rejected against authoritative-empty ground truth"
        );
        assert_eq!(report.supported + report.abstained + report.rejected, 0);
    }

    /// MIK-6914.AC.2 (the abstain case) — a genuine could-not-check: the client
    /// claims the source was authoritatively empty, but GitHub reported its
    /// search did not complete (`incomplete_results == true`), so the gateway
    /// observed no authoritative count. The claim is scored `Abstain`, kept
    /// distinct from an authoritative negative.
    #[test]
    fn client_empty_claim_over_uncheckable_search_scores_abstain() {
        let result = github_result(3, true);
        let receipt = ground_truth_receipt("gw-ab", true, &result);
        // Incomplete search → could-not-check → no observed count.
        assert_eq!(receipt.receipt.row_count, None);

        let claim = derive_claim(Some(&ClientClaim::untrusted(
            "gw-ab",
            Claim::AuthoritativeEmpty,
        )));

        let (report, mis_joined) = capture_and_score("gw-ab", claim, receipt);
        assert_eq!(mis_joined, 0);
        assert_eq!(report.abstained, 1, "no authoritative count → abstain");
        assert_eq!(report.supported + report.unsupported + report.rejected, 0);
    }

    /// MIK-6914.AC.2 (independence) — the gateway-observed ground-truth count is
    /// derived from the result and is invariant to whatever the client claims.
    /// The same authoritatively-empty result yields `row_count == Some(0)` under
    /// three contradictory client claims.
    #[test]
    fn ground_truth_is_independent_of_the_client_claim() {
        let result = github_result(0, false);
        for claim in [
            Claim::Succeeded,
            Claim::AuthoritativeEmpty,
            Claim::FoundRows { count: 99 },
        ] {
            let receipt = ground_truth_receipt("gw-ind", true, &result);
            // The claim-under-test is derived separately and cannot move the
            // observed ground truth.
            let _under_test = derive_claim(Some(&ClientClaim::untrusted("gw-ind", claim)));
            assert_eq!(
                receipt.receipt.row_count,
                Some(0),
                "ground truth must not depend on the client claim"
            );
        }
    }

    /// An honest client count matching the observed ground truth scores
    /// `Supported` — the positive control for the two negative-path tests above.
    #[test]
    fn honest_client_count_over_matching_ground_truth_scores_supported() {
        let result = github_result(2, false);
        let receipt = ground_truth_receipt("gw-ok", true, &result);
        assert_eq!(receipt.receipt.row_count, Some(2));

        let claim = derive_claim(Some(&ClientClaim::untrusted(
            "gw-ok",
            Claim::FoundRows { count: 2 },
        )));

        let (report, mis_joined) = capture_and_score("gw-ok", claim, receipt);
        assert_eq!(mis_joined, 0);
        assert_eq!(report.supported, 1);
        assert_eq!(report.unsupported + report.abstained + report.rejected, 0);
    }
}
