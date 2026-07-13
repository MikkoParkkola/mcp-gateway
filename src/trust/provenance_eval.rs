// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Offline provenance-eval harness (MIK-6906, rung 2).
//!
//! Rung 1 ([`super::result_provenance`]) stamps a signed, facts-only receipt of
//! every observed tool call. This harness is the first *consumer* of those
//! receipts: it replays real tool traffic, treats the signed receipts as the
//! ground truth of what the gateway actually observed, and scores whether the
//! agent-visible *claim* attached to each result is supported by those facts.
//!
//! The metric it produces is the unsupported-claim rate — how often an agent
//! emits a claim the observed evidence does not back. That is the number the
//! MIK-5854 spike only pretended to measure: its ground truth was a hand-mirror
//! of its own classifier (`expected_verdict = classify(input)`), so it measured
//! nothing. Here the ground truth is the *receipt* — real observed data produced
//! by a separate component — and the fixture labels are independent literals.
//! [`tests::ground_truth_is_not_a_scorer_mirror`] proves the labels genuinely
//! discriminate rather than echoing the scorer.
//!
//! Design contract:
//! - **Offline / shadow only.** Pure functions, no async, no network, no wiring
//!   into any request path. Nothing here runs on the production hot path
//!   (MIK-6904.RUNG2.4).
//! - **Consumes signed receipts.** [`replay`] verifies each receipt's signature
//!   through the same [`AttestationValidator`] the gateway uses before it will
//!   score it; an unverifiable receipt is *rejected*, never scored, because
//!   untrusted ground truth is not ground truth (MIK-6904.RUNG2.1).
//! - **Abstain is first-class.** "The source could not be checked" is reported
//!   separately from "the source was checked and authoritatively empty"
//!   (MIK-6904.RUNG2.3). Conflating the two is the exact silent failure this
//!   whole line of work targets.

use serde::{Deserialize, Serialize};

use super::result_provenance::{RuntimeProvenanceReceipt, SignedResultProvenance};
use crate::attestation::validator::AttestationValidator;

/// What the agent surfaced to the user about a tool result — the claim under
/// scrutiny. Every variant is a statement the receipt facts can support,
/// contradict, or be silent on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Claim {
    /// "The source was queried and authoritatively returned nothing."
    /// Supported only by an *observed* empty result on a successful call.
    AuthoritativeEmpty,
    /// "The source returned exactly `count` matching rows/items."
    FoundRows {
        /// The exact row/item count the agent asserted.
        count: u64,
    },
    /// "The call succeeded." Asserts nothing about the row count.
    Succeeded,
}

/// The scorer's verdict on one claim, given the receipt facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimVerdict {
    /// The receipt facts entail the claim.
    Supported,
    /// The receipt facts contradict the claim.
    Unsupported,
    /// The receipt lacks the facts needed to adjudicate the claim
    /// ("could-not-check"). Distinct from an authoritative negative.
    Abstain,
}

/// Score one claim against the facts in a receipt.
///
/// This is the whole adjudication logic. It reads *only* observed facts
/// (`backend_ok`, `row_count`) and never infers meaning the receipt does not
/// carry — in particular an absent `row_count` is treated as "not observed"
/// (→ `Abstain`), never as zero. A failed call can never support any positive
/// claim, which is the checked-empty-vs-could-not-check distinction made
/// structural.
#[must_use]
pub fn score(claim: &Claim, receipt: &RuntimeProvenanceReceipt) -> ClaimVerdict {
    // A call the backend reported as failed cannot support any claim about what
    // the source "said" — this is could-not-check, never an authoritative fact.
    // Every claim (success, empty, count) is unsupported by a failure.
    if !receipt.backend_ok {
        return ClaimVerdict::Unsupported;
    }

    match claim {
        // Success is directly observed.
        Claim::Succeeded => ClaimVerdict::Supported,
        Claim::AuthoritativeEmpty => match receipt.row_count {
            Some(0) => ClaimVerdict::Supported,
            Some(_) => ClaimVerdict::Unsupported,
            // Count not observed → cannot confirm the source was actually empty.
            None => ClaimVerdict::Abstain,
        },
        Claim::FoundRows { count } => match receipt.row_count {
            Some(observed) if observed == *count => ClaimVerdict::Supported,
            Some(_) => ClaimVerdict::Unsupported,
            None => ClaimVerdict::Abstain,
        },
    }
}

/// One replayed unit: a claim the agent surfaced plus the signed receipt of the
/// call that produced it.
#[derive(Debug, Clone)]
pub struct ReplayCase {
    /// What the agent claimed about the result.
    pub claim: Claim,
    /// The signed provenance receipt rung 1 stamped for that call.
    pub signed: SignedResultProvenance,
}

/// Tally of a replay run. Every count is disjoint; `total == supported +
/// unsupported + abstained + rejected`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalReport {
    /// Cases seen.
    pub total: usize,
    /// Claims the receipt facts entailed.
    pub supported: usize,
    /// Claims the receipt facts contradicted.
    pub unsupported: usize,
    /// Claims the receipt could not adjudicate (could-not-check).
    pub abstained: usize,
    /// Cases whose receipt signature did not verify — excluded from scoring
    /// because untrusted ground truth cannot back a metric.
    pub rejected: usize,
}

impl EvalReport {
    /// Unsupported-claim rate over *adjudicated* cases only (supported +
    /// unsupported). Abstained and rejected cases are excluded from the
    /// denominator: an abstain is "insufficient evidence to judge", not a
    /// scoring failure, and must not be blended into the rate. Returns `None`
    /// when nothing was adjudicated.
    #[must_use]
    pub fn unsupported_rate(&self) -> Option<f64> {
        let adjudicated = self.supported + self.unsupported;
        if adjudicated == 0 {
            return None;
        }
        // Cast is safe: counts are small relative to f64's integer precision.
        #[allow(clippy::cast_precision_loss)]
        Some(self.unsupported as f64 / adjudicated as f64)
    }
}

/// Replay a set of cases against the observed receipts, verifying each
/// receipt's signature before scoring it.
///
/// Offline only. `validator` must hold the key the receipts were signed with;
/// receipts that fail verification are counted as `rejected` and never scored.
#[must_use]
pub fn replay(cases: &[ReplayCase], validator: &AttestationValidator) -> EvalReport {
    let mut report = EvalReport::default();
    for case in cases {
        report.total += 1;
        if !validator.verify_result_provenance(&case.signed) {
            report.rejected += 1;
            continue;
        }
        match score(&case.claim, &case.signed.receipt) {
            ClaimVerdict::Supported => report.supported += 1,
            ClaimVerdict::Unsupported => report.unsupported += 1,
            ClaimVerdict::Abstain => report.abstained += 1,
        }
    }
    report
}

/// One line of an offline provenance-eval corpus (MIK-6908, rung 3): the
/// claim under scrutiny, the signed receipt it should be judged against, and
/// the `call_id` join key that binds the two together.
///
/// A corpus is assembled from two independently sourced streams — an agent's
/// rendered claims and the gateway's signed receipt log — so nothing
/// guarantees they arrive pre-zipped in the right order. `call_id` is the
/// join key [`super::result_provenance::RuntimeProvenanceReceipt::call_id`]
/// exists for: [`score_corpus`] enforces it explicitly rather than trusting
/// positional alignment between the two streams.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusRecord {
    /// The call this record is about. Must equal the `call_id` carried
    /// inside `receipt.receipt` for the record to be scored — see
    /// [`score_corpus`].
    pub call_id: String,
    /// What the agent claimed about the result of that call.
    pub claim: Claim,
    /// The signed provenance receipt rung 1 stamped for that call.
    pub receipt: SignedResultProvenance,
}

/// Score a corpus of independently sourced (claim, receipt) pairs, enforcing
/// the `call_id` join before any record reaches [`replay`].
///
/// A record whose `call_id` does not equal the `call_id` carried inside its
/// own `receipt` is a **mis-join**: two independently authored streams (an
/// agent transcript and a gateway receipt log) were zipped together
/// incorrectly, so the claim and the receipt do not describe the same call.
/// Mis-joined records are counted in the returned `usize` and are excluded
/// entirely from the [`EvalReport`] — they are never scored, because judging
/// a claim against the wrong call's receipt would produce a number that
/// looks like a metric but measures nothing (MIK-6908.RUNG3.2).
///
/// Returns `(report, mis_joined_count)`.
#[must_use]
pub fn score_corpus(
    records: &[CorpusRecord],
    validator: &AttestationValidator,
) -> (EvalReport, usize) {
    let mut mis_joined = 0usize;
    let cases: Vec<ReplayCase> = records
        .iter()
        .filter_map(|record| {
            if record.receipt.receipt.call_id.as_deref() == Some(record.call_id.as_str()) {
                Some(ReplayCase {
                    claim: record.claim.clone(),
                    signed: record.receipt.clone(),
                })
            } else {
                mis_joined += 1;
                None
            }
        })
        .collect();
    (replay(&cases, validator), mis_joined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::signer::BnautAttestationSigner;
    use crate::trust::result_provenance::CacheOutcome;

    const KEY: &[u8] = b"provenance-eval-test-key";

    fn signer() -> BnautAttestationSigner {
        BnautAttestationSigner::new(KEY.to_vec(), "unit")
    }

    fn validator() -> AttestationValidator {
        AttestationValidator::new(signer())
    }

    /// Build a signed receipt from observed facts. `row_count = None` models a
    /// backend that exposes no count.
    fn signed_receipt(
        backend_ok: bool,
        row_count: Option<u64>,
        cache: CacheOutcome,
    ) -> SignedResultProvenance {
        let mut r = RuntimeProvenanceReceipt::observed(
            "demo",
            "search",
            "2026-07-13T10:15:30Z",
            cache,
            backend_ok,
        );
        if let Some(n) = row_count {
            r = r.with_row_count(n);
        }
        r.sign(&signer())
    }

    /// Build a signed receipt carrying an explicit `call_id`, for
    /// [`score_corpus`] join-key tests.
    fn signed_receipt_with_call_id(
        call_id: &str,
        backend_ok: bool,
        row_count: Option<u64>,
    ) -> SignedResultProvenance {
        let mut r = RuntimeProvenanceReceipt::observed(
            "demo",
            "search",
            "2026-07-13T10:15:30Z",
            CacheOutcome::Miss,
            backend_ok,
        )
        .with_call_id(call_id);
        if let Some(n) = row_count {
            r = r.with_row_count(n);
        }
        r.sign(&signer())
    }

    /// The labelled ground-truth set. Every `expected` is a hand-authored
    /// literal — NOT computed by `score` — so the fixture is an independent
    /// oracle, not a mirror of the classifier (MIK-6904.RUNG2.3).
    fn ground_truth() -> Vec<(ReplayCase, ClaimVerdict)> {
        vec![
            // Source queried, genuinely empty → the "no results" claim is honest.
            (
                ReplayCase {
                    claim: Claim::AuthoritativeEmpty,
                    signed: signed_receipt(true, Some(0), CacheOutcome::Miss),
                },
                ClaimVerdict::Supported,
            ),
            // The core silent failure: call FAILED but agent rendered "no results".
            (
                ReplayCase {
                    claim: Claim::AuthoritativeEmpty,
                    signed: signed_receipt(false, None, CacheOutcome::Miss),
                },
                ClaimVerdict::Unsupported,
            ),
            // Backend exposes no count → cannot confirm authoritative-empty.
            (
                ReplayCase {
                    claim: Claim::AuthoritativeEmpty,
                    signed: signed_receipt(true, None, CacheOutcome::Hit),
                },
                ClaimVerdict::Abstain,
            ),
            // Honest count claim.
            (
                ReplayCase {
                    claim: Claim::FoundRows { count: 3 },
                    signed: signed_receipt(true, Some(3), CacheOutcome::Miss),
                },
                ClaimVerdict::Supported,
            ),
            // Inflated count claim.
            (
                ReplayCase {
                    claim: Claim::FoundRows { count: 10 },
                    signed: signed_receipt(true, Some(3), CacheOutcome::Miss),
                },
                ClaimVerdict::Unsupported,
            ),
            // Success genuinely observed.
            (
                ReplayCase {
                    claim: Claim::Succeeded,
                    signed: signed_receipt(true, None, CacheOutcome::Bypass),
                },
                ClaimVerdict::Supported,
            ),
            // "Succeeded" over a failed call.
            (
                ReplayCase {
                    claim: Claim::Succeeded,
                    signed: signed_receipt(false, None, CacheOutcome::Miss),
                },
                ClaimVerdict::Unsupported,
            ),
        ]
    }

    /// MIK-6904.RUNG2.2 — the scorer flags a known unsupported claim and passes
    /// a known supported one on the fixed labelled fixture.
    #[test]
    fn scorer_matches_every_ground_truth_label() {
        for (case, expected) in ground_truth() {
            assert_eq!(
                score(&case.claim, &case.signed.receipt),
                expected,
                "scorer disagreed with independent label for {:?}",
                case.claim
            );
        }
    }

    /// MIK-6904.RUNG2.3 — the labels are not a hand-copy of the verdict rules.
    /// A degenerate scorer that blindly returns `Supported` must FAIL the
    /// fixture; if it passed, the labels would carry no independent signal and
    /// the metric would be unfalsifiable (the exact spike failure).
    #[test]
    fn ground_truth_is_not_a_scorer_mirror() {
        let const_supported = |_: &Claim, _: &RuntimeProvenanceReceipt| ClaimVerdict::Supported;
        let disagreements = ground_truth()
            .iter()
            .filter(|(case, expected)| {
                const_supported(&case.claim, &case.signed.receipt) != *expected
            })
            .count();
        assert!(
            disagreements > 0,
            "a constant scorer reproduced the fixture — labels do not discriminate"
        );
    }

    /// MIK-6904.RUNG2.3 — the report keeps could-not-check separate from
    /// authoritative-negative. The fixture contains at least one of each and
    /// they land in different buckets.
    #[test]
    fn report_separates_abstain_from_authoritative_negative() {
        let cases: Vec<ReplayCase> = ground_truth().into_iter().map(|(c, _)| c).collect();
        let report = replay(&cases, &validator());
        // At least one abstain (could-not-check) and one authoritative-empty
        // (supported) — proving the two are counted distinctly, not merged.
        assert!(report.abstained >= 1, "no could-not-check case counted");
        assert!(
            report.supported >= 1,
            "no authoritative-negative/positive case counted"
        );
        assert_eq!(
            report.total,
            report.supported + report.unsupported + report.abstained + report.rejected
        );
    }

    /// MIK-6904.RUNG2.1 — replay consumes *signed* receipts: a tampered receipt
    /// whose signature no longer verifies is rejected, never scored.
    #[test]
    fn replay_rejects_unverifiable_receipts() {
        let mut case = ReplayCase {
            claim: Claim::Succeeded,
            signed: signed_receipt(true, None, CacheOutcome::Miss),
        };
        // Tamper: flip an observed fact without re-signing.
        case.signed.receipt.backend_ok = false;
        let report = replay(&[case], &validator());
        assert_eq!(report.rejected, 1);
        assert_eq!(report.supported + report.unsupported + report.abstained, 0);
    }

    /// A receipt signed with a different key is not trusted ground truth.
    #[test]
    fn replay_rejects_foreign_key_signatures() {
        let foreign = BnautAttestationSigner::new(b"someone-elses-key".to_vec(), "unit");
        let mut receipt = RuntimeProvenanceReceipt::observed(
            "demo",
            "search",
            "2026-07-13T10:15:30Z",
            CacheOutcome::Miss,
            true,
        );
        receipt = receipt.with_row_count(0);
        let case = ReplayCase {
            claim: Claim::AuthoritativeEmpty,
            signed: receipt.sign(&foreign),
        };
        let report = replay(&[case], &validator());
        assert_eq!(report.rejected, 1);
    }

    /// The unsupported-claim rate is computed over adjudicated cases only, with
    /// abstain and rejected excluded from the denominator.
    #[test]
    fn unsupported_rate_excludes_abstain_and_rejected() {
        let cases: Vec<ReplayCase> = ground_truth().into_iter().map(|(c, _)| c).collect();
        let report = replay(&cases, &validator());
        // Fixture: 3 supported, 3 unsupported, 1 abstain, 0 rejected.
        assert_eq!(report.supported, 3);
        assert_eq!(report.unsupported, 3);
        assert_eq!(report.abstained, 1);
        assert_eq!(report.rejected, 0);
        let rate = report.unsupported_rate().expect("adjudicated cases exist");
        assert!((rate - 3.0 / 6.0).abs() < 1e-9, "rate was {rate}");
    }

    #[test]
    fn empty_replay_has_no_rate() {
        assert_eq!(EvalReport::default().unsupported_rate(), None);
    }

    /// MIK-6908.RUNG3.2 — correctly-joined records (record `call_id` equals
    /// the `call_id` inside their own receipt) score exactly as [`replay`]
    /// would score them directly, and nothing is flagged mis-joined.
    #[test]
    fn score_corpus_scores_correctly_joined_records() {
        let records = vec![
            CorpusRecord {
                call_id: "gw-call-1".to_string(),
                claim: Claim::FoundRows { count: 3 },
                receipt: signed_receipt_with_call_id("gw-call-1", true, Some(3)),
            },
            CorpusRecord {
                call_id: "gw-call-2".to_string(),
                claim: Claim::FoundRows { count: 10 },
                receipt: signed_receipt_with_call_id("gw-call-2", true, Some(3)),
            },
            CorpusRecord {
                call_id: "gw-call-3".to_string(),
                claim: Claim::AuthoritativeEmpty,
                receipt: signed_receipt_with_call_id("gw-call-3", true, None),
            },
        ];
        let (report, mis_joined) = score_corpus(&records, &validator());
        assert_eq!(mis_joined, 0);
        assert_eq!(report.total, 3);
        assert_eq!(report.supported, 1, "the honest count claim");
        assert_eq!(report.unsupported, 1, "the inflated count claim");
        assert_eq!(report.abstained, 1, "no observed row_count");
        assert_eq!(report.rejected, 0);
    }

    /// MIK-6908.RUNG3.2 — a record whose `call_id` disagrees with the
    /// `call_id` carried inside its own receipt is a mis-join: it is counted
    /// in the returned `usize` and never reaches [`replay`], so it cannot
    /// pollute `total`/`supported`/`unsupported`/`abstained`/`rejected`.
    #[test]
    fn score_corpus_excludes_mis_joined_records_from_the_report() {
        let records = vec![
            // Correctly joined — must still be scored.
            CorpusRecord {
                call_id: "gw-call-1".to_string(),
                claim: Claim::Succeeded,
                receipt: signed_receipt_with_call_id("gw-call-1", true, None),
            },
            // Mis-joined: claim's call_id ("gw-call-2") does not match the
            // receipt's own call_id ("gw-call-99").
            CorpusRecord {
                call_id: "gw-call-2".to_string(),
                claim: Claim::Succeeded,
                receipt: signed_receipt_with_call_id("gw-call-99", true, None),
            },
        ];
        let (report, mis_joined) = score_corpus(&records, &validator());
        assert_eq!(mis_joined, 1, "exactly one mis-joined record");
        assert_eq!(
            report.total, 1,
            "only the correctly-joined record is scored"
        );
        assert_eq!(report.supported, 1);
        assert_eq!(
            report.supported + report.unsupported + report.abstained + report.rejected,
            report.total,
            "mis-joined record must not appear in any bucket"
        );
    }

    /// A record with no `call_id` on its receipt at all (e.g. a receipt from
    /// a direct/untraced route) is also a mis-join under the same rule — it
    /// cannot be proven to describe the claimed call, so it is excluded
    /// rather than silently scored.
    #[test]
    fn score_corpus_treats_missing_receipt_call_id_as_mis_joined() {
        let records = vec![CorpusRecord {
            call_id: "gw-call-1".to_string(),
            claim: Claim::Succeeded,
            receipt: signed_receipt(true, None, CacheOutcome::Miss),
        }];
        let (report, mis_joined) = score_corpus(&records, &validator());
        assert_eq!(mis_joined, 1);
        assert_eq!(report.total, 0);
    }

    /// MIK-6908.RUNG3.2 — a correctly-joined record whose signature does not
    /// verify is rejected by the underlying [`replay`], distinctly from a
    /// mis-join: the join key matched, but the ground truth is untrusted.
    #[test]
    fn score_corpus_rejects_bad_signatures_via_replay() {
        let mut receipt = signed_receipt_with_call_id("gw-call-1", true, None);
        // Tamper after signing without re-signing — the HMAC no longer covers
        // the mutated fact.
        receipt.receipt.backend_ok = false;
        let records = vec![CorpusRecord {
            call_id: "gw-call-1".to_string(),
            claim: Claim::Succeeded,
            receipt,
        }];
        let (report, mis_joined) = score_corpus(&records, &validator());
        assert_eq!(mis_joined, 0, "join key matched; this is not a mis-join");
        assert_eq!(report.total, 1);
        assert_eq!(report.rejected, 1);
        assert_eq!(report.supported + report.unsupported + report.abstained, 0);
    }

    /// MIK-6908.RUNG3.2/RUNG3.3 — `unsupported_rate` on a `score_corpus`
    /// report is computed exactly as it is on a direct [`replay`] report:
    /// over adjudicated cases only, excluding mis-joins (never reach the
    /// report), abstains, and rejections from the denominator.
    #[test]
    fn score_corpus_unsupported_rate_matches_expected() {
        let records = vec![
            CorpusRecord {
                call_id: "gw-call-1".to_string(),
                claim: Claim::FoundRows { count: 3 },
                receipt: signed_receipt_with_call_id("gw-call-1", true, Some(3)),
            },
            CorpusRecord {
                call_id: "gw-call-2".to_string(),
                claim: Claim::FoundRows { count: 10 },
                receipt: signed_receipt_with_call_id("gw-call-2", true, Some(3)),
            },
            CorpusRecord {
                call_id: "gw-call-3".to_string(),
                claim: Claim::AuthoritativeEmpty,
                receipt: signed_receipt_with_call_id("gw-call-3", true, None),
            },
            // Mis-joined — must not shift the rate.
            CorpusRecord {
                call_id: "gw-call-4".to_string(),
                claim: Claim::Succeeded,
                receipt: signed_receipt_with_call_id("gw-call-mismatch", true, None),
            },
        ];
        let (report, mis_joined) = score_corpus(&records, &validator());
        assert_eq!(mis_joined, 1);
        let rate = report.unsupported_rate().expect("adjudicated cases exist");
        assert!((rate - 1.0 / 2.0).abs() < 1e-9, "rate was {rate}");
    }
}
