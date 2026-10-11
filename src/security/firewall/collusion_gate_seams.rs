// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8205`: the gate's side of a caller's own subset-forward seams (the
//! seam pass itself is `collusion_seam_excuse.rs`, in the detector).

#[cfg(test)]
use std::time::{Duration, Instant};

use serde_json::Value;

use super::super::collusion::Recorded;
use super::super::collusion::big::{KeptStep, StepEvidence, UnreadStep};
use super::super::collusion_digest::{Judged, UnreadReceipt};
use super::{
    CAPACITY_METRIC, CollusionDetector, DeliveryDigest, Firewall, RelayCaller, key_path_runs,
};

impl Firewall {
    /// The tail of `record_digest` for a single-source receipt: record it
    /// capped (MIK-7992), then its subset-forward seams (`MIK-8205`), read
    /// before capping, which keeps no seams.
    pub(super) fn record_kept(
        &self,
        detector: &CollusionDetector,
        source: &str,
        caller: RelayCaller<'_>,
        flows: u64,
        digest: &DeliveryDigest,
    ) {
        let now = self.relay.now();
        // `MIK-8066` D9: a step's evidence reaches the record only through
        // its judgement, matched exhaustively with every field named.
        let sample = match &digest.judged {
            Judged::Unread {
                receipt: UnreadReceipt { fps, cut },
                step,
            } => {
                let sample = step.as_ref().map(|UnreadStep { evidence }| evidence.fps());
                let recorded = (fps.clone(), cut.clone(), sample);
                Self::record_unread(
                    detector,
                    (source, caller),
                    (digest.sensitive, flows),
                    recorded,
                    now,
                );
                return;
            }
            Judged::Staged(big) => {
                // Never retained (unreachable in today's wiring): fail
                // closed, as an unread answer.
                let capped = self.capped(digest);
                let receipt = capped.as_ref().unwrap_or(digest);
                let recorded = (
                    receipt.fingerprints(detector),
                    receipt.cut_fps.clone(),
                    Some(big.staged_evidence()),
                );
                Self::record_unread(
                    detector,
                    (source, caller),
                    (digest.sensitive, flows),
                    recorded,
                    now,
                );
                return;
            }
            Judged::Kept(Some(KeptStep { evidence, excuse })) => {
                if let Some(excuse) = excuse {
                    excuse.publish(now);
                }
                evidence.as_ref().map(StepEvidence::fps)
            }
            Judged::Kept(None) | Judged::Pending => None,
        };
        // `MIK-8205`: read before capping, which keeps no seams.
        let seams = digest.seam_excuses.clone();
        // MIK-7992: the one sink every record passes, so a plan step's
        // receipt never kept to its plan's answer is recorded capped too.
        let capped = self.capped(digest);
        let digest = capped.as_ref().unwrap_or(digest);
        detector.record_sampled_at(
            (source, caller.key()),
            (digest.sensitive, flows),
            (
                digest.fingerprints(detector),
                digest.cut_fps.clone(),
                sample,
            ),
            now,
        );
        if let Some(seams) = seams {
            detector.record_seam_excuses_at(source, caller.key(), &seams, now);
        }
    }

    /// `MIK-8066` D6: an unread receipt's evidence under the caller's unread
    /// holder, and the caller's excuse from `source` marked lost, so it is
    /// refused for lost room, never excused. No seams: nothing was read.
    fn record_unread(
        detector: &CollusionDetector,
        (source, caller): (&str, RelayCaller<'_>),
        held: (bool, u64),
        recorded: Recorded,
        now: std::time::Instant,
    ) {
        detector.record_unread_at((source, caller.key()), held, recorded, now);
        detector.mark_step_lost(source, caller.key());
    }

    /// `MIK-8205` (S4): the subset-forward seams of a plan `answer`'s runs,
    /// by the owner that produced each run. Only a run whose pieces all have
    /// one owner (`owner_of`, by identity: the one receipt that keeps the
    /// piece whole) gets seams; a run spanning owners gets none (its
    /// cross-step seams are `MIK-8113`, K6). One capped pass over all such
    /// runs. Empty with relay detection off.
    pub(crate) fn single_step_subset_seams(
        &self,
        answer: &Value,
        owner_of: &dyn Fn(&str) -> Option<u32>,
    ) -> Vec<(u32, Vec<u64>)> {
        let Some(detector) = self.relay_detector() else {
            return Vec::new();
        };
        let mut runs = Vec::new();
        let mut steps = Vec::new();
        for run in key_path_runs(answer) {
            let labels: Option<Vec<u32>> = run.iter().map(|piece| owner_of(piece)).collect();
            let Some(labels) = labels else { continue };
            let Some(&step) = labels.first() else {
                continue;
            };
            if labels.iter().all(|&l| l == step) {
                runs.push(run);
                steps.push(step);
            }
        }
        let (by_run, cut) = detector.seam_excuses_by_run(&runs);
        if cut {
            telemetry_metrics::counter!(CAPACITY_METRIC, "bound" => "seam_excuse_cut").increment(1);
        }
        let mut by_step: std::collections::BTreeMap<u32, Vec<u64>> =
            std::collections::BTreeMap::new();
        for (r, fp) in by_run {
            by_step.entry(steps[r]).or_default().push(fp);
        }
        by_step.into_iter().collect()
    }
}

impl Firewall {
    /// Freeze this firewall's receipt clock `by` past its current reading, so
    /// a row ages its receipts without sleeping and without wall time moving
    /// them afterwards (MIK-8354). Per instance: other firewalls keep the real
    /// clock, which parallel tests need.
    #[cfg(test)]
    pub(crate) fn advance_collusion_clock_for_test(&self, by: Duration) {
        let mut frozen = self.relay.frozen.lock();
        *frozen = Some(frozen.unwrap_or_else(Instant::now) + by);
    }
}
