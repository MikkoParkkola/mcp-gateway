// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8205`: the gate's side of a caller's own subset-forward seams (the
//! seam pass itself is `collusion_seam_excuse.rs`, in the detector).

use std::time::Instant;

use serde_json::Value;

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
        // `MIK-8205`: read before capping, which keeps no seams.
        let seams = digest.seam_excuses.clone();
        // MIK-7992: the one sink every record passes, so a plan step's
        // receipt never kept to its plan's answer is recorded capped too.
        let capped = self.capped(digest);
        let digest = capped.as_ref().unwrap_or(digest);
        let now = Instant::now();
        detector.record_cut_fingerprints_at(
            source,
            caller.key(),
            (digest.sensitive, flows),
            (digest.fingerprints(detector), digest.cut_fps.clone()),
            now,
        );
        if let Some(seams) = seams {
            detector.record_seam_excuses_at(source, caller.key(), &seams, now);
        }
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
