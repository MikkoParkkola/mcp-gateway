// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8251`: the delivered runs of a plan step's own span of the answer.

use std::collections::HashSet;

use super::super::collusion::CollusionDetector;
use super::{Delivered, Segment, run_forms};

/// `MIK-8251`: the sampled fingerprints of each run of the step's own answer
/// leaves that it staged whole, read in ANSWER order and broken at every
/// leaf of another step or one it did not stage whole. That is text the
/// caller received contiguously from this step (an extra copy the count cap
/// keeps out of the receipt's text still sits in it), so a run across a
/// late-redacted marker stays receipted. Fingerprints only, never kept text.
pub(super) fn own_span_delivered_runs(
    detector: &CollusionDetector,
    delivered: &Delivered<'_>,
    step: Option<u32>,
    whole: &HashSet<(&str, bool)>,
) -> Vec<u64> {
    let mut fps = Vec::new();
    let mut run: Vec<Segment> = Vec::new();
    let mut flush = |run: &mut Vec<Segment>| {
        if run.len() > 1 {
            let refs: Vec<&Segment> = run.iter().collect();
            fps.extend(
                run_forms(&refs)
                    .iter()
                    .flat_map(|f| detector.fingerprints(f)),
            );
        }
        run.clear();
    };
    for (i, leaf) in delivered.all.iter().enumerate() {
        let key = i >= delivered.values_len;
        if step.is_some() && delivered.label(i) == step && whole.contains(&(*leaf, key)) {
            run.push(Segment {
                text: (*leaf).to_owned(),
                whole: true,
                gap_before: false,
                key,
            });
        } else {
            flush(&mut run);
        }
    }
    flush(&mut run);
    fps
}
