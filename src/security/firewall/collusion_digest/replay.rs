// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8408` stage 1: a committed receipt as an immutable replay
//! snapshot, and a fresh digest built from one. A child of
//! `collusion_digest`, so it reads the digest's private fields without
//! widening any of them; the store that holds the snapshots is
//! `collusion::replay`.

use std::sync::Arc;

use super::super::collusion::CollusionDetector;
use super::super::collusion::replay::REPLAY_ITEM_OVERHEAD;
use super::{Delivered, DeliveryDigest, Joins, Judged, Segment, UnreadReceipt};

/// One piece of delivered text, as a snapshot holds it: [`ReplayReceipt`]'s
/// copy of a digest segment.
#[derive(Clone)]
pub(in super::super) struct ReplaySegment {
    pub(in super::super) text: String,
    pub(in super::super) whole: bool,
    pub(in super::super) gap_before: bool,
    pub(in super::super) key: bool,
}

/// A snapshot's key-path joins, mirroring the digest's own three shapes so
/// a replay records the same join fingerprints in the same position.
#[derive(Clone)]
pub(in super::super) enum ReplayJoins {
    None,
    Text(Box<[String]>),
    Runs(Box<[Box<[u32]>]>),
    Fps(Box<[u64]>),
}

/// The judged state a snapshot may carry (F2/F3): every state whose
/// recording needs no big-step reservation. A receipt judged `Kept(Some)`
/// or `Unread { step: Some }`, or still `Staged`, holds evidence and an
/// excuse bound to the original caller's reserved sketch position, so it
/// yields no snapshot at all and never reaches this enum.
#[derive(Clone)]
pub(in super::super) enum ReplayJudged {
    /// Not judged: an ordinary delivery, or a receipt not yet retained.
    Pending,
    /// Kept to a read answer, with no big step behind it.
    Kept,
    /// The answer could not be read: the capped receipt's evidence and
    /// cut, recorded under an unread holder exactly as live.
    Unread {
        fps: Vec<u64>,
        cut: Option<Arc<[u64]>>,
    },
}

/// An immutable snapshot of one committed in-plan receipt (F2): every
/// field `record_digest` reads to record that receipt, and nothing else.
/// It holds no view charge, no one-shot `recorded` flag and no big-step
/// reservation, so a fresh digest built from it records as a first record.
/// It also holds no `leaf_hashes`: recording never reads them (they serve
/// seam ownership before commit, which a replay does not re-run).
#[derive(Clone)]
pub(crate) struct ReplayReceipt {
    /// The plan step label; `None` for a seam receipt.
    pub(in super::super) label: Option<u32>,
    /// The `server` the receipt is recorded under.
    pub(in super::super) server: String,
    /// The `tool` the receipt is recorded under.
    pub(in super::super) tool: String,
    pub(in super::super) segments: Vec<ReplaySegment>,
    /// Fingerprints retained from leaves a change removed.
    pub(in super::super) retained: Vec<u64>,
    pub(in super::super) sensitive: bool,
    /// Staged whole, its cap still to apply where it is recorded.
    pub(in super::super) deferred: bool,
    /// A seam of two or more sources: the contributing `server:tool`s.
    pub(in super::super) seam_sources: Option<Box<[String]>>,
    /// What the holder received when this receipt was cut: excuse only.
    pub(in super::super) cut_fps: Option<Arc<[u64]>>,
    pub(in super::super) joins: ReplayJoins,
    /// The caller's own subset-forward seams: excuse only.
    pub(in super::super) seam_excuses: Option<Arc<[u64]>>,
    pub(in super::super) judged: ReplayJudged,
    /// A view cut was refused its charge; recording marks the excuse lost.
    pub(in super::super) cut_lost: bool,
}

impl ReplayReceipt {
    /// Its real byte size in the store's accounting: fingerprint bytes plus
    /// text bytes plus [`REPLAY_ITEM_OVERHEAD`] per item held.
    pub(in super::super) fn bytes(&self) -> usize {
        let mut total = REPLAY_ITEM_OVERHEAD
            .saturating_add(self.server.len())
            .saturating_add(self.tool.len())
            .saturating_add(self.retained.len().saturating_mul(8));
        for segment in &self.segments {
            total = total
                .saturating_add(segment.text.len())
                .saturating_add(REPLAY_ITEM_OVERHEAD);
        }
        if let Some(sources) = &self.seam_sources {
            for source in sources {
                total = total
                    .saturating_add(source.len())
                    .saturating_add(REPLAY_ITEM_OVERHEAD);
            }
        }
        for fps in [self.cut_fps.as_deref(), self.seam_excuses.as_deref()]
            .into_iter()
            .flatten()
        {
            total = total.saturating_add(fps.len().saturating_mul(8));
        }
        total = total.saturating_add(match &self.joins {
            ReplayJoins::None => 0,
            ReplayJoins::Text(joins) => joins
                .iter()
                .map(|j| j.len().saturating_add(REPLAY_ITEM_OVERHEAD))
                .fold(0_usize, usize::saturating_add),
            ReplayJoins::Runs(runs) => runs
                .iter()
                .map(|r| {
                    r.len()
                        .saturating_mul(4)
                        .saturating_add(REPLAY_ITEM_OVERHEAD)
                })
                .fold(0_usize, usize::saturating_add),
            ReplayJoins::Fps(fps) => fps.len().saturating_mul(8),
        });
        if let ReplayJudged::Unread { fps, cut } = &self.judged {
            total = total.saturating_add(fps.len().saturating_mul(8));
            if let Some(cut) = cut {
                total = total.saturating_add(cut.len().saturating_mul(8));
            }
        }
        total
    }
}

impl DeliveryDigest {
    /// This committed receipt as an immutable replay snapshot (F2), under
    /// step label `label` and source `server:tool`: every field recording
    /// reads, never the view charge, the one-shot `recorded` flag, the
    /// leaf hashes recording never reads, or a big-step reservation.
    /// `None` for a receipt whose judged state is a big-step excuse bound
    /// to the original caller (F3: `Kept(Some)` and
    /// `Unread { step: Some }`, and a step still `Staged`, whose
    /// reservation is that same caller's): the caller counts the drop.
    pub(in super::super) fn replay_snapshot(
        &self,
        label: Option<u32>,
        server: &str,
        tool: &str,
    ) -> Option<ReplayReceipt> {
        let judged = match &self.judged {
            Judged::Pending => ReplayJudged::Pending,
            Judged::Kept(None) => ReplayJudged::Kept,
            Judged::Kept(Some(_)) | Judged::Staged(_) => return None,
            Judged::Unread { receipt, step } => match step {
                Some(_) => return None,
                None => ReplayJudged::Unread {
                    fps: receipt.fps.clone(),
                    cut: receipt.cut.clone(),
                },
            },
        };
        let joins = match &self.joins {
            Joins::None => ReplayJoins::None,
            Joins::Text(joins) => ReplayJoins::Text(joins.clone()),
            Joins::Runs(runs) => ReplayJoins::Runs(runs.clone()),
            Joins::Fps(fps) => ReplayJoins::Fps(fps.clone()),
        };
        Some(ReplayReceipt {
            label,
            server: server.to_owned(),
            tool: tool.to_owned(),
            segments: self
                .segments
                .iter()
                .map(|s| ReplaySegment {
                    text: s.text.clone(),
                    whole: s.whole,
                    gap_before: s.gap_before,
                    key: s.key,
                })
                .collect(),
            retained: self.retained.clone(),
            sensitive: self.sensitive,
            deferred: self.deferred,
            seam_sources: self.seam_sources.clone(),
            cut_fps: self.cut_fps.clone(),
            joins,
            seam_excuses: self.seam_excuses.clone(),
            judged,
            cut_lost: self.cut_lost,
        })
    }

    /// A fresh digest from a replay snapshot (F2): `recorded` unset, no
    /// view charge and no reservation, so recording it records exactly
    /// what the snapshotted receipt recorded.
    pub(crate) fn of_replay_receipt(receipt: &ReplayReceipt) -> Self {
        // On the default digest, whose `recorded` flag, view charge and
        // leaf hashes are already the fresh values a replay starts with.
        Self {
            segments: receipt
                .segments
                .iter()
                .map(|s| Segment {
                    text: s.text.clone(),
                    whole: s.whole,
                    gap_before: s.gap_before,
                    key: s.key,
                })
                .collect(),
            retained: receipt.retained.clone(),
            sensitive: receipt.sensitive,
            deferred: receipt.deferred,
            seam_sources: receipt.seam_sources.clone(),
            cut_fps: receipt.cut_fps.clone(),
            joins: match &receipt.joins {
                ReplayJoins::None => Joins::None,
                ReplayJoins::Text(joins) => Joins::Text(joins.clone()),
                ReplayJoins::Runs(runs) => Joins::Runs(runs.clone()),
                ReplayJoins::Fps(fps) => Joins::Fps(fps.clone()),
            },
            seam_excuses: receipt.seam_excuses.clone(),
            judged: match &receipt.judged {
                ReplayJudged::Pending => Judged::Pending,
                ReplayJudged::Kept => Judged::Kept(None),
                ReplayJudged::Unread { fps, cut } => Judged::Unread {
                    receipt: UnreadReceipt {
                        fps: fps.clone(),
                        cut: cut.clone(),
                    },
                    step: None,
                },
            },
            cut_lost: receipt.cut_lost,
            ..Self::default()
        }
    }

    /// This replayed digest kept to the answer as delivered now (F4).
    /// Unchanged when every component is still delivered: each segment
    /// whole or inside a delivered leaf of its kind, and every recorded
    /// fingerprint among the answer's k-grams. Otherwise it is retained
    /// against the answer as a live receipt is, its seam sources restored
    /// (retention strips them), and the excuse-only sets that cannot be
    /// filtered safely (`cut_fps`, `seam_excuses`, an unread receipt's
    /// cut) are dropped. The second value says whether such a set was
    /// dropped, for the caller to count.
    pub(in super::super) fn kept_to_replay_answer(
        mut self,
        detector: &CollusionDetector,
        delivered: &Delivered<'_>,
        step: Option<u32>,
    ) -> (Self, bool) {
        let found = delivered.kgrams(detector);
        let unread_fps: &[u64] = match &self.judged {
            Judged::Unread { receipt, .. } => &receipt.fps,
            _ => &[],
        };
        let delivered_segment = |s: &Segment| {
            if delivered.holds(s) {
                return true;
            }
            if s.whole {
                return false;
            }
            let leaves = if s.key {
                &delivered.all[delivered.values_len.min(delivered.all.len())..]
            } else {
                &delivered.all[..delivered.values_len.min(delivered.all.len())]
            };
            leaves.iter().any(|leaf| leaf.contains(s.text.as_str()))
        };
        // As retention decides: a fingerprint also stays when it spans
        // adjacent kept leaves of this receipt's own runs, not only when
        // the answer's own forms hold it. The joins are not rechecked:
        // with every segment delivered, live retention's judgement of
        // them stands.
        let across = self.run_kgrams(detector);
        let fully = self.segments.iter().all(delivered_segment)
            && self
                .leaf_fingerprints(detector)
                .iter()
                .all(|fp| found.contains(fp) || across.contains(fp))
            && unread_fps.iter().all(|fp| found.contains(fp));
        if fully {
            return (self, false);
        }
        // An unread receipt's evidence lives in its judgement, not its
        // segments: filter it there, and drop its cut.
        if matches!(self.judged, Judged::Unread { .. }) {
            let mut dropped = self.cut_fps.take().is_some() || self.seam_excuses.take().is_some();
            if let Judged::Unread { receipt, .. } = &mut self.judged {
                receipt.fps.retain(|fp| found.contains(fp));
                dropped = dropped || receipt.cut.take().is_some();
            }
            self.segments.retain(|s| delivered_segment(s) && s.whole);
            self.retained.retain(|fp| found.contains(fp));
            return (self, dropped);
        }
        let dropped = self.cut_fps.is_some() || self.seam_excuses.is_some();
        let seam_sources = self.seam_sources.clone();
        let mut kept = self.retaining_for(detector, delivered, step);
        kept.seam_sources = seam_sources;
        (kept, dropped)
    }
}
