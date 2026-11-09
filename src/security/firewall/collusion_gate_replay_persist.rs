// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A task's replay entry persisted in its row: written by the
//! settle that stores the result, rebuilt by a read that finds no entry in
//! memory. The fingerprints are keyed per process, so the persisted form
//! carries the epoch it was made under and a process with another epoch
//! treats the result as untrackable. It holds no text the stored result
//! does not hold: segments only when the result delivers them, joins as
//! their fingerprints.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::super::collusion::replay::{ReplayHandle, StoredKey, count_replay_skipped};
use super::super::collusion::replay_epoch;
use super::super::collusion_digest::{ReplayJoins, ReplayJudged, ReplayReceipt, ReplaySegment};
use super::replay_gate::{ReplaySource, ReplayedDigest, replayed};
use super::{Delivered, Firewall, delivery_parts};
use crate::security::ReplayCalls;

/// The snapshot a row holds in place of one it could not keep; the task
/// store writes the same text (`record::SNAPSHOT_UNTRACKABLE`).
pub(crate) const SNAPSHOT_UNTRACKABLE: &str = "untrackable";

/// What a stored read found for its task's replay entry.
pub(crate) enum Adopted {
    /// No snapshot (an older row, detection off, nothing to replay): the
    /// read stages nothing from it, as before.
    NoSnapshot,
    /// A snapshot this process cannot track: the marker, another epoch, a
    /// form it cannot read, or one over the store's caps. Never plain.
    Untrackable,
    /// The entry, live or rebuilt from the row: its digests, its calls and
    /// the handle the delivery settles at its write.
    Held(Vec<ReplayedDigest>, ReplayCalls, Option<ReplayHandle>),
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Persisted {
    epoch: u64,
    answer_digest: String,
    calls: ReplayCalls,
    receipts: Vec<PersistedReceipt>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistedSegment {
    text: String,
    whole: bool,
    gap_before: bool,
    key: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
enum PersistedJoins {
    None,
    Runs(Vec<Vec<u32>>),
    Fps(Vec<u64>),
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
enum PersistedJudged {
    Pending,
    Kept,
    Unread {
        fps: Vec<u64>,
        cut: Option<Vec<u64>>,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistedReceipt {
    label: Option<u32>,
    server: String,
    tool: String,
    segments: Vec<PersistedSegment>,
    retained: Vec<u64>,
    inferred: bool,
    deferred: bool,
    seam_sources: Option<Vec<String>>,
    seam_inferred: Option<Vec<bool>>,
    cut_fps: Option<Vec<u64>>,
    joins: PersistedJoins,
    seam_excuses: Option<Vec<u64>>,
    judged: PersistedJudged,
    cut_lost: bool,
}

impl PersistedReceipt {
    /// `receipt` as persisted; `None` for text joins, which are converted
    /// to fingerprints before this (`with_join_fingerprints`).
    fn of(receipt: &ReplayReceipt) -> Option<Self> {
        Some(Self {
            label: receipt.label,
            server: receipt.server.clone(),
            tool: receipt.tool.clone(),
            segments: receipt
                .segments
                .iter()
                .map(|s| PersistedSegment {
                    text: s.text.clone(),
                    whole: s.whole,
                    gap_before: s.gap_before,
                    key: s.key,
                })
                .collect(),
            retained: receipt.retained.clone(),
            inferred: receipt.inferred,
            deferred: receipt.deferred,
            seam_sources: receipt.seam_sources.as_deref().map(<[String]>::to_vec),
            seam_inferred: receipt.seam_inferred.as_deref().map(<[bool]>::to_vec),
            cut_fps: receipt.cut_fps.as_deref().map(<[u64]>::to_vec),
            joins: match &receipt.joins {
                ReplayJoins::None => PersistedJoins::None,
                ReplayJoins::Text(_) => return None,
                ReplayJoins::Runs(runs) => {
                    PersistedJoins::Runs(runs.iter().map(|r| r.to_vec()).collect())
                }
                ReplayJoins::Fps(fps) => PersistedJoins::Fps(fps.to_vec()),
            },
            seam_excuses: receipt.seam_excuses.as_deref().map(<[u64]>::to_vec),
            judged: match &receipt.judged {
                ReplayJudged::Pending => PersistedJudged::Pending,
                ReplayJudged::Kept => PersistedJudged::Kept,
                ReplayJudged::Unread { fps, cut } => PersistedJudged::Unread {
                    fps: fps.clone(),
                    cut: cut.as_deref().map(<[u64]>::to_vec),
                },
            },
            cut_lost: receipt.cut_lost,
        })
    }

    /// The in-memory snapshot this persisted receipt was made from.
    fn into_receipt(self) -> ReplayReceipt {
        ReplayReceipt {
            label: self.label,
            server: self.server,
            tool: self.tool,
            segments: self
                .segments
                .into_iter()
                .map(|s| ReplaySegment {
                    text: s.text,
                    whole: s.whole,
                    gap_before: s.gap_before,
                    key: s.key,
                })
                .collect(),
            retained: self.retained,
            inferred: self.inferred,
            deferred: self.deferred,
            seam_sources: self.seam_sources.map(Vec::into_boxed_slice),
            seam_inferred: self.seam_inferred.map(Vec::into_boxed_slice),
            cut_fps: self.cut_fps.map(Arc::from),
            joins: match self.joins {
                PersistedJoins::None => ReplayJoins::None,
                PersistedJoins::Runs(runs) => {
                    ReplayJoins::Runs(runs.into_iter().map(Vec::into_boxed_slice).collect())
                }
                PersistedJoins::Fps(fps) => ReplayJoins::Fps(fps.into_boxed_slice()),
            },
            seam_excuses: self.seam_excuses.map(Arc::from),
            judged: match self.judged {
                PersistedJudged::Pending => ReplayJudged::Pending,
                PersistedJudged::Kept => ReplayJudged::Kept,
                PersistedJudged::Unread { fps, cut } => ReplayJudged::Unread {
                    fps,
                    cut: cut.map(Arc::from),
                },
            },
            cut_lost: self.cut_lost,
        }
    }
}

impl Firewall {
    /// The persisted form of a task's committed in-plan `receipts`, for the
    /// settle to store with `stored` (the result as stored), under this
    /// process's epoch. `None` with relay detection off or nothing to
    /// replay; the untrackable marker when the stored result does not
    /// deliver every segment, or is over the bound a replay reads.
    pub(crate) fn persisted_replay(
        &self,
        receipts: &[ReplaySource<'_>],
        calls: &ReplayCalls,
        answer_digest: &str,
        stored: &Value,
    ) -> Option<Value> {
        let detector = self.relay_detector()?;
        let mut snapshots = Vec::with_capacity(receipts.len());
        for (digest, label, server, tool) in receipts {
            match digest.replay_snapshot(*label, server, tool) {
                Some(snapshot) => snapshots.push(snapshot),
                None if digest.is_staged_step() => count_replay_skipped("staged"),
                None => count_replay_skipped("big_step"),
            }
        }
        if snapshots.is_empty() {
            return None;
        }
        let untrackable = Some(Value::from(SNAPSHOT_UNTRACKABLE));
        let (leaves, values) = delivery_parts(stored);
        let Some(delivered) = Delivered::of_parts(leaves, values) else {
            return untrackable;
        };
        let mut kept = Vec::with_capacity(snapshots.len());
        for snapshot in snapshots {
            if !snapshot.delivered_by(&delivered) {
                return untrackable;
            }
            kept.push(snapshot.with_join_fingerprints(detector));
        }
        // One the replay store would refuse is untrackable from the start, so
        // a read refuses it at its start, never after delivering it untracked.
        if !self.relay.replay.fits(&kept, calls, answer_digest) {
            return untrackable;
        }
        let mut persisted = Vec::with_capacity(kept.len());
        for receipt in &kept {
            let Some(receipt) = PersistedReceipt::of(receipt) else {
                return untrackable;
            };
            persisted.push(receipt);
        }
        serde_json::to_value(Persisted {
            epoch: replay_epoch(),
            answer_digest: answer_digest.to_owned(),
            calls: calls.clone(),
            receipts: persisted,
        })
        .ok()
        .or(untrackable)
    }

    /// The replay entry of the stored task read under `key`: a live entry
    /// as it is, else rebuilt from the row's `snapshot`, pending with this
    /// read as its one delivery and live for `retention` (capture-if-absent,
    /// one lock). With relay detection off nothing is read.
    pub(crate) fn adopt_replay(
        &self,
        key: &StoredKey,
        snapshot: Option<&Value>,
        retention: Duration,
    ) -> Adopted {
        if self.relay_detector().is_none() {
            return Adopted::NoSnapshot;
        }
        let Some(snapshot) = snapshot else {
            // Nothing to rebuild from: an entry already held is served as a
            // lookup serves it; a miss is counted by the store, as always.
            return self
                .replay_digests_for_delivery(key)
                .map_or(Adopted::NoSnapshot, |(digests, calls, handle)| {
                    Adopted::Held(digests, calls, handle)
                });
        };
        let Some(parts) = self.trackable_parts(snapshot) else {
            return Adopted::Untrackable;
        };
        let Some(acquired) = self
            .relay
            .replay
            .adopt(key, parts, self.relay.now(), retention)
        else {
            return Adopted::Untrackable;
        };
        let (entry, handle) = acquired.into_parts();
        Adopted::Held(replayed(&entry), entry.calls.clone(), handle)
    }
}

impl Firewall {
    /// The parts of a persisted `snapshot` this process can track: one it
    /// can read, made under this process's epoch, that the replay store's
    /// caps admit. `None` is untrackable. The one classifier a read's start
    /// and its rebuild share, so a snapshot judged trackable is rebuilt.
    fn trackable_parts(
        &self,
        snapshot: &Value,
    ) -> Option<(Vec<ReplayReceipt>, ReplayCalls, String)> {
        let persisted = serde_json::from_value::<Persisted>(snapshot.clone()).ok()?;
        if persisted.epoch != replay_epoch() {
            return None;
        }
        let receipts: Vec<ReplayReceipt> = persisted
            .receipts
            .into_iter()
            .map(PersistedReceipt::into_receipt)
            .collect();
        self.relay
            .replay
            .fits(&receipts, &persisted.calls, &persisted.answer_digest)
            .then_some((receipts, persisted.calls, persisted.answer_digest))
    }

    /// The verdict on a stored task read whose persisted snapshot this
    /// process cannot track (the marker, another epoch, a form it cannot
    /// read), under `view`, the collusion view published when the read
    /// starts: `None` when it is trackable, has no snapshot, or detection
    /// is off or `off`. `block` refuses the read; `observe` delivers it,
    /// the untrackable fact counted and audited as an observed relay is.
    /// Decided at read start: the write commits after the answer is built
    /// and cannot refuse it (a read that starts under `off` and is written
    /// under `block` delivers untracked: the stated limit).
    pub(crate) fn untrackable_read(
        &self,
        view: &super::super::CollusionView,
        snapshot: Option<&Value>,
        (server, tool): (&str, &str),
        audit: (&str, &str),
    ) -> Option<super::super::FirewallVerdict> {
        self.relay_detector()?;
        let trackable = self.trackable_parts(snapshot?).is_some();
        if trackable || view.action() == super::CollusionAction::Off {
            return None;
        }
        let block = view.action() == super::CollusionAction::Block;
        let label = if block { "block" } else { "observe" };
        telemetry_metrics::counter!(super::RELAY_METRIC, "action" => label, "reason" => "untrackable")
            .increment(1);
        let verdict = super::super::FirewallVerdict {
            allowed: !block,
            action: if block {
                super::super::FirewallAction::Block
            } else {
                super::super::FirewallAction::Warn
            },
            findings: vec![super::relay_finding(
                "stored task result cannot be tracked for relay in this process".to_string(),
                String::new(),
            )],
            anomaly_score: None,
        };
        if let Some(ref logger) = self.audit {
            logger.log_request(audit.0, server, tool, audit.1, &Value::Null, &verdict);
        }
        Some(verdict)
    }
}

#[cfg(test)]
#[path = "collusion_gate_replay_persist_tests.rs"]
mod tests;
