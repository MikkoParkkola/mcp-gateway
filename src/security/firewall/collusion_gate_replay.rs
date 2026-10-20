// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8408` stage 2: the firewall surface of the replay receipt store.
//! The gateway commits a stored plan delivery's in-plan receipts here and
//! reads fresh digests back at replay; the store, its keys and its
//! snapshots stay inside the firewall (E1, F1, F2).

use std::time::Duration;

use serde_json::Value;

use super::super::collusion::replay::{StoredKey, count_replay_skipped};
use super::{Delivered, DeliveryDigest, Firewall, delivery_parts};

/// One committed receipt to snapshot: its digest, its plan step label
/// (`None` for a seam) and the source it was recorded under.
pub(crate) type ReplaySource<'a> = (&'a DeliveryDigest, Option<u32>, &'a str, &'a str);

/// The calls one delivery dispatched, `(label, server, tool)` each (H2).
pub(crate) type ReplayCalls = Vec<(Option<u32>, String, String)>;

/// One fresh digest built from a stored snapshot (F2), with the label and
/// source it stages under and, for a composite seam, its contributing
/// `server:tool`s.
pub(crate) struct ReplayedDigest {
    pub(crate) digest: DeliveryDigest,
    pub(crate) label: Option<u32>,
    pub(crate) server: String,
    pub(crate) tool: String,
    pub(crate) seam_sources: Option<Box<[String]>>,
    /// The stored entry's answer digest (F4), the same on every digest
    /// of one entry: [`Firewall::keep_replayed_digest`] compares the
    /// replayed answer against it.
    pub(crate) answer_digest: String,
}

impl Firewall {
    /// Store the committed in-plan `receipts` of a retained sync plan
    /// delivery under its admission key (F1), with its `calls` and the
    /// digest of the delivered answer they were committed against (F4),
    /// live for `retention` (the retained result's own retention).
    pub(crate) fn store_sync_replay(
        &self,
        identity: &str,
        round: &str,
        operation: &str,
        receipts: &[ReplaySource<'_>],
        calls: ReplayCalls,
        answer_digest: &str,
        retention: Duration,
    ) {
        let key = StoredKey::Sync {
            identity: identity.to_owned(),
            round: round.to_owned(),
            operation: operation.to_owned(),
        };
        self.store_replay(key, receipts, calls, answer_digest, retention);
    }

    /// [`Self::store_sync_replay`] for a task's settled result, under
    /// `(task id, revision)`, live for the task's remaining retention.
    pub(crate) fn store_task_replay(
        &self,
        id: &str,
        revision: u64,
        receipts: &[ReplaySource<'_>],
        calls: ReplayCalls,
        answer_digest: &str,
        retention: Duration,
    ) {
        let key = StoredKey::Task {
            id: id.to_owned(),
            revision,
        };
        self.store_replay(key, receipts, calls, answer_digest, retention);
    }

    /// Snapshot each of `receipts` (F2), counting a `big_step` drop for
    /// each judged big-step receipt that yields no snapshot (F3) and a
    /// `staged` drop for a step still staged at capture, and insert the
    /// entry. When
    /// every candidate yielded no snapshot there is nothing to replay:
    /// no entry is inserted and any previous entry under the key goes,
    /// as an overwrite would take it.
    fn store_replay(
        &self,
        key: StoredKey,
        receipts: &[ReplaySource<'_>],
        calls: ReplayCalls,
        answer_digest: &str,
        retention: Duration,
    ) {
        if self.relay_detector().is_none() {
            return;
        }
        let mut snapshots = Vec::with_capacity(receipts.len());
        for (digest, label, server, tool) in receipts {
            match digest.replay_snapshot(*label, server, tool) {
                Some(snapshot) => snapshots.push(snapshot),
                None if digest.is_staged_step() => count_replay_skipped("staged"),
                None => count_replay_skipped("big_step"),
            }
        }
        if snapshots.is_empty() {
            self.relay.replay.remove(&key);
            return;
        }
        self.relay.replay.insert(
            key,
            snapshots,
            calls,
            answer_digest.to_owned(),
            self.relay.now(),
            retention,
        );
    }

    /// Drop a retained sync delivery's entry: a non-plan commit under the
    /// same key (F1).
    pub(crate) fn remove_sync_replay(&self, identity: &str, round: &str, operation: &str) {
        self.relay.replay.remove(&StoredKey::Sync {
            identity: identity.to_owned(),
            round: round.to_owned(),
            operation: operation.to_owned(),
        });
    }

    /// Drop a settled task's entry under `(task id, revision)`.
    pub(crate) fn remove_task_replay(&self, id: &str, revision: u64) {
        self.relay.replay.remove(&StoredKey::Task {
            id: id.to_owned(),
            revision,
        });
    }

    /// Fresh digests for a retained sync delivery's snapshots, with its
    /// calls; `None` stages nothing, counted `absent` or `expired` (E2).
    pub(crate) fn sync_replay_digests(
        &self,
        identity: &str,
        round: &str,
        operation: &str,
    ) -> Option<(Vec<ReplayedDigest>, ReplayCalls)> {
        let key = StoredKey::Sync {
            identity: identity.to_owned(),
            round: round.to_owned(),
            operation: operation.to_owned(),
        };
        self.replay_digests(&key)
    }

    /// [`Self::sync_replay_digests`] for a stored task at `revision`.
    pub(crate) fn task_replay_digests(
        &self,
        id: &str,
        revision: u64,
    ) -> Option<(Vec<ReplayedDigest>, ReplayCalls)> {
        let key = StoredKey::Task {
            id: id.to_owned(),
            revision,
        };
        self.replay_digests(&key)
    }

    fn replay_digests(&self, key: &StoredKey) -> Option<(Vec<ReplayedDigest>, ReplayCalls)> {
        let entry = self.relay.replay.lookup(key, self.relay.now())?;
        let digests = entry
            .receipts
            .iter()
            .map(|receipt| ReplayedDigest {
                digest: DeliveryDigest::of_replay_receipt(receipt),
                label: receipt.label,
                server: receipt.server.clone(),
                tool: receipt.tool.clone(),
                seam_sources: receipt.seam_sources.clone(),
                answer_digest: entry.answer_digest.clone(),
            })
            .collect();
        Some((digests, entry.calls.clone()))
    }

    /// Count one seam receipt dropped because its entry has a nested
    /// label (F5, as kept by H3).
    pub(crate) fn count_nested_seam_drop(&self) {
        if self.relay_detector().is_some() {
            count_replay_skipped("nested_seam");
        }
    }

    /// `digest`, a replayed receipt, kept to `answer` as delivered now
    /// (F4): unchanged only when `answer` is byte-identical to the stored
    /// answer its entry's receipts were committed against — its
    /// `canonical_json_sha256` equals `stored_digest` (the canonical
    /// JSON hash, not the detector's keyed one: the gate is a whole-answer
    /// equality test, and the keyed hash exists only as sampled k-grams
    /// of leaf forms, which cannot certify that nothing outside the kept
    /// segments changed) — and the answer still delivers all of it. Else
    /// filtered against it, dropping what cannot be filtered safely
    /// (counted). `None` when the answer is over the bound a receipt is
    /// kept against, counted `over_bound`: the receipt stages nothing,
    /// never text the replay did not deliver.
    pub(crate) fn keep_replayed_digest(
        &self,
        digest: DeliveryDigest,
        answer: &Value,
        stored_digest: Option<&str>,
        step: Option<u32>,
    ) -> Option<DeliveryDigest> {
        let detector = self.relay_detector()?;
        let (leaves, values) = delivery_parts(answer);
        let Some(delivered) = Delivered::of_parts(leaves, values) else {
            count_replay_skipped("over_bound");
            return None;
        };
        let delivered = delivered.with_answer(answer);
        let identical = stored_digest
            .is_some_and(|stored| stored == crate::hashing::canonical_json_sha256(answer));
        let (kept, dropped) = digest.kept_to_replay_answer(detector, &delivered, identical, step);
        if dropped {
            count_replay_skipped("filtered");
        }
        Some(kept)
    }
}
