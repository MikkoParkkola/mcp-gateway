// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8408` stage 2: the firewall surface of the replay receipt store.
//! The gateway commits a stored plan delivery's in-plan receipts here and
//! reads fresh digests back at replay; the store and its snapshots stay
//! inside the firewall (E1, F1, F2). Its key type is shared with relay
//! replay (MIK-8662).

use std::time::Duration;

use serde_json::Value;

use super::super::collusion::replay::{ReplayHandle, StoredKey, count_replay_skipped};
use super::{Delivered, DeliveryDigest, Firewall, delivery_parts};
use crate::security::ReplayCalls;

/// One committed receipt to snapshot: its digest, its plan step label
/// (`None` for a seam) and the source it was recorded under.
pub(crate) type ReplaySource<'a> = (&'a DeliveryDigest, Option<u32>, &'a str, &'a str);

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
    /// of one entry: [`Firewall::keep_replayed_digests`] compares the
    /// replayed answer against it.
    pub(crate) answer_digest: String,
}

impl Firewall {
    /// Store the committed in-plan `receipts` of a stored delivery under
    /// `key`: a retained sync plan answer under its admission key (F1:
    /// identity, round, operation), or a task's settled result under
    /// `(task id, revision)`. The entry keeps its `calls` and the digest of
    /// the delivered answer they were committed against (F4), live for
    /// `retention` (the retained result's or the task's own).
    ///
    /// Each receipt is snapshotted (F2), counting a `big_step` drop for
    /// each judged big-step receipt that yields no snapshot (F3) and a
    /// `staged` drop for a step still staged at capture. When every
    /// candidate yielded no snapshot there is nothing to replay: no entry
    /// is inserted and any previous entry under the key goes, as an
    /// overwrite would take it. With relay detection off nothing is stored
    /// and nothing is removed, so a commit with no candidates at all goes
    /// through [`Self::remove_replay`] instead.
    ///
    /// The capture is made before anything is delivered, whatever the
    /// action: the entry is pending and the returned handle is settled at
    /// the delivery's write ([`Self::settle_replay`]), which keeps it or,
    /// under `off`, lets it go (ADR-029, pending-snapshot rule).
    pub(crate) fn store_replay(
        &self,
        key: StoredKey,
        receipts: &[ReplaySource<'_>],
        calls: ReplayCalls,
        answer_digest: &str,
        retention: Duration,
    ) -> Option<ReplayHandle> {
        self.relay_detector()?;
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
            return None;
        }
        let (digest, now) = (answer_digest.to_owned(), self.relay.now());
        self.relay
            .replay
            .insert_pending(key, snapshots, calls, digest, now, retention)
    }

    /// How many replay entries the store holds (tests only).
    #[cfg(test)]
    pub(crate) fn replay_entries_for_test(&self) -> usize {
        self.relay.replay.len_for_test()
    }

    /// `handle`'s delivery was written under `generation`: a write not
    /// under an effective `off` keeps its entry; one under `off` ends that
    /// delivery, and the entry goes once no delivery of it is outstanding.
    pub(crate) fn settle_replay(
        &self,
        handle: ReplayHandle,
        generation: &crate::config_reload::Generation,
    ) {
        let off = generation.collusion_view().action() == super::CollusionAction::Off;
        self.relay.replay.settle(handle, off);
    }

    /// Drop the entry under `key`: a non-plan commit under a retained sync
    /// delivery's key (F1), or a settled task's commit with nothing to
    /// replay. Runs with relay detection off too.
    pub(crate) fn remove_replay(&self, key: &StoredKey) {
        self.relay.replay.remove(key);
    }

    /// Fresh digests for the snapshots stored under `key`, with its calls;
    /// `None` stages nothing, counted `absent` or `expired` (E2). Rows read
    /// it; a delivery acquires (`replay_digests_for_delivery`, `adopt_replay`).
    #[cfg(test)]
    pub(crate) fn replay_digests(
        &self,
        key: &StoredKey,
    ) -> Option<(Vec<ReplayedDigest>, ReplayCalls)> {
        let entry = self.relay.replay.lookup(key, self.relay.now())?;
        let digests = replayed(&entry);
        Some((digests, entry.calls.clone()))
    }

    /// [`Self::replay_digests`] for a replay that will deliver the entry:
    /// a pending entry is held for that delivery, whose handle is settled
    /// at its write (or released if it is never written).
    pub(crate) fn replay_digests_for_delivery(
        &self,
        key: &StoredKey,
    ) -> Option<(Vec<ReplayedDigest>, ReplayCalls, Option<ReplayHandle>)> {
        let (entry, handle) = self
            .relay
            .replay
            .acquire(key, self.relay.now())?
            .into_parts();
        let digests = replayed(&entry);
        Some((digests, entry.calls.clone(), handle))
    }

    /// Count one seam receipt dropped because its entry has a nested
    /// label (F5, as kept by H3).
    pub(crate) fn count_nested_seam_drop(&self) {
        if self.relay_detector().is_some() {
            count_replay_skipped("nested_seam");
        }
    }

    /// One delivery's replayed receipts, digest and plan step each,
    /// kept to `answer` as delivered now (F4): a digest is unchanged
    /// only when `answer` is byte-identical to the stored answer its
    /// entry's receipts were committed against — its
    /// `canonical_json_sha256` equals `stored_digest` (the canonical
    /// JSON hash, not the detector's keyed one: the gate is a whole-answer
    /// equality test, and the keyed hash exists only as sampled k-grams
    /// of leaf forms, which cannot certify that nothing outside the kept
    /// segments changed) — and the answer still delivers all of it. Else
    /// filtered against it, dropping what cannot be filtered safely
    /// (counted `filtered`, once per receipt that dropped a set).
    ///
    /// The answer is read, hashed and fingerprinted once for the whole
    /// delivery: every digest is kept against the same `Delivered`, so
    /// its k-gram set is built once, however many receipts replay. The
    /// results are in `items` order, `None` where the receipt stages
    /// nothing — relay detection off, or the answer over the bound a
    /// receipt is kept against, counted `over_bound` once per dropped
    /// receipt: never text the replay did not deliver. No items, no
    /// work: the answer is not read at all.
    pub(crate) fn keep_replayed_digests(
        &self,
        items: Vec<(DeliveryDigest, Option<u32>)>,
        answer: &Value,
        stored_digest: Option<&str>,
    ) -> Vec<Option<DeliveryDigest>> {
        if items.is_empty() {
            return Vec::new();
        }
        let Some(detector) = self.relay_detector() else {
            return items.into_iter().map(|_| None).collect();
        };
        let (leaves, values) = delivery_parts(answer);
        let Some(delivered) = Delivered::of_parts(leaves, values) else {
            // Once per dropped receipt, as the per-receipt form counted.
            for _ in &items {
                count_replay_skipped("over_bound");
            }
            return items.into_iter().map(|_| None).collect();
        };
        let delivered = delivered.with_answer(answer);
        let identical = stored_digest
            .is_some_and(|stored| stored == crate::hashing::canonical_json_sha256(answer));
        items
            .into_iter()
            .map(|(digest, step)| {
                let (kept, dropped) =
                    digest.kept_to_replay_answer(detector, &delivered, identical, step);
                if dropped {
                    count_replay_skipped("filtered");
                }
                Some(kept)
            })
            .collect()
    }
}

/// Fresh digests for every snapshot of `entry` (F2).
pub(super) fn replayed(
    entry: &super::super::collusion::replay::ReplayEntry,
) -> Vec<ReplayedDigest> {
    entry
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
        .collect()
}
