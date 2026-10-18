// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a firewall records of a delivery for relay detection: the delivery
//! and receipt digests, their leaf hashes and caps, and the record written
//! for them.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde_json::Value;

use super::super::collusion_digest::key_path_run_indices;
use super::{
    CAPACITY_METRIC, DELIVERED_SET_CAP, DeliveryDigest, Firewall, PLAN_STAGED_CAP, PlanStaging,
    RelayCaller, context_integrity_sensitive, delivery_parts, key_path_joins, key_path_runs,
};

impl Firewall {
    /// Record `result` as delivered to `caller` from `server:tool`. Call it
    /// only with what the caller actually receives. Production records go
    /// through a staged or committed [`DeliveryDigest`]; this one-step form
    /// is the tests' shorthand.
    #[cfg(test)]
    pub(crate) fn record_delivery(
        &self,
        caller: RelayCaller<'_>,
        server: &str,
        tool: &str,
        result: &Value,
    ) {
        if let Some(digest) = self.delivery_digest(server, tool, result) {
            self.record_digest(caller, server, tool, &digest);
        }
    }

    /// What recording `result` from `server:tool` needs, taken now: its
    /// capped text and sensitivity. `None` when relay detection is off.
    pub(crate) fn delivery_digest(
        &self,
        server: &str,
        tool: &str,
        result: &Value,
    ) -> Option<DeliveryDigest> {
        let (digest, cut) = self.digest_with(server, tool, result, DeliveryDigest::of_parts)?;
        // `MIK-8209`: the key-path joins, on a budget of their own; one walk
        // of `result` serves them and the seam pass.
        let runs = key_path_runs(result);
        let joins: Vec<String> = runs.iter().map(|run| run.concat()).collect();
        let (mut digest, joins_cut) = digest.with_joins(joins.clone());
        // `MIK-8205`: the caller's own subset-forward seams, excuse only.
        if let Some(detector) = self.relay_detector() {
            let (seams, seams_cut) = detector.seam_excuse_fingerprints(&runs);
            if seams_cut {
                telemetry_metrics::counter!(CAPACITY_METRIC, "bound" => "seam_excuse_cut")
                    .increment(1);
            }
            if !seams.is_empty() {
                digest.seam_excuses = Some(seams.into());
            }
        }
        self.count_cut(joins_cut && !cut);
        if cut || joins_cut {
            // `MIK-8066.EXCUSE.1`: the whole delivered value, as received.
            let (leaves, values) = delivery_parts(result);
            digest.cut_fps = self.fps_of_leaves(&leaves, values, &joins);
        }
        Some(digest)
    }

    /// [`Self::delivery_digest`], or for a plan step (`plan`: what its
    /// delivery has staged so far, as [`DeliveryDigest::staged_len`] counts)
    /// staged whole, capped once it is kept to what the plan delivers or when
    /// recorded (MIK-7992). From [`DELIVERED_SET_CAP`] staged on, a step is
    /// capped now; from [`PLAN_STAGED_CAP`] on, its receipt is dropped and
    /// counted, so a plan of many steps stages a bounded total.
    pub(crate) fn receipt_digest(
        &self,
        server: &str,
        tool: &str,
        result: &Value,
        plan: Option<&PlanStaging>,
    ) -> Option<DeliveryDigest> {
        let Some(staged) = plan else {
            return self.delivery_digest(server, tool, result);
        };
        let total = staged.baseline();
        if total >= PLAN_STAGED_CAP {
            self.relay_detector()?;
            self.count_plan_drop_once(staged);
            return None;
        }
        let digest = if total < DELIVERED_SET_CAP {
            let digest = self
                .digest_with(server, tool, result, DeliveryDigest::of_plan_step_parts)?
                .0;
            // `MIK-8209` K2a: the key-path runs, staged as leaf indices.
            let (leaves, values) = delivery_parts(result);
            digest.with_join_runs(key_path_run_indices(result, &leaves, values))
        } else {
            // A plan step is sketched only once kept to the plan's answer
            // (`MIK-8066` E1''): capped here, its cut text gets no sketch.
            let (digest, cut) = self.digest_with(server, tool, result, DeliveryDigest::of_parts)?;
            let (digest, joins_cut) = digest.with_joins(key_path_joins(result));
            // One cut per delivery: a join cut comes with a leaf cut.
            self.count_cut(joins_cut && !cut);
            digest
        };
        staged.add_baseline(digest.staged_len());
        let digest = self.attach_big(digest, (server, tool), result, staged);
        Some(self.with_leaf_hashes(digest, (server, tool), result, staged))
    }

    /// `MIK-8066` D4: `leaf`'s keyed hash, for seam ownership; `None` with
    /// relay detection off.
    pub(crate) fn leaf_hash(&self, leaf: &str) -> Option<u64> {
        Some(self.relay_detector()?.leaf_hash(leaf))
    }

    /// `MIK-8066` D4 + A3: a plan step's value leaves as sorted keyed hashes,
    /// 8 B each, charged to the plan's total only (an attachment, F3), so the
    /// capping switch stays 2a's. Only a step staged whole or a staged
    /// `BigStep` keeps them, and only while the total has room: a step
    /// skipped for room keeps none and is marked lost, because no hashes
    /// means no subset seam, which fails safe.
    fn with_leaf_hashes(
        &self,
        mut digest: DeliveryDigest,
        (server, tool): (&str, &str),
        result: &Value,
        staged: &PlanStaging,
    ) -> DeliveryDigest {
        let Some(detector) = self.relay_detector() else {
            return digest;
        };
        if !digest.is_deferred() && !digest.is_staged_step() {
            return digest;
        }
        let (leaves, values) = delivery_parts(result);
        let mut hashes: Vec<u64> = leaves[..values.min(leaves.len())]
            .iter()
            .map(|leaf| detector.leaf_hash(leaf))
            .collect();
        hashes.sort_unstable();
        hashes.dedup();
        let bytes = hashes.len() * 8;
        if staged.total().saturating_add(bytes) > PLAN_STAGED_CAP {
            if let Some(caller) = staged.caller() {
                detector.mark_step_lost(&format!("{server}:{tool}"), &caller);
            }
            telemetry_metrics::counter!(CAPACITY_METRIC, "bound" => "plan_leaf_hashes_skipped")
                .increment(1);
            return digest;
        }
        staged.add_attachment(bytes);
        digest.leaf_hashes = Some(hashes.into());
        digest
    }

    fn digest_with(
        &self,
        server: &str,
        tool: &str,
        result: &Value,
        of_parts: fn(&[&str], usize, bool) -> (DeliveryDigest, bool),
    ) -> Option<(DeliveryDigest, bool)> {
        self.relay_detector()?;
        let source = format!("{server}:{tool}");
        let sensitive = self.relay.sources.iter().any(|p| p.matches(&source))
            || context_integrity_sensitive(result);
        let (leaves, values) = delivery_parts(result);
        let (digest, cut) = of_parts(&leaves, values, sensitive);
        self.count_cut(cut);
        Some((digest, cut))
    }

    /// A copy of `digest` with its deferred cap applied, a cut counted;
    /// `None` when it was capped at staging.
    pub(super) fn capped(&self, digest: &DeliveryDigest) -> Option<DeliveryDigest> {
        let (mut capped, cut) = digest.capped()?;
        self.count_cut(cut);
        if cut {
            capped.cut_fps = self.fps_of(digest);
        }
        Some(capped)
    }

    /// `MIK-8066.EXCUSE.1`: every fingerprint of a delivered value's leaves,
    /// values joined as a delivery walk reads them (both forms) and each key,
    /// all of it text the caller received; sketched when recorded
    /// (`MIK-8200`).
    pub(super) fn fps_of_leaves(
        &self,
        leaves: &[&str],
        values: usize,
        joins: &[String],
    ) -> Option<Arc<[u64]>> {
        let detector = self.relay_detector()?;
        let (vals, keys) = leaves.split_at(values.min(leaves.len()));
        let mut fps = detector.fingerprints(&vals.join("\n"));
        if vals.len() > 1 {
            fps.extend(detector.fingerprints(&vals.concat()));
        }
        for key in keys {
            fps.extend(detector.fingerprints(key));
        }
        // Each key-path join alone, never run into a neighbour (`MIK-8209`).
        for join in joins {
            fps.extend(detector.fingerprints(join));
        }
        Some(fps.into())
    }

    /// `MIK-8066.EXCUSE.1`: every fingerprint of `whole`, the receipt kept
    /// to the plan's answer before its cut: what the holder received.
    fn fps_of(&self, whole: &DeliveryDigest) -> Option<Arc<[u64]>> {
        let detector = self.relay_detector()?;
        Some(whole.fingerprints(detector).into())
    }

    fn count_cut(&self, cut: bool) {
        if cut {
            self.relay.text_cut.fetch_add(1, Ordering::Relaxed);
            telemetry_metrics::counter!(CAPACITY_METRIC, "bound" => "record_text_cut").increment(1);
        }
    }

    /// Record `digest` as delivered to `caller` from `server:tool`.
    pub(crate) fn record_digest(
        &self,
        caller: RelayCaller<'_>,
        server: &str,
        tool: &str,
        digest: &DeliveryDigest,
    ) {
        let Some(detector) = self.relay_detector() else {
            return;
        };
        // A2: by reference, a digest could be recorded twice; the first
        // record sets the flag, a second adds no evidence and no charge.
        let twice = digest.recorded.swap(true, Ordering::Relaxed);
        if twice {
            detector
                .views
                .double_records
                .fetch_add(1, Ordering::Relaxed);
        }
        debug_assert!(!twice, "a delivery digest was recorded twice");
        if twice {
            return;
        }
        let source = format!("{server}:{tool}");
        // MIK-8113: a seam of several sources leaves only by a flow every
        // contributing source allows.
        if let Some(sources) = digest.seam_sources.as_deref() {
            let masks = sources.iter().map(|s| self.relay.source_flows(s)).collect();
            detector.record_seam_at(
                &source,
                caller.key(),
                (digest.sensitive, masks),
                digest.fingerprints(detector),
                self.relay.now(),
            );
            return;
        }
        let flows = self.relay.source_flows(&source);
        self.record_kept(detector, &source, caller, flows, digest);
    }
}
