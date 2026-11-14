// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Recording follows the generation current at delivery (ADR-029, amended,
//! items 3 and 4): a delivery committed while the effective action is `off`
//! records and snapshots nothing, and one committed while it is `block`
//! does, whatever the action was at startup or when the call was admitted.
//!
//! Every row holds the generation it hands the commit, as the funnel's
//! caller would have read it; the Meta-MCP carries a reload context over the
//! same live config so the production read has one to find.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use super::super::{AnswerShape, GatewayStamps, RELAY_RECEIPTS, RelayKey, plan_step};
use super::{OTHER_PROSE, PROSE, text_result};
use crate::config_reload::{LiveConfig, ReloadContext};
use crate::gateway::meta_mcp::MetaMcp;
use crate::security::firewall::collusion_live_rig::{Rig, classified, config};
use crate::security::firewall::{CollusionAction, Firewall, RelayCaller, StoredKey};

/// A Meta-MCP, its relay firewall and the live config both were built from.
pub(super) struct LiveMeta {
    pub(super) meta: Arc<MetaMcp>,
    pub(super) rig: Rig,
    /// What the `alpha` backend received (`tools/call` params).
    pub(super) seen: Arc<parking_lot::Mutex<Vec<serde_json::Value>>>,
    _dir: tempfile::TempDir,
}

impl LiveMeta {
    pub(super) fn firewall(&self) -> &Firewall {
        &self.rig.firewall
    }

    pub(super) fn live(&self) -> &Arc<LiveConfig> {
        &self.rig.live
    }

    pub(super) fn publish(&self, action: CollusionAction) {
        self.rig
            .reload(|c| c.security.firewall.collusion.action = action);
    }
}

/// A Meta-MCP over `alpha:read` as the one listed source, `window_secs` of
/// window, every k-gram kept, the clock frozen.
pub(super) fn live_meta(action: CollusionAction, window_secs: u64) -> LiveMeta {
    live_meta_listing(action, window_secs, &["alpha:read"])
}

/// [`live_meta`] with `sources` as the listed sources.
pub(super) fn live_meta_listing(
    action: CollusionAction,
    window_secs: u64,
    sources: &[&str],
) -> LiveMeta {
    let mut cfg = config(action, sources, vec![]);
    cfg.security.firewall.collusion.window_secs = window_secs;
    let rig = Rig::new(cfg);
    let (meta, dir, seen) = meta_over(&rig);
    LiveMeta {
        meta,
        rig,
        seen,
        _dir: dir,
    }
}

/// A Meta-MCP running `rig`'s firewall, with a reload context over `rig`'s
/// live config so the production read of "the generation now" finds it.
fn meta_over(
    rig: &Rig,
) -> (
    Arc<MetaMcp>,
    tempfile::TempDir,
    Arc<parking_lot::Mutex<Vec<serde_json::Value>>>,
) {
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let backend = Arc::new(crate::backend::Backend::new(
        "alpha",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    backend.set_transport_for_test(Arc::new(super::Seen(Arc::clone(&seen))));
    assert!(registry.register(backend));
    let mut meta = MetaMcp::new(Arc::clone(&registry));
    meta.set_firewall(Some(Arc::clone(&rig.firewall)));
    meta.share_keyring_with_for_test(&rig.firewall);
    let dir = tempfile::tempdir().expect("a private directory");
    let path = dir.path().join("gateway.yaml");
    let yaml = crate::yaml::to_string(&*rig.live.get()).expect("the config serialises");
    crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("written owner-only");
    let context = ReloadContext::new(
        path,
        Arc::clone(&rig.live),
        registry,
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    )
    .expect("the context builds");
    meta.set_reload_context(Arc::new(context));
    (Arc::new(meta), dir, seen)
}

pub(super) fn sync_key() -> StoredKey {
    StoredKey::Sync {
        identity: "identity".to_owned(),
        round: String::new(),
        operation: "operation".to_owned(),
    }
}

/// Alice's plan call, run inside a collector: one `alpha:read` step staged
/// under a Sync capture and finalised as delivered.
pub(super) async fn plan_body(meta: &MetaMcp, result: &serde_json::Value) {
    // The answer is the step's own output, so the receipt is kept whole.
    let answer = result.clone();
    super::super::replay::note_sync_capture(
        "identity".to_owned(),
        String::new(),
        "operation".to_owned(),
    );
    plan_step(None, async {
        meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "read"), result);
    })
    .await;
    let snapshot = meta.relay_snapshot(&answer);
    meta.restage_if_changed(snapshot, Some(&answer), AnswerShape::Literal);
    meta.rebuild_receipt_from_final(Some(&answer), GatewayStamps::Legacy, AnswerShape::Literal);
}

/// [`plan_body`] in a staged collector, returned uncommitted.
pub(super) async fn stage_plan(
    lm: &LiveMeta,
    result: &serde_json::Value,
) -> super::super::StagedReceipts {
    let ((), staged) = lm.meta.collecting_staged(plan_body(&lm.meta, result)).await;
    staged
}

/// Whether bob sending `PROSE` through `alpha:send` is refused under the
/// generation published now.
pub(super) fn bob_refused(lm: &LiveMeta) -> bool {
    let params = json!({"name": "send", "arguments": {"text": PROSE}});
    let generation = lm.live().generation();
    !lm.firewall()
        .check_relay(
            generation.collusion_view(),
            RelayCaller::Keyed("bob"),
            "alpha",
            "send",
            &params,
            ("s", "bob"),
        )
        .allowed
}

/// R4.1 (red first): a plan delivery committed while `off` was current is
/// not held, though it was admitted and staged under `block`. The control,
/// with no `off` published, is held and snapshotted. RED on base: recording
/// ignores the delivery-time generation, so the startup `block` holds it.
#[tokio::test]
async fn r4_1_a_commit_while_off_records_and_snapshots_nothing() {
    let control = live_meta(CollusionAction::Block, 1);
    let staged = stage_plan(&control, &text_result(PROSE)).await;
    staged.commit(true, &control.live().generation());
    assert!(
        control.firewall().replay_digests(&sync_key()).is_some(),
        "premise: a steady `block` snapshots the plan"
    );
    assert!(bob_refused(&control), "premise: a steady `block` records");

    let lm = live_meta(CollusionAction::Block, 1);
    let staged = stage_plan(&lm, &text_result(PROSE)).await;
    lm.publish(CollusionAction::Off);
    staged.commit(true, &lm.live().generation());
    lm.publish(CollusionAction::Block);
    assert!(
        lm.firewall().replay_digests(&sync_key()).is_none(),
        "R4.1: a snapshot was stored for a commit while `off` was current"
    );
    assert!(
        !bob_refused(&lm),
        "R4.1: the copy delivered while off is held"
    );
}

/// R4.2: with relay detection `off`, a delivery still stages its facts (a
/// reload to `on` between staging and delivery must not fail open) but
/// records nothing. RED on base: nothing is staged under a startup `off`.
#[tokio::test]
async fn r4_2_a_steady_off_stages_facts_and_records_nothing() {
    let lm = live_meta(CollusionAction::Off, 1);
    let meta = &lm.meta;
    let facts = meta
        .collecting_staged(async {
            meta.stage_relay_receipt(
                RelayKey::new("alice", true),
                ("alpha", "read"),
                &classified(PROSE),
            );
            RELAY_RECEIPTS
                .try_with(|r| {
                    r.borrow()
                        .iter()
                        .map(|r| r.digest.facts_for_test())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        })
        .await;
    let (facts, staged) = facts;
    assert_eq!(
        facts,
        [(Some(std::sync::Arc::<str>::from("alpha:read")), true)],
        "R4.2: the staged receipt does not carry the source and the inferred fact"
    );
    staged.commit(true, &lm.live().generation());
    let tracked = lm
        .firewall()
        .collusion_detector()
        .expect("the firewall builds a detector under `off`")
        .tracked_fingerprints();
    assert_eq!(tracked, 0, "R4.2: a steady `off` recorded");
}

/// P8.5b: a call admitted while `off` and committed after `block` was
/// published is held. The control, `block` published after the commit, is
/// not. RED on base: nothing is staged under a startup `off`.
#[tokio::test]
async fn p8_5b_off_to_block_between_admission_and_commit_is_held() {
    let after_commit = live_meta(CollusionAction::Off, 1);
    let staged = stage_plan(&after_commit, &text_result(PROSE)).await;
    staged.commit(true, &after_commit.live().generation());
    after_commit.publish(CollusionAction::Block);
    assert!(
        !bob_refused(&after_commit),
        "control: a commit while off holds nothing"
    );

    let lm = live_meta(CollusionAction::Off, 1);
    let staged = stage_plan(&lm, &text_result(PROSE)).await;
    lm.publish(CollusionAction::Block);
    staged.commit(true, &lm.live().generation());
    assert!(
        bob_refused(&lm),
        "P8.5b: the commit under block holds nothing"
    );
}

/// P8.12: a plan committed while `off` is current and every later action is
/// `block` stores no replay entry and holds nothing. GREEN pin on base, for
/// the wrong reason (a startup `off` builds no detector); the item-4 mutant
/// that gates recording on the detector alone turns it red on the fix.
#[tokio::test]
async fn p8_12_a_startup_off_commit_then_block_holds_nothing() {
    let lm = live_meta(CollusionAction::Off, 1);
    let staged = stage_plan(&lm, &text_result(PROSE)).await;
    staged.commit(true, &lm.live().generation());
    lm.publish(CollusionAction::Block);
    assert!(
        lm.firewall().replay_digests(&sync_key()).is_none(),
        "P8.12: a replay entry was stored for a commit while off"
    );
    assert!(!bob_refused(&lm), "P8.12: held");
}

/// Alice's single-target call delivering `staged`, then redacted to
/// `delivered` before the commit, committed under the generation current.
async fn redacted_commit(lm: &LiveMeta, staged: &serde_json::Value, delivered: &serde_json::Value) {
    let meta = &lm.meta;
    let ((), receipts) = meta
        .collecting_staged(async {
            meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "read"), staged);
            let snapshot = meta.relay_snapshot(staged);
            meta.restage_if_changed(snapshot, Some(delivered), AnswerShape::Literal);
        })
        .await;
    receipts.commit(true, &lm.live().generation());
}

/// A classified result whose marker the redaction removed.
fn classified_pair() -> (serde_json::Value, serde_json::Value) {
    let mut classified = text_result(&format!("{PROSE} {OTHER_PROSE}"));
    classified["_context_integrity"] =
        json!({"classification": {"data_classes": ["personal_data"]}});
    (classified, text_result(PROSE))
}

/// P8.14a: an inferred fact with no source named anywhere is held. GREEN pin
/// on base.
#[tokio::test]
async fn p8_14a_an_inferred_fact_with_no_listed_source_is_held() {
    let lm = live_meta_listing(CollusionAction::Block, 600, &[]);
    let (classified, _) = classified_pair();
    let meta = &lm.meta;
    let ((), receipts) = meta
        .collecting_staged(async {
            meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "read"), &classified);
        })
        .await;
    receipts.commit(true, &lm.live().generation());
    assert!(bob_refused(&lm), "P8.14a: an inferred copy is not held");
}

/// P8.14b: the inferred fact survives a redaction that removes the marker,
/// and any source edit after it. GREEN pin on base.
#[tokio::test]
async fn p8_14b_an_inferred_fact_survives_redaction_and_source_edits() {
    let lm = live_meta_listing(CollusionAction::Block, 600, &[]);
    let (classified, delivered) = classified_pair();
    redacted_commit(&lm, &classified, &delivered).await;
    assert!(bob_refused(&lm), "refused after the redaction");
    lm.rig
        .reload(|c| c.security.firewall.collusion.sources = vec!["alpha:read".to_string()]);
    assert!(bob_refused(&lm), "refused after the source was added");
    lm.rig
        .reload(|c| c.security.firewall.collusion.sources = vec![]);
    assert!(
        bob_refused(&lm),
        "P8.14b: refused after the source was removed"
    );
}

/// P8.14c: a list match does not cross a redaction. The copy is held because
/// its source was listed at delivery; once the list is emptied, the redacted
/// copy is plain. RED on base: the rebuild ORs the combined bit and the
/// startup lists apply.
#[tokio::test]
async fn p8_14c_a_list_match_does_not_cross_a_redaction() {
    let lm = live_meta_listing(CollusionAction::Block, 600, &["alpha:read"]);
    let staged = text_result(&format!("{PROSE} {OTHER_PROSE}"));
    redacted_commit(&lm, &staged, &text_result(PROSE)).await;
    assert!(bob_refused(&lm), "control: held while the source is listed");
    lm.rig
        .reload(|c| c.security.firewall.collusion.sources = vec![]);
    assert!(
        !bob_refused(&lm),
        "P8.14c: the list match survived the redaction"
    );
}

/// P8.9b: a plan staged and redacted while `off`, committed after `block` is
/// published, snapshots for replay; replayed to alice later, the copy keeps
/// its inferred fact across the redaction, so bob relaying the redacted
/// text is refused. RED on base: nothing is staged under a startup `off`.
#[tokio::test]
async fn p8_9b_a_replay_staged_and_redacted_while_off_is_held_after_activation() {
    let lm = live_meta_listing(CollusionAction::Off, 1, &[]);
    let (classified, delivered) = classified_pair();
    let meta = &lm.meta;
    let ((), staged) = meta
        .collecting_staged(async {
            super::super::replay::note_sync_capture(
                "identity".to_owned(),
                String::new(),
                "operation".to_owned(),
            );
            plan_step(None, async {
                meta.stage_relay_receipt(
                    RelayKey::new("alice", true),
                    ("alpha", "read"),
                    &classified,
                );
            })
            .await;
            let snapshot = meta.relay_snapshot(&classified);
            meta.restage_if_changed(snapshot, Some(&delivered), AnswerShape::Literal);
            meta.rebuild_receipt_from_final(
                Some(&delivered),
                GatewayStamps::Legacy,
                AnswerShape::Literal,
            );
        })
        .await;
    lm.publish(CollusionAction::Block);
    staged.commit(true, &lm.live().generation());
    lm.rig.lapse(Duration::from_secs(2));
    let entry = lm.firewall().replay_digests(&sync_key());
    assert!(entry.is_some(), "P8.9b: no snapshot was stored");
    let digests = entry.map_or_default(|(digests, _)| digests);
    assert!(!digests.is_empty(), "P8.9b: the snapshot holds no digests");
    // The original delivery has lapsed: only the replay can hold it again.
    assert!(
        !bob_refused(&lm),
        "P8.9b: the lapsed delivery still refuses"
    );
    let g1 = lm.live().generation();
    for replayed in digests {
        let alice = RelayCaller::Keyed("alice");
        lm.firewall().record_digest(
            alice,
            &replayed.server,
            &replayed.tool,
            &replayed.digest,
            &g1,
        );
    }
    assert!(bob_refused(&lm), "P8.9b: the replayed copy is not held");
}
