// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The recording funnels judge a delivery under the generation their
//! caller captured at delivery (ADR-029, amended, item 4), not the startup
//! action, the admission-time generation, or one read again after the
//! capture. The capture hook reloads between the caller's capture and the
//! funnel, so a funnel that re-reads sees a different generation.

use std::sync::Arc;
use std::time::Instant;

use serde_json::json;

use super::live::{LiveMeta, live_meta, plan_body, stage_plan, sync_key};
use super::text_result;
use crate::config_reload::LiveConfig;
use crate::security::firewall::CollusionAction::{Block, Off};
use crate::security::firewall::collusion_live_rig::one_fp;

use super::super::{collecting_http, commit_capture_hook};

/// Publish `action` over `live`'s current config.
fn publish(live: &LiveConfig, action: crate::security::firewall::CollusionAction) {
    let mut config = (*live.get()).clone();
    config.security.firewall.collusion.action = action;
    live.set(config);
}

/// Alice's HTTP plan call over `lm`: collected, delivered, then handed to
/// `emit_http_checked` with `block` published in between (the delivery-time
/// generation) and the capture hook armed with `hook`, and its body read.
/// Whether the hook ran.
async fn http_plan(lm: &LiveMeta, text: &str, hook: impl FnOnce() + 'static) -> bool {
    let (meta, result) = (Arc::clone(&lm.meta), text_result(text));
    let response = collecting_http(Arc::clone(&meta), async move {
        plan_body(&meta, &result).await;
        meta.settle_relay_receipts(&crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
            json!({}),
        ));
        axum::Json(json!({"ok": true}))
    })
    .await;
    publish(lm.live(), Block);
    let before = commit_capture_hook::reached();
    commit_capture_hook::arm(hook);
    let (response, _) = crate::gateway::outbound::emit_http_checked(response, None).await;
    // The server takes the body: that is the write the receipts commit at.
    let _ = axum::body::to_bytes(response.into_body(), usize::MAX).await;
    commit_capture_hook::reached() > before
}

/// R4.3a a1: admitted under a startup `off`, delivered under `block`, with
/// `off` published after the capture. The funnel records under the captured
/// `block`: the snapshot is stored and bob is refused. RED on base: a
/// startup `off` builds no detector, so nothing is staged or recorded.
#[tokio::test]
async fn r4_3a_a1_the_http_funnel_records_under_the_captured_generation() {
    let lm = live_meta(Off, 1);
    let live = Arc::clone(lm.live());
    let ran = http_plan(&lm, &one_fp(0), move || publish(&live, Off)).await;
    lm.publish(Block);
    assert!(
        lm.firewall().replay_digests(&sync_key()).is_some(),
        "R4.3a a1: no snapshot under the captured `block`"
    );
    assert!(
        bob_refused_with(&lm, &one_fp(0)),
        "R4.3a a1: nothing was recorded"
    );
    assert!(ran, "R4.3a a1: the capture hook never ran");
}

/// R4.3a a2: as a1, but the hook publishes a source list that no longer
/// covers `alpha:read` and fills alice's cap for the text under it. The
/// captured `block` view lists `alpha:read`, so the step receipt overflows as
/// `(alpha:read, false)`; a re-read would judge it plain and drop it. RED on
/// base: nothing is recorded under a startup `off`.
#[tokio::test]
async fn r4_3a_a2_the_funnel_does_not_re_read_after_the_capture() {
    let lm = live_meta(Off, 1);
    let text = one_fp(0);
    let (live, firewall) = (Arc::clone(lm.live()), Arc::clone(&lm.rig.firewall));
    let hook_text = text.clone();
    let ran = http_plan(&lm, &text, move || {
        let mut config = (*live.get()).clone();
        config.security.firewall.collusion.sources = vec!["fill:*".to_string()];
        live.set(config);
        let generation = live.generation();
        let Some(detector) = firewall.collusion_detector() else {
            return;
        };
        for i in 0..64 {
            detector.record_delivery_under(
                generation.collusion_view(),
                (&format!("fill:{i}"), false),
                "alice",
                &hook_text,
                Instant::now(),
            );
        }
    })
    .await;
    let pairs: Vec<(String, bool)> = lm
        .firewall()
        .collusion_detector()
        .map_or_default(|detector| detector.overflow_pairs_of(&text, "alice"))
        .into_iter()
        .map(|(source, inferred)| (source.to_string(), inferred))
        .collect();
    assert_eq!(
        pairs,
        [("alpha:read".to_string(), false)],
        "R4.3a a2: the receipt was not held as an overflow pair"
    );
    assert!(ran, "R4.3a a2: the capture hook never ran");
}

/// R4.4a: effective `block`, requested `off` (held beside a window edit):
/// recording and the snapshot follow the effective action. GREEN pin on
/// base; the raw-action mutant turns it red.
#[tokio::test]
async fn r4_4a_an_effective_block_records_though_off_is_requested() {
    let lm = live_meta(Block, 600);
    lm.rig.reload(|c| {
        c.security.firewall.collusion.action = Off;
        c.security.firewall.collusion.window_secs = 601;
    });
    let g1 = lm.live().generation();
    assert_eq!(
        g1.collusion_view().action(),
        Block,
        "control: held at block"
    );
    let staged = stage_plan(&lm, &text_result(&one_fp(0))).await;
    staged.commit(true, &g1);
    assert!(
        lm.firewall().replay_digests(&sync_key()).is_some(),
        "R4.4a: no snapshot under the effective block"
    );
    assert!(bob_refused_with(&lm, &one_fp(0)), "R4.4a: not recorded");
}

/// R4.4b: effective `off`, requested `block` (held beside a window edit).
/// Startup `block`; `off` published (effective off); then `block` with a
/// changed window, which is held, so the effective action stays `off`. A
/// delivery committed then records and snapshots nothing; once the edit
/// applies, bob relaying the text is allowed. The control, a delivery under
/// the applied `block`, is held on any base. RED on base at the snapshot: the
/// startup `block` records the delivery whatever the generation says.
#[tokio::test]
async fn r4_4b_an_effective_off_records_nothing_though_block_is_requested() {
    let text = one_fp(0);
    let control = live_meta(Block, 600);
    let staged = stage_plan(&control, &text_result(&text)).await;
    staged.commit(true, &control.live().generation());
    assert!(
        bob_refused_with(&control, &text),
        "control: a delivery under an applied `block` is held"
    );

    let lm = live_meta(Block, 600);
    lm.publish(Off);
    lm.rig.reload(|c| {
        c.security.firewall.collusion.action = Block;
        c.security.firewall.collusion.window_secs = 601;
    });
    let g1 = lm.live().generation();
    assert_eq!(g1.collusion_view().action(), Off, "premise: held at off");
    let staged = stage_plan(&lm, &text_result(&text)).await;
    staged.commit(true, &g1);
    lm.rig.reload(|c| {
        c.security.firewall.collusion.action = Block;
        c.security.firewall.collusion.window_secs = 600;
    });
    assert!(
        lm.firewall().replay_digests(&sync_key()).is_none(),
        "R4.4b: a snapshot was stored under the effective off"
    );
    assert!(
        !bob_refused_with(&lm, &text),
        "R4.4b: recorded under the effective off"
    );
}

/// Whether bob sending `text` through `alpha:send` is refused under the
/// generation published now.
fn bob_refused_with(lm: &LiveMeta, text: &str) -> bool {
    let params = json!({"name": "send", "arguments": {"text": text}});
    let generation = lm.live().generation();
    !lm.firewall()
        .check_relay(
            generation.collusion_view(),
            crate::security::firewall::RelayCaller::Keyed("bob"),
            "alpha",
            "send",
            &params,
            ("s", "bob"),
        )
        .allowed
}

/// R4.3c: the bridge's `DeliveryCommit` closure records under the
/// generation current when delivery is confirmed, not the one it was built
/// under. c1: a list that no longer covers the source; c2: `off` at
/// confirmation, then an active witness that lists it. Control: unchanged.
/// RED on base at c1 and c2 (the closure records the build-time combined bit).
#[tokio::test]
async fn r4_3c_the_bridge_closure_records_under_the_confirmation_generation() {
    let text = one_fp(0);
    let confirm = |edit: fn(&mut crate::config::Config)| {
        let lm = live_meta(Block, 600);
        let commit = lm
            .meta
            .delivery_commit(
                RelayKey::new("alice", true),
                ("alpha", "read"),
                &text_result(&text),
            )
            .expect("a block firewall builds a commit");
        lm.rig.reload(edit);
        commit.commit();
        lm
    };
    let control = confirm(|_| {});
    assert!(bob_refused_with(&control, &text), "control: recorded");

    let c1 = confirm(|c| c.security.firewall.collusion.sources = vec!["beta:read".to_string()]);
    assert!(
        !bob_refused_with(&c1, &text),
        "R4.3c c1: the build-time bit was recorded"
    );

    let c2 = confirm(|c| c.security.firewall.collusion.action = Off);
    c2.rig.reload(|c| {
        c.security.firewall.collusion.action = Block;
        c.security.firewall.collusion.sources = vec!["alpha:read".to_string()];
    });
    assert!(
        !bob_refused_with(&c2, &text),
        "R4.3c c2: recorded while off"
    );
}

use super::super::RelayKey;
