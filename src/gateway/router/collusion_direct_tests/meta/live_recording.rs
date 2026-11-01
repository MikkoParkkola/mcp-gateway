// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R4.3b′ (live collusion, item 4): a keyed `gateway_execute` chain over
//! HTTP stores its replay snapshot under the generation current at
//! delivery, not the startup action. The in-plan receipts are captured
//! under the Sync admission key (admission.rs `note_sync_capture_key`),
//! committed by `emit_http` through `capture_commit`.
//!
//! The premise is a control on the same fixture and path, not a probe of
//! the same delivery: the staged receipts and the capture slot are
//! private to `invoke::relay`. Under steady `block` the control's entry
//! exists, which proves the chain stages in-plan receipts (`capture_commit`
//! keeps only in-plan or seam receipts) and sets the Sync key the row
//! computes; its step labels show the receipts are plan steps.

use crate::config_reload::LiveConfig;
use crate::security::firewall::StoredKey;
use sha2::Digest as _;

use super::*;

/// The fixture with its live config seeded from the firewall's own
/// collusion parameters (`Setup::default()`, with `action`), so a reload
/// that edits only the action applies rather than being held.
async fn live_fixture(action: CollusionAction) -> Fixture {
    let mut fx = meta_fixture(
        Setup {
            action,
            ..Setup::default()
        },
        None,
    )
    .await;
    let st = Arc::get_mut(&mut fx.state).expect("state is unique");
    let mut cfg = (*st.live_config.get()).clone();
    let defaults = Setup::default();
    cfg.security.firewall.collusion = CollusionConfig {
        action,
        window_secs: defaults.window_secs,
        sources: defaults.sources,
        ..CollusionConfig::default()
    };
    st.live_config = Arc::new(LiveConfig::new(cfg));
    // The clock is frozen at construction: nothing ages out on a slow run.
    firewall(&fx).advance_collusion_clock_for_test(Duration::ZERO);
    fx
}

fn firewall(fx: &Fixture) -> &Firewall {
    fx.state
        .firewall
        .as_deref()
        .expect("the fixture installs a firewall")
}

/// Publish the current live config with only the collusion action edited.
fn reload(fx: &Fixture, action: CollusionAction) {
    let mut cfg = (*fx.state.live_config.get()).clone();
    cfg.security.firewall.collusion.action = action;
    fx.state.live_config.set(cfg);
    assert_eq!(
        fx.state
            .live_config
            .get()
            .security
            .firewall
            .collusion
            .action,
        action,
        "premise: the reload published"
    );
}

/// Alice's keyed two-step chain of `alpha:read`, and the Sync key its
/// answer is stored under: admission's identity for alice's principal and
/// `key`, round "" (a fresh call), the operation admission keyed.
async fn keyed_chain(fx: &Fixture, key: &str) -> StoredKey {
    let _ = crate::gateway::meta_mcp::admission::take_last_operation();
    let chain = json!({"chain": [
        {"tool": "alpha:read", "arguments": {"n": 1}},
        {"tool": "alpha:read", "arguments": {"n": 2}},
    ]});
    let (status, body) = post(fx, Some("a"), "gateway_execute", &chain, &keyed(key)).await;
    assert!(
        status == 200 && envelope(&body).get("error").is_none(),
        "premise: the chain delivered: {status} {body}"
    );
    let operation = crate::gateway::meta_mcp::admission::take_last_operation()
        .expect("premise: the keyed chain was admitted");
    let digest: [u8; 32] = sha2::Sha256::digest(b"a").into();
    let principal = super::super::key(b"a", "alice").principal_for(&digest);
    // Admission keys under `execution_principal(owner)`: the routed owner
    // first, which for an API-key client is `credential:<principal>`
    // (`session_owner_key`, pinned by `route_owners_with_auth_on`).
    let owner = format!(
        "{}{}",
        crate::gateway::auth::CREDENTIAL_OWNER_PREFIX,
        principal.storage_form()
    );
    let (identity, operation) =
        crate::gateway::meta_mcp::invoke::relay::sync_replay_key(&owner, key, &operation);
    StoredKey::Sync {
        identity,
        round: String::new(),
        operation,
    }
}

/// Case B (the red-first proof): startup `block`, `off` published before
/// the in-plan delivery. The control (steady block) stores an entry with
/// plan-step labels; after the reload the delivery stores none.
/// RED on base: recording ignores the delivery-time generation, so the
/// startup block stores the entry.
#[tokio::test]
async fn r43b_prime_b_off_published_before_delivery_stores_no_replay_entry() {
    let fx = live_fixture(CollusionAction::Block).await;
    let control = keyed_chain(&fx, "r43bp-b-control").await;
    let (digests, _) = firewall(&fx)
        .replay_digests(&control)
        .expect("premise: steady block stores the chain's entry under the Sync key");
    // Seam receipts may sit beside the step receipts (`capture_commit`
    // keeps both); at least one labelled alpha:read step must be there.
    let receipts: Vec<(Option<u32>, &str, &str)> = digests
        .iter()
        .map(|d| (d.label, d.server.as_str(), d.tool.as_str()))
        .collect();
    assert!(
        receipts
            .iter()
            .any(|&(label, server, tool)| label.is_some() && (server, tool) == ("alpha", "read")),
        "premise: the entry holds an in-plan, labelled alpha:read receipt: {receipts:?}"
    );
    reload(&fx, CollusionAction::Off);
    let key = keyed_chain(&fx, "r43bp-b").await;
    assert!(
        firewall(&fx).replay_digests(&key).is_none(),
        "R4.3b′ B: a replay entry was stored under the Sync key though `off` was current at delivery"
    );
}

/// Case A (the post-fix positive half): startup `off`, `block` published
/// with the startup window, min_matches and common_principals, then the
/// in-plan delivery stores an entry under the Sync key. On base this
/// fails at that assert by the startup gate: under a startup `off` no
/// detector exists (`detector_for`), so nothing is staged or stored. After
/// the fix the detector is always built and the matching activation
/// applies (ADR-029 amended).
#[tokio::test]
async fn r43b_prime_a_block_published_before_delivery_stores_a_replay_entry() {
    let fx = live_fixture(CollusionAction::Off).await;
    reload(&fx, CollusionAction::Block);
    let key = keyed_chain(&fx, "r43bp-a").await;
    assert!(
        firewall(&fx).replay_digests(&key).is_some(),
        "R4.3b′ A: no replay entry under the Sync key though `block` was current at delivery"
    );
}
