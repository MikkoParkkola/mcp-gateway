// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8011 / MIK-8025: what the gateway writes into a direct-route answer is
//! not backend text, so a direct caller's receipt leaves it out, live and on
//! an idempotent replay, while the backend's own text stays in.

use super::*;

/// A copy needs a shared run of `K + 2W - 1` = 79 chars to reach the
/// default two matching fingerprints, so each probe is at least that long.
const PROBE: usize = 79;

/// `read` costs 1.0 against a 1.1 budget per tool, overall and for `alice`
/// (bearer `a`), so her first read is answered with three gateway warnings.
#[cfg(feature = "cost-governance")]
fn warn_alice(meta: MetaMcp) -> MetaMcp {
    use crate::cost_accounting::config::CostGovernanceConfig;
    use crate::cost_accounting::enforcer::BudgetEnforcer;
    use crate::cost_accounting::registry::CostRegistry;
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    cfg.tool_costs.insert("read".to_string(), 1.0);
    cfg.budgets.daily = Some(1.1);
    cfg.budgets.per_tool.insert("read".to_string(), 1.1);
    cfg.budgets.per_key.insert("alice".to_string(), 1.1);
    let registry = Arc::new(CostRegistry::new(&cfg));
    let enforcer = Arc::new(BudgetEnforcer::new(cfg, Arc::clone(&registry)));
    meta.with_cost_governance(enforcer, registry)
}

/// Every answer is stamped with the gateway's signed `_meta.provenance`.
fn stamp(mut meta: MetaMcp) -> MetaMcp {
    meta.enable_provenance_stamping(
        crate::attestation::BnautAttestationSigner::new(b"prov-key".to_vec(), "unit")
            .with_audience("test-gateway")
            .derive_domain(crate::attestation::RESULT_PROVENANCE_DOMAIN_INFO),
    );
    meta
}

/// The string leaves of `value` in the order a delivery digest walks them,
/// newline-joined as it joins them; long enough to be caught.
fn leaf_run(value: &Value) -> String {
    fn visit<'v>(value: &'v Value, out: &mut Vec<&'v str>) {
        match value {
            Value::String(s) => out.push(s),
            Value::Array(items) => items.iter().for_each(|v| visit(v, out)),
            Value::Object(map) => map.values().for_each(|v| visit(v, out)),
            _ => {}
        }
    }
    let mut leaves = Vec::new();
    visit(value, &mut leaves);
    let run = leaves.join("\n");
    assert!(run.len() >= PROBE, "base: too short to be caught: {value}");
    run
}

/// The gateway's cost warnings in a delivered body, as one probe.
#[cfg(feature = "cost-governance")]
fn warning(body: &str) -> String {
    let warnings = &envelope(body)["result"]["_cost_warnings"];
    assert!(warnings.is_array(), "base: no gateway cost warning: {body}");
    leaf_run(warnings)
}

/// The gateway's `_meta.provenance` stamp in a delivered body, as one probe.
fn provenance_text(body: &str) -> String {
    let stamp = &envelope(body)["result"]["_meta"]["provenance"];
    assert!(stamp.is_object(), "base: no provenance stamp: {body}");
    leaf_run(stamp)
}

/// `read` with an idempotency key, as `who`.
async fn keyed_read(fx: &Fixture, who: &str, key: &str) -> String {
    let (status, body) = fx
        .call(Some(who), &call("read", &json!({}), Some(key), None))
        .await;
    assert_eq!(status, 200, "{body}");
    body
}

/// `MIK-8011.DIRECT.1`: a live direct read carries the gateway's cost warning;
/// A's receipt leaves it out (B may send it) and keeps the backend's text.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn a_direct_cost_warning_stays_out_of_the_receipt() {
    let fx = fixture(Setup {
        arm: warn_alice,
        ..Setup::default()
    })
    .await;
    let text = warning(&fx.read(Some("a")).await);
    assert_sent(&fx, &fx.send(Some("b"), &text).await, 1);
    assert_refused(&fx, &fx.send(Some("b"), PROSE).await, 1);
}

/// `MIK-8011.DIRECT.2`: an idempotent replay serves the stored warning; the
/// replay's own receipt (the first one lapsed) leaves it out as well.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn a_replayed_direct_cost_warning_stays_out_of_the_receipt() {
    let fx = fixture(Setup {
        window_secs: 1,
        arm: warn_alice,
        ..Setup::default()
    })
    .await;
    let text = warning(&keyed_read(&fx, "a", "key-8011").await);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let reads = fx.reads();
    let replay = keyed_read(&fx, "a", "key-8011").await;
    assert_eq!(
        fx.reads(),
        reads,
        "base: the re-issue is a replay: {replay}"
    );
    assert_eq!(
        warning(&replay),
        text,
        "the replay serves the stored warning"
    );
    assert_sent(&fx, &fx.send(Some("b"), &text).await, 1);
    assert_refused(&fx, &fx.send(Some("b"), PROSE).await, 1);
}

/// `MIK-8025.RED.1`: the gateway's provenance stamp on a live direct answer is
/// not in A's receipt; the backend's text is.
#[tokio::test]
async fn a_direct_provenance_stamp_stays_out_of_the_receipt() {
    let fx = fixture(Setup {
        arm: stamp,
        ..Setup::default()
    })
    .await;
    let text = provenance_text(&fx.read(Some("a")).await);
    assert_sent(&fx, &fx.send(Some("b"), &text).await, 1);
    assert_refused(&fx, &fx.send(Some("b"), PROSE).await, 1);
}

/// `MIK-8025.RECEIPT.1`: a replay serves the stored stamp; its receipt (the
/// first one lapsed) leaves the stamp out and keeps the backend's text.
#[tokio::test]
async fn a_replayed_direct_provenance_stamp_stays_out_of_the_receipt() {
    let fx = fixture(Setup {
        window_secs: 1,
        arm: stamp,
        ..Setup::default()
    })
    .await;
    let text = provenance_text(&keyed_read(&fx, "a", "key-8025").await);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let reads = fx.reads();
    let replay = keyed_read(&fx, "a", "key-8025").await;
    assert_eq!(
        fx.reads(),
        reads,
        "base: the re-issue is a replay: {replay}"
    );
    assert_eq!(
        provenance_text(&replay),
        text,
        "the replay serves the stamp"
    );
    assert_sent(&fx, &fx.send(Some("b"), &text).await, 1);
    assert_refused(&fx, &fx.send(Some("b"), PROSE).await, 1);
}
