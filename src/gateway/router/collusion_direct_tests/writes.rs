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

/// A modern-era direct `read` as `key` on the signed, relayed fixture (the
/// hardened posture serves the direct route no legacy `tools/call`); with
/// `cmd`, the text a relay check reads.
async fn signed_read(
    fx: &crate::gateway::router::direct_guards_fixture::Fx,
    key: &str,
    cmd: Option<&str>,
) -> (axum::http::StatusCode, Value) {
    use crate::protocol::meta::{KEY_CLIENT_CAPABILITIES, KEY_PROTOCOL_VERSION, MODERN_VERSIONS};
    let args = cmd.map_or_else(|| json!({}), |cmd| json!({ "cmd": cmd }));
    let params = json!({"name": "read", "arguments": args, "_meta": {
        KEY_PROTOCOL_VERSION: MODERN_VERSIONS[0],
        KEY_CLIENT_CAPABILITIES: {},
    }});
    crate::gateway::router::direct_guards_fixture::send_with_headers(
        fx,
        "/mcp/alpha",
        key,
        "tools/call",
        params,
        None,
        &[
            ("mcp-protocol-version", MODERN_VERSIONS[0]),
            ("mcp-method", "tools/call"),
            ("mcp-name", "read"),
        ],
    )
    .await
}

/// `MIK-8025.NOTE.1`: the hardened direct route signs every answer; the
/// signature is the gateway's, so A's receipt leaves it out (B may send it)
/// and keeps the backend's text (B is refused).
#[tokio::test]
async fn a_direct_signature_stays_out_of_the_receipt() {
    use crate::gateway::router::direct_guards_fixture::{Answer, fixture_signed_relayed};
    let fx = fixture_signed_relayed(Answer::Text(PROSE)).await;
    let (status, first) = signed_read(&fx, "k-std", None).await;
    assert_eq!(status, 200, "{first}");
    let signature = &first["result"]["_signature"];
    assert!(signature.is_object(), "base: no gateway signature: {first}");
    let text = leaf_run(signature);
    let (status, sent) = signed_read(&fx, "k-budget", Some(&text)).await;
    assert_eq!(status, 200, "the signature was receipted: {sent}");
    assert!(sent.get("error").is_none(), "{sent}");
    let (status, relay) = signed_read(&fx, "k-budget", Some(PROSE)).await;
    assert_eq!(status, 403, "the backend's text was not receipted: {relay}");
    assert_eq!(relay["error"]["code"], -32002, "{relay}");
}

/// `MIK-8011.DIRECT.3` control: a backend's own `_cost_warnings` member, on an
/// answer the gateway gave no warning, is backend text and stays receipted.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn a_backend_cost_warnings_member_stays_in_the_receipt() {
    let fx = fixture(Setup::default()).await;
    fx.answer_read(Read::Raw(json!({
        "content": [{"type": "text", "text": "ok"}],
        "isError": false,
        "_cost_warnings": [PROSE],
    })));
    let body = fx.read(Some("a")).await;
    assert!(
        body.contains("orchard"),
        "base: the member is delivered: {body}"
    );
    assert_refused(&fx, &fx.send(Some("b"), PROSE).await, 0);
}

/// `read` costs 9000 against the credential-named key's 10000 budget, so its
/// read gets one per-key warning naming the key (82 chars once redacted).
#[cfg(feature = "cost-governance")]
fn warn_credential_key(meta: MetaMcp) -> MetaMcp {
    use crate::cost_accounting::config::CostGovernanceConfig;
    use crate::cost_accounting::enforcer::BudgetEnforcer;
    use crate::cost_accounting::registry::CostRegistry;
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    cfg.tool_costs.insert("read".to_string(), 9000.0);
    cfg.budgets
        .per_key
        .insert(CREDENTIAL_KEY.to_string(), 10_000.0);
    let registry = Arc::new(CostRegistry::new(&cfg));
    let enforcer = Arc::new(BudgetEnforcer::new(cfg, Arc::clone(&registry)));
    meta.with_cost_governance(enforcer, registry)
}

/// MIK-8011 (design RED.3): the response scan redacts the warning naming the
/// credential-like key in place; the note binds the text the caller got, so
/// the redacted warning is still left out of the receipt and the backend's
/// text stays in.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn a_redacted_direct_cost_warning_stays_out_of_the_receipt() {
    let fx = fixture(Setup {
        arm: warn_credential_key,
        ..Setup::default()
    })
    .await;
    let body = fx.read(Some("c")).await;
    let warnings = &envelope(&body)["result"]["_cost_warnings"];
    let delivered = warnings.to_string();
    assert!(
        delivered.contains("[REDACTED:credential]") && !delivered.contains(CREDENTIAL_KEY),
        "base: the scan redacted the warning: {body}"
    );
    assert_sent(&fx, &fx.send(Some("b"), &leaf_run(warnings)).await, 1);
    assert_refused(&fx, &fx.send(Some("b"), PROSE).await, 1);
}

/// Every eligible answer carries the gateway's signature-chain link.
fn link(mut meta: MetaMcp) -> MetaMcp {
    meta.set_chain_signer(
        crate::security::signature_chain::ChainSigner::from_seed(&[7; 32], "gw-test")
            .expect("signer"),
        crate::config::ChainEmit::Always,
    );
    meta
}

/// `MIK-8025.NOTE.1` (chain): the origin link the gateway adds to a live
/// direct answer is the gateway's, so A's receipt leaves it out (B may send
/// it) and keeps the backend's text (B is refused).
#[tokio::test]
async fn a_direct_chain_link_stays_out_of_the_receipt() {
    let fx = fixture(Setup {
        arm: link,
        ..Setup::default()
    })
    .await;
    let body = fx.read(Some("a")).await;
    let chain = &envelope(&body)["result"]["_meta"][crate::security::signature_chain::CHAIN_META];
    assert!(!chain.is_null(), "base: no chain link: {body}");
    let text = leaf_run(chain);
    assert_sent(&fx, &fx.send(Some("b"), &text).await, 1);
    assert_refused(&fx, &fx.send(Some("b"), PROSE).await, 1);
}
