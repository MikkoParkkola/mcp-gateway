// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! COLLUDE.1 §13.3 M12, and the shared outbound builder.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{Value, json};

use super::*;
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::authz_tests::ctx;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::firewall::{
    CollusionAction, CollusionConfig, Firewall, FirewallConfig, RelayCaller,
};

/// Ordinary prose, long enough for several fingerprints.
const PROSE: &str = "The orchard ledger for the north slope records seven rows of late pears, \
    the grafting dates for each rootstock, the hours the drip lines ran during the dry weeks of \
    August, and which crew pruned the older trees after the second frost. It closes with the \
    count of crates sent to the cooperative press and a note about the broken ladder by the barn.";

/// A backend keeping every `tools/call` params it received.
struct Seen(Arc<parking_lot::Mutex<Vec<Value>>>);

#[async_trait::async_trait]
impl crate::transport::Transport for Seen {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/list" {
            let tool = json!({"name": "send", "description": "A tool.", "inputSchema": {"type": "object"}});
            return Ok(JsonRpcResponse::success(id, json!({"tools": [tool]})));
        }
        self.0.lock().push(params.unwrap_or(Value::Null));
        let sent = json!({"content": [{"type": "text", "text": "sent"}], "isError": false});
        Ok(JsonRpcResponse::success(id, sent))
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// M12: an injected secret is never part of what the relay check reads.
/// The secret here is text another caller was delivered: a check on the
/// post-injection params would refuse the call; the backend still gets it.
#[tokio::test]
async fn relay_audit_has_no_injected_secret() {
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let backend = Arc::new(crate::backend::Backend::new(
        "alpha",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    backend.set_transport_for_test(Arc::new(Seen(Arc::clone(&seen))));
    assert!(registry.register(backend));
    let rule: crate::secret_injection::CredentialRule =
        serde_json::from_value(json!({"name": "token", "value": PROSE, "inject_key": "token"}))
            .expect("rule parses");
    let injector = crate::secret_injection::SecretInjector::new(HashMap::from([(
        "alpha".to_string(),
        vec![rule],
    )]));
    let firewall = Arc::new(Firewall::from_config(
        FirewallConfig {
            rules: serde_yaml::from_str("[{match: \"*\", action: allow}]").unwrap(),
            collusion: CollusionConfig {
                action: CollusionAction::Block,
                sources: vec!["alpha:*".to_string()],
                ..CollusionConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    ));
    let mut meta = MetaMcp::new(registry).with_secret_injector(injector);
    meta.set_firewall(Some(Arc::clone(&firewall)));
    let delivered = json!({"content": [{"type": "text", "text": PROSE}]});
    firewall.record_delivery(RelayCaller::Keyed("alice"), "alpha", "send", &delivered);

    let bob = MetaMcpCallerContext {
        caller_key: Some("bob"),
        ..ctx(&AllowAll)
    };
    let call = json!({"server": "alpha", "tool": "send", "arguments": {"text": "hello"}});
    let result = meta.invoke_tool(&call, None, &bob).await;
    assert!(
        result.is_ok(),
        "the injected secret was checked: {result:?}"
    );
    let seen = seen.lock().clone();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0]["arguments"]["token"], PROSE, "base: injected");
}

/// A value the caller put under a key secret injection overwrites never
/// leaves the gateway, so the relay check does not read it either.
#[tokio::test]
async fn relay_check_skips_a_caller_value_the_injector_overwrites() {
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let backend = Arc::new(crate::backend::Backend::new(
        "alpha",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    backend.set_transport_for_test(Arc::new(Seen(Arc::clone(&seen))));
    assert!(registry.register(backend));
    let rule: crate::secret_injection::CredentialRule = serde_json::from_value(
        json!({"name": "token", "value": "vault-secret", "inject_key": "token"}),
    )
    .expect("rule parses");
    let injector = crate::secret_injection::SecretInjector::new(HashMap::from([(
        "alpha".to_string(),
        vec![rule],
    )]));
    let firewall = Arc::new(Firewall::from_config(
        FirewallConfig {
            rules: serde_yaml::from_str("[{match: \"*\", action: allow}]").unwrap(),
            collusion: CollusionConfig {
                action: CollusionAction::Block,
                sources: vec!["alpha:*".to_string()],
                ..CollusionConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    ));
    let mut meta = MetaMcp::new(registry).with_secret_injector(injector);
    meta.set_firewall(Some(Arc::clone(&firewall)));
    let delivered = json!({"content": [{"type": "text", "text": PROSE}]});
    firewall.record_delivery(RelayCaller::Keyed("alice"), "alpha", "send", &delivered);

    let bob = MetaMcpCallerContext {
        caller_key: Some("bob"),
        ..ctx(&AllowAll)
    };
    let call = json!({"server": "alpha", "tool": "send", "arguments": {"token": PROSE}});
    let result = meta.invoke_tool(&call, None, &bob).await;
    assert!(
        result.is_ok(),
        "an overwritten caller value was checked: {result:?}"
    );
    let seen = seen.lock().clone();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(
        seen[0]["arguments"]["token"], "vault-secret",
        "base: overwritten"
    );
}

/// Under `observe` a relay on the meta route is let through and reported: the
/// backend is called, and the audit log holds one digest-only relay finding.
#[tokio::test]
async fn meta_observe_reports_a_relay_and_sends_it() {
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let backend = Arc::new(crate::backend::Backend::new(
        "alpha",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    backend.set_transport_for_test(Arc::new(Seen(Arc::clone(&seen))));
    assert!(registry.register(backend));
    let dir = tempfile::tempdir().expect("tempdir");
    let firewall = Arc::new(Firewall::from_config(
        FirewallConfig {
            rules: serde_yaml::from_str("[{match: \"*\", action: allow}]").unwrap(),
            audit_log: Some(dir.path().join("audit.ndjson")),
            collusion: CollusionConfig {
                action: CollusionAction::Observe,
                sources: vec!["alpha:*".to_string()],
                ..CollusionConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    ));
    let mut meta = MetaMcp::new(registry);
    meta.set_firewall(Some(Arc::clone(&firewall)));
    let delivered = json!({"content": [{"type": "text", "text": PROSE}]});
    firewall.record_delivery(RelayCaller::Keyed("alice"), "alpha", "send", &delivered);

    let bob = MetaMcpCallerContext {
        caller_key: Some("bob"),
        ..ctx(&AllowAll)
    };
    let call = json!({"server": "alpha", "tool": "send", "arguments": {"text": PROSE}});
    let result = meta.invoke_tool(&call, None, &bob).await;
    assert!(result.is_ok(), "observe must not refuse: {result:?}");
    assert_eq!(seen.lock().len(), 1, "base: the relay was sent");
    let audit = std::fs::read_to_string(dir.path().join("audit.ndjson")).expect("audited");
    assert_eq!(audit.matches("collusion_relay").count(), 1, "{audit}");
    assert!(!audit.contains("orchard"), "content leaked into the audit");
}

/// MIK-7800: HTTP receipts ride on the response and record only when
/// `emit_http`, the last step, lets it out. A response a later step replaces
/// (the grant slot) is dropped, and its receipts with it.
#[tokio::test]
async fn http_receipts_record_only_when_emit_http_lets_the_answer_out() {
    let firewall = Arc::new(Firewall::from_config(
        FirewallConfig {
            collusion: CollusionConfig {
                action: CollusionAction::Block,
                sources: vec!["alpha:*".to_string()],
                ..CollusionConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    ));
    let mut meta = MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    meta.set_firewall(Some(Arc::clone(&firewall)));
    let meta = Arc::new(meta);
    let deliver = |delivers: bool| {
        let meta = Arc::clone(&meta);
        async move {
            let value = json!({"content": [{"type": "text", "text": PROSE}]});
            meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "send"), &value);
            let answer = if delivers {
                JsonRpcResponse::success(RequestId::Number(1), value)
            } else {
                JsonRpcResponse::error(Some(RequestId::Number(1)), -32000, "refused")
            };
            meta.settle_relay_receipts(&answer);
            axum::Json(json!({"ok": true}))
        }
    };
    let relayed = || {
        let params = json!({"name": "send", "arguments": {"text": PROSE}});
        let verdict = firewall.check_relay(
            RelayCaller::Keyed("bob"),
            "alpha",
            "send",
            &params,
            ("s", "bob"),
        );
        !verdict.allowed
    };

    // Replaced after the dispatch: dropped before `emit_http`.
    drop(
        crate::gateway::meta_mcp::invoke::relay::collecting_http(Arc::clone(&meta), deliver(true))
            .await,
    );
    assert!(!relayed(), "a replaced answer must record no receipt");
    // An answer that is not a delivered result records nothing either.
    let refused =
        crate::gateway::meta_mcp::invoke::relay::collecting_http(Arc::clone(&meta), deliver(false))
            .await;
    crate::gateway::outbound::emit_http(refused, None).await;
    assert!(!relayed(), "an error answer must record no receipt");
    // Out as built: recorded.
    let out =
        crate::gateway::meta_mcp::invoke::relay::collecting_http(Arc::clone(&meta), deliver(true))
            .await;
    crate::gateway::outbound::emit_http(out, None).await;
    assert!(relayed(), "control: a delivered answer records its receipt");
}

/// The relay check and the dispatch read one builder: every field a
/// backend receives beside `arguments` is in it.
#[test]
fn outbound_params_carry_meta_and_retry_fields() {
    let retry = OutboundRetry {
        request_state: Some("state".to_string()),
        input_responses: Some(json!({"k1": {"roots": []}})),
    };
    let inbound = json!({"progressToken": "p-1", "baggage": "k=v", "other": "dropped"});
    let params = outbound_params("send", json!({"a": 1}), Some(&inbound), Some("ck"), &retry);
    assert_eq!(params["name"], "send");
    assert_eq!(params["arguments"]["a"], 1);
    assert_eq!(params["_meta"]["progressToken"], "p-1");
    assert_eq!(params["_meta"]["baggage"], "k=v");
    assert_eq!(params["_meta"]["prompt_cache_key"], "ck");
    assert!(params["_meta"].get("other").is_none(), "{params}");
    assert_eq!(params["requestState"], "state");
    assert_eq!(params["inputResponses"]["k1"]["roots"], json!([]));
}

/// MIK-7832.RELAY.3: the recorded copy is the form the caller is handed, so
/// the reserved signature-chain member, which delivery strips, is not in it.
#[test]
fn a_recorded_catalogue_result_omits_the_reserved_chain_member() {
    let meta = MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    let result = json!({
        "contents": [{"uri": "res://orchard", "text": PROSE}],
        "_meta": {crate::security::signature_chain::CHAIN_META: {"link": "reserved-chain-text"}},
    });
    let recorded = meta.recorded_prompt(("alpha", "resources/read"), None, "catalogue", &result);
    assert!(
        !recorded.to_string().contains("reserved-chain-text"),
        "{recorded}"
    );
    assert!(
        recorded.to_string().contains("orchard ledger"),
        "{recorded}"
    );
}

/// MIK-7832.RELAY.4: a string or array result has no member for the
/// context-integrity verdict, so the verdict rides in a wrapper instead of
/// being dropped.
#[test]
fn a_recorded_non_object_result_keeps_its_verdict() {
    let meta = MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    for result in [
        json!(format!("{PROSE} Contact: keeper@orchardcoop.fi")),
        json!([format!("{PROSE} Contact: keeper@orchardcoop.fi")]),
    ] {
        let recorded =
            meta.recorded_prompt(("alpha", "resources/read"), None, "catalogue", &result);
        assert!(
            recorded.get("_context_integrity").is_some(),
            "verdict dropped: {recorded}"
        );
        assert!(
            recorded.to_string().contains("orchard ledger"),
            "{recorded}"
        );
    }
}

/// MIK-7832.RELAY.4: wrapping a non-object result keeps it detectable: the
/// recorded copy's text still marks a later send of that text as a relay.
#[test]
fn a_wrapped_non_object_result_still_marks_a_relay() {
    let meta = MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    let fw = Firewall::from_config(
        FirewallConfig {
            collusion: CollusionConfig {
                action: CollusionAction::Block,
                sources: vec!["alpha:*".to_string()],
                ..CollusionConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    );
    let delivered = json!(format!("{PROSE} Contact: keeper@orchardcoop.fi"));
    let recorded = meta.recorded_prompt(("alpha", "resources/read"), None, "catalogue", &delivered);
    fw.record_delivery(
        RelayCaller::Keyed("a"),
        "alpha",
        "resources/read",
        &recorded,
    );
    let params = json!({"name": "send", "arguments": {"text": PROSE}});
    let verdict = fw.check_relay(
        RelayCaller::Keyed("b"),
        "alpha",
        "send",
        &params,
        ("s", "b"),
    );
    assert!(!verdict.allowed, "{verdict:?}");
}
