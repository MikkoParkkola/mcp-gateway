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
