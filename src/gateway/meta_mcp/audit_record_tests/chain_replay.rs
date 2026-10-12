// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7636: a chain-refused call is recorded uninspected, and a keyed replay
//! of its stored failure keeps saying so.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use super::{Scripted, api_key_caller, context, ok_result, records};
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, ChainEmit, ChainMode, FailsafeConfig};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::MetaMcp;
use crate::idempotency::IdempotencyCache;
use crate::protocol::mrtr::RetryFields;
use crate::security::firewall::tenant_guard::TenantGuardConfig;
use crate::security::firewall::{Firewall, FirewallConfig};
use crate::security::transparency_log::TransparencyLogConfig;

/// A gateway whose one backend `alpha` requires a signature chain but answers
/// without one, with attribution on, idempotency on and a log in `dir`.
fn chained_meta(dir: &tempfile::TempDir) -> MetaMcp {
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig {
            signature_chain: ChainMode::Require,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Scripted(Ok(ok_result()))));
    let _ = registry.register(backend);
    let logger = crate::security::TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: dir
            .path()
            .join("audit.jsonl")
            .to_string_lossy()
            .into_owned(),
        key_id: "d1".to_string(),
        ..TransparencyLogConfig::default()
    }))
    .expect("open log");
    let mut meta = MetaMcp::new(registry);
    meta.enable_transparency_log(Arc::new(logger));
    meta.set_chain_signer(
        crate::security::signature_chain::ChainSigner::from_seed(&[7; 32], "gw-test")
            .expect("signer"),
        ChainEmit::OnRequest,
    );
    meta.enable_idempotency(Arc::new(IdempotencyCache::new()), Duration::from_secs(300));
    meta.set_firewall(Some(Arc::new(
        Firewall::from_config(
            FirewallConfig {
                tenant_guard: TenantGuardConfig {
                    arg_keys: vec!["customer_id".to_string()],
                    ..TenantGuardConfig::default()
                },
                ..FirewallConfig::default()
            },
            None,
        )
        .with_continuations(meta.continuation()),
    )));
    meta
}

/// GH2555 (meta route). The first call is refused unread by the chain check;
/// the same key served again from the stored failure is a cached delivery of
/// a value no gate read.
#[tokio::test]
async fn a_replayed_chain_refusal_keeps_its_uninspected_attribution() {
    // With no tenant named first (GH2555.2), so that case fails on its own,
    // then with one.
    for arguments in [json!({}), json!({"customer_id": "cust-1"})] {
        let dir = tempfile::tempdir().unwrap();
        let meta = chained_meta(&dir);
        let who = api_key_caller();
        let retry = RetryFields {
            idempotency_key: Some(format!(
                "key-7636-{}",
                arguments.as_object().map_or(0, serde_json::Map::len)
            )),
            ..RetryFields::default()
        };
        let mut caller = context(&AllowAll, &who);
        caller.retry = &retry;
        let args = json!({"server": "alpha", "tool": "read", "arguments": arguments});
        let mut errors = Vec::new();
        for _ in 0..2 {
            let error = meta
                .invoke_tool(&args, None, &caller)
                .await
                .expect_err("the chain check refuses the unchained answer");
            errors.push(error.to_rpc_code());
        }
        // The replay answers the stored refusal's code.
        assert_eq!(errors[0], errors[1], "{errors:?}");
        let all = records(&dir);
        assert_eq!(all.len(), 2, "{all:?}");
        assert_eq!(all[0]["attribution"], json!("uninspected"), "{}", all[0]);
        assert_eq!(
            all[1]["attribution"],
            json!("cached_delivery_uninspected"),
            "arguments {arguments}: {}",
            all[1]
        );
    }
}
