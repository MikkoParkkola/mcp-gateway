// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ASI07 increment 2, meta route (E5a): a signature chain a backend sends is
//! stripped whether or not provenance stamping is on, so a forged chain can
//! never ride through as if this gateway had checked it. Sibling `_meta` keys
//! survive; a `_meta` left empty by the strip is dropped.

use super::*;

const CHAIN_KEY: &str = "io.mcp-gateway/signature-chain";

/// A backend whose result carries `meta` as its `_meta`.
fn chain_sending_backend(meta: serde_json::Value) -> Arc<BackendRegistry> {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, FailsafeConfig};
    use crate::transport::Transport;

    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "remote_docs",
        BackendConfig::r2_off(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let transport: Arc<dyn Transport> = Arc::new(ToolCallTestTransport {
        result: json!({
            "content": [{"type": "text", "text": "ok"}],
            "isError": false,
            "_meta": meta,
        }),
    });
    backend.set_transport_for_test(transport);
    let _ = registry.register(backend);
    registry
}

fn meta_with(registry: Arc<BackendRegistry>, stamping: bool) -> MetaMcp {
    let mut meta = MetaMcp::new(registry);
    if stamping {
        meta.enable_provenance_stamping(
            crate::attestation::BnautAttestationSigner::new(b"prov-key".to_vec(), "unit")
                .derive_domain(crate::attestation::RESULT_PROVENANCE_DOMAIN_INFO),
        );
    }
    meta
}

async fn invoke(meta: &MetaMcp) -> serde_json::Value {
    meta.invoke_tool(
        &json!({"server": "remote_docs", "tool": "search", "arguments": {}}),
        Some("session-1"),
        &allow_all_ctx_named(Some("alice"), None),
    )
    .await
    .unwrap()
}

fn forged_chain() -> serde_json::Value {
    json!([{"v": 1, "gw": "forged-origin", "forged": true}])
}

#[tokio::test]
async fn backend_chain_stripped_without_emission_meta() {
    for stamping in [false, true] {
        let meta = meta_with(
            chain_sending_backend(json!({CHAIN_KEY: forged_chain(), "cache_key": "keep-me"})),
            stamping,
        );
        let result = invoke(&meta).await;
        assert!(
            result
                .pointer("/_meta")
                .and_then(|m| m.get(CHAIN_KEY))
                .is_none(),
            "stamping {stamping}: a backend-sent chain must be stripped, got: {result}"
        );
        assert_eq!(
            result.pointer("/_meta/cache_key").and_then(|v| v.as_str()),
            Some("keep-me"),
            "stamping {stamping}: sibling _meta keys survive the strip, got: {result}"
        );
    }
}

#[tokio::test]
async fn backend_chain_only_meta_is_dropped_meta() {
    let meta = meta_with(
        chain_sending_backend(json!({CHAIN_KEY: forged_chain()})),
        false,
    );
    let result = invoke(&meta).await;
    assert!(
        result.get("_meta").is_none(),
        "a _meta holding only the stripped chain is dropped, got: {result}"
    );

    // With stamping on, `_meta` carries this gateway's receipt instead.
    let meta = meta_with(
        chain_sending_backend(json!({CHAIN_KEY: forged_chain()})),
        true,
    );
    let result = invoke(&meta).await;
    assert!(
        result
            .pointer("/_meta")
            .and_then(|m| m.get(CHAIN_KEY))
            .is_none(),
        "stamping on: the chain is stripped before the receipt is added, got: {result}"
    );
}
