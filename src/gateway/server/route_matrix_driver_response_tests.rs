// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Drivers for the response-stage matrix on stdio (MIK-8689 phase B): one
//! `tools/call read` by its surfaced name through the real stdio dispatch,
//! with the HMAC receipt and the public seal both installed. Each returns the
//! delivered JSON-RPC body; the matrix (`route_check_matrix_tests::response`)
//! owns every assertion.

use std::sync::Arc;

use serde_json::{Value, json};

use super::{BackendRegistry, Counting, MetaMcp, audited_firewall_with, stdio_meta, stdio_send};
use crate::attestation::{BnautAttestationSigner, RESULT_PROVENANCE_DOMAIN_INFO};
use crate::protocol::meta::Era;
use crate::trust::provenance_public::ProvenancePublicSigner;

/// What else the stdio Meta-MCP runs beside the two provenance signers.
#[derive(Clone, Copy, Debug)]
pub(crate) enum StdioSetup {
    /// Nothing else.
    Plain,
    /// The production firewall with a Warn rule on `read`: a credential in
    /// the answer is redacted and the answer delivered.
    Redacting,
}

/// `alpha`'s `read` surfaced by name, so the backend envelope is the result.
fn surface(meta: &mut MetaMcp) {
    // Surfacing is a consuming builder; the placeholder is dropped.
    let built = std::mem::replace(meta, MetaMcp::new(Arc::new(BackendRegistry::new())));
    *meta = built.with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
        server: "alpha".to_string(),
        tool: "read".to_string(),
    }]);
}

/// Both provenance signers, keyed as the HTTP drivers key them, so one trust
/// set verifies every route.
fn dual_signed(meta: &mut MetaMcp) {
    meta.enable_provenance_stamping(
        BnautAttestationSigner::new(b"prov-key".to_vec(), "unit")
            .with_audience("test-gateway")
            .derive_domain(RESULT_PROVENANCE_DOMAIN_INFO),
    );
    meta.enable_public_provenance(ProvenancePublicSigner::from_seed_for_test(
        [7u8; 32],
        "prov-test-1",
    ));
}

/// One stdio `tools/call read` in `era` under `setup`, the backend answering
/// `answer`.
pub(crate) async fn stdio_sealed(setup: StdioSetup, era: Era, answer: Value) -> Value {
    let audit = tempfile::tempdir().expect("a temporary directory");
    let firewall = matches!(setup, StdioSetup::Redacting).then(|| {
        audited_firewall_with(&audit.path().join("firewall.jsonl"), |config| {
            config.rules = vec![crate::security::firewall::FirewallRule {
                tool_match: "read".to_string(),
                action: crate::security::firewall::FirewallAction::Warn,
                reason: None,
                scan: Vec::new(),
                servers: None,
                keys: None,
                except: None,
            }];
        })
    });
    let transport = Arc::new(Counting {
        calls: Arc::default(),
        answer,
    });
    let meta = stdio_meta(
        move |meta| {
            surface(meta);
            dual_signed(meta);
            if let Some(firewall) = firewall {
                meta.share_keyring_with_for_test(&firewall);
                meta.set_firewall(Some(firewall));
            }
        },
        transport,
    )
    .await;
    let mut call_meta = serde_json::Map::new();
    if era == Era::Modern {
        call_meta.insert(
            "io.modelcontextprotocol/protocolVersion".to_string(),
            json!("2026-07-28"),
        );
        call_meta.insert(
            "io.modelcontextprotocol/clientCapabilities".to_string(),
            json!({"elicitation": {"form": {}}}),
        );
    }
    let params = json!({ "name": "read", "arguments": {}, "_meta": call_meta });
    stdio_send(&meta, params).await
}

/// Two legacy keyed calls (`r1`) of the surfaced `read` on one stdio
/// Meta-MCP with idempotency on, as `build_meta.rs` enables it: the first
/// runs, the second is the replay. Returns (first, replay, backend sends).
pub(crate) async fn stdio_sealed_replay() -> (Value, Value, usize) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let calls = Arc::new(AtomicUsize::new(0));
    let transport = Arc::new(Counting {
        calls: Arc::clone(&calls),
        answer: json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
    });
    let meta = stdio_meta(
        |meta| {
            surface(meta);
            dual_signed(meta);
            meta.enable_idempotency(
                Arc::new(crate::idempotency::IdempotencyCache::new()),
                crate::idempotency::CLEANUP_INTERVAL,
            );
        },
        transport,
    )
    .await;
    let params = json!({ "name": "read", "arguments": {},
                         "_meta": { (crate::protocol::mrtr::IDEMPOTENCY_KEY_META): "r1" } });
    let first = stdio_send(&meta, params.clone()).await;
    let replay = stdio_send(&meta, params).await;
    (first, replay, calls.load(Ordering::SeqCst))
}

/// [`stdio_sealed_replay`] across eras: a legacy keyed call (`r1`) stores the
/// answer, then a modern call with the same key is served it. Returns (first,
/// second, backend sends).
pub(crate) async fn stdio_legacy_then_modern_replay() -> (Value, Value, usize) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let calls = Arc::new(AtomicUsize::new(0));
    let transport = Arc::new(Counting {
        calls: Arc::clone(&calls),
        answer: json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
    });
    let meta = stdio_meta(
        |meta| {
            surface(meta);
            dual_signed(meta);
            meta.enable_idempotency(
                Arc::new(crate::idempotency::IdempotencyCache::new()),
                crate::idempotency::CLEANUP_INTERVAL,
            );
        },
        transport,
    )
    .await;
    let key = crate::protocol::mrtr::IDEMPOTENCY_KEY_META;
    let legacy = json!({ "name": "read", "arguments": {}, "_meta": { (key): "r1" } });
    let modern = json!({ "name": "read", "arguments": {}, "_meta": {
        (key): "r1",
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}},
    } });
    let first = stdio_send(&meta, legacy).await;
    let second = stdio_send(&meta, modern).await;
    (first, second, calls.load(Ordering::SeqCst))
}

/// One message-signed stdio `gateway_invoke` of `alpha`'s `read` (nonce
/// `n1`), with both provenance signers and a transparency log on the
/// Meta-MCP. Returns the delivered body, its `response_delivery_attempt` rows
/// and the log's directory (kept alive by the caller).
pub(crate) async fn stdio_signed_recorded() -> (Value, Vec<Value>, tempfile::TempDir) {
    use crate::gateway::router::route_matrix_driver_tests::response::{delivery_rows, temp_log};
    let (dir, log) = temp_log(None);
    let meta_log = Arc::clone(&log);
    let transport = Arc::new(Counting {
        calls: Arc::default(),
        answer: json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
    });
    let meta = stdio_meta(
        move |meta| {
            dual_signed(meta);
            meta.enable_message_signing(
                crate::security::message_signing::MessageSigner::new(
                    b"stdio-recsign-secret-0123456789abcdef".to_vec(),
                    None,
                    "stdio".to_owned(),
                ),
                std::time::Duration::from_secs(300),
                false,
            );
            meta.enable_transparency_log(meta_log);
        },
        transport,
    )
    .await;
    let params = json!({ "name": "gateway_invoke", "arguments": {
        "server": "alpha", "tool": "read", "arguments": {}, "nonce": "n1" } });
    let body = stdio_send(&meta, params).await;
    let rows = delivery_rows(&log).await;
    (body, rows, dir)
}
