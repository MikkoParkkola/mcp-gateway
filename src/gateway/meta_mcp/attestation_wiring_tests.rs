// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Per-action attestation wiring (MIK-5223, B1-IDENT), extracted from
//! `tests.rs` for the file-size ratchet.

use super::*;
use crate::attestation::{
    AttestationMode, AttestationValidator, BnautAttestationSigner, TokenRequest,
};
use chrono::{TimeDelta, Utc};
use uuid::Uuid;

const KEY: &[u8] = b"gateway-invoke-wiring-key";

fn validator() -> Arc<AttestationValidator> {
    Arc::new(AttestationValidator::new(BnautAttestationSigner::new(
        KEY.to_vec(),
        "wiring",
    )))
}

fn valid_token() -> String {
    token_with(vec!["t".to_string()])
}

fn token_with(capabilities: Vec<String>) -> String {
    BnautAttestationSigner::new(KEY.to_vec(), "wiring")
        .issue(
            &TokenRequest {
                agent_identity: "agent-9".to_string(),
                task_uuid: Uuid::new_v4(),
                capabilities,
            },
            Utc::now(),
            TimeDelta::minutes(5),
        )
        .encoded()
        .to_string()
}

#[test]
fn mik_5223_caps_2_enforce_rejects_read_token_on_write_tool() {
    // MIK-5223.CAPS.2 — a token minted for ["read"] must NOT authorize a
    // write (non-read) tool under enforce mode (fail-closed, JSON-RPC -32002).
    let v = validator();
    let mm = make_meta_mcp().with_attestation(Arc::clone(&v), AttestationMode::Enforce);
    let token = token_with(vec!["read".to_string()]);
    // WHEN the read-scoped token invokes a write tool
    let err = mm
        .check_attestation(
            &json!({"server": "s", "tool": "write", "attestation": token}),
            Some("agent-9"),
            "gateway_invoke",
        )
        .unwrap_err();
    // THEN the call is rejected with the attestation JSON-RPC code -32002
    assert_eq!(err.to_rpc_code(), -32002, "got: {err}");
    assert!(err.to_string().contains("Attestation rejected"));
    assert_eq!(v.rejections_total(), 1);

    // AND the same read-scoped token IS admitted for the read tool.
    let ok = mm.check_attestation(
        &json!({"server": "s", "tool": "read", "attestation": token_with(vec!["read".to_string()])}),
        Some("agent-9"),
        "gateway_invoke",
    );
    assert!(ok.is_ok());
}

#[test]
fn mik_5223_caps_3_observe_logs_capability_mismatch_without_blocking() {
    // MIK-5223.CAPS.3 — observe mode records the capability mismatch in the
    // audit ring buffer but does NOT block the call.
    let v = validator();
    let mm = make_meta_mcp().with_attestation(Arc::clone(&v), AttestationMode::Observe);
    let token = token_with(vec!["read".to_string()]);
    let res = mm.check_attestation(
        &json!({"server": "s", "tool": "write", "attestation": token}),
        Some("agent-9"),
        "gateway_invoke",
    );
    // THEN the call is NOT blocked...
    assert!(res.is_ok());
    // ...but the capability mismatch is audited.
    assert_eq!(v.rejections_total(), 1);
    let records = v.audit().snapshot();
    assert_eq!(records.len(), 1);
    assert!(matches!(
        records[0].rejection,
        crate::attestation::AttestationRejection::CapabilityNotGranted { .. }
    ));
}

#[test]
fn no_validator_is_a_no_op_even_without_token() {
    // GIVEN a gateway with no attestation validator attached (default)
    let mm = make_meta_mcp();
    // WHEN a call carries no attestation token
    // THEN the gate passes (zero-cost no-op, byte-identical to before)
    assert!(
        mm.check_attestation(&json!({"server": "s", "tool": "t"}), None, "gateway_invoke")
            .is_ok()
    );
}

#[test]
fn observe_mode_passes_invalid_token_but_audits_it() {
    // GIVEN observe mode (enforce = false) — the safe rollout position
    let v = validator();
    let mm = make_meta_mcp().with_attestation(Arc::clone(&v), AttestationMode::Observe);
    // WHEN a call presents a forged/garbage token
    let res = mm.check_attestation(
        &json!({"server": "s", "tool": "t", "attestation": "forged.token"}),
        Some("agent-9"),
        "gateway_invoke",
    );
    // THEN the call is NOT blocked (observe never breaks traffic)...
    assert!(res.is_ok());
    // ...but the rejection is recorded in the audit ring buffer.
    assert_eq!(v.rejections_total(), 1);
    let records = v.audit().snapshot();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].boundary, "gateway_invoke");
}

#[test]
fn enforce_mode_rejects_missing_token_fail_closed() {
    // GIVEN enforce mode (fail-closed)
    let v = validator();
    let mm = make_meta_mcp().with_attestation(Arc::clone(&v), AttestationMode::Enforce);
    // WHEN a call presents NO attestation token
    let err = mm
        .check_attestation(&json!({"server": "s", "tool": "t"}), None, "gateway_invoke")
        .unwrap_err();
    // THEN the call is rejected with the attestation JSON-RPC code
    let msg = err.to_string();
    assert!(msg.contains("Attestation rejected"), "got: {msg}");
    assert_eq!(v.rejections_total(), 1);
}

#[test]
fn enforce_mode_rejects_forged_token() {
    // GIVEN enforce mode
    let v = validator();
    let mm = make_meta_mcp().with_attestation(Arc::clone(&v), AttestationMode::Enforce);
    // WHEN a call presents a token that fails signature verification
    let err = mm
        .check_attestation(
            &json!({"server": "s", "tool": "t", "attestation": "bad.signature"}),
            Some("agent-9"),
            "gateway_invoke",
        )
        .unwrap_err();
    // THEN it is rejected, and the forgery attempt is audited
    assert!(err.to_string().contains("Attestation rejected"));
    assert_eq!(v.rejections_total(), 1);
}

#[test]
fn enforce_mode_admits_valid_token() {
    // GIVEN enforce mode and a correctly-signed, unexpired token
    let v = validator();
    let mm = make_meta_mcp().with_attestation(Arc::clone(&v), AttestationMode::Enforce);
    let token = valid_token();
    // WHEN the call presents the valid token
    let res = mm.check_attestation(
        &json!({"server": "s", "tool": "t", "attestation": token}),
        Some("agent-9"),
        "gateway_invoke",
    );
    // THEN the call is admitted and the success is counted (no rejection)
    assert!(res.is_ok());
    assert_eq!(v.validations_total(), 1);
    assert_eq!(v.rejections_total(), 0);
    assert!(v.audit().is_empty());
}

#[test]
fn observe_mode_admits_valid_token_without_auditing() {
    // GIVEN observe mode and a valid token
    let v = validator();
    let mm = make_meta_mcp().with_attestation(Arc::clone(&v), AttestationMode::Observe);
    let token = valid_token();
    // WHEN the valid token is presented
    let res = mm.check_attestation(
        &json!({"server": "s", "tool": "t", "attestation": token}),
        Some("agent-9"),
        "gateway_invoke",
    );
    // THEN it passes and counts as a successful validation
    assert!(res.is_ok());
    assert_eq!(v.validations_total(), 1);
    assert!(v.audit().is_empty());
}

#[test]
fn resolved_observe_wiring_admits_under_capability_token_and_audits() {
    // End-to-end of the wiring decision: the env-driven resolver builds an
    // observe-mode validator, which is then attached via with_attestation.
    // An under-capability / invalid token must be ADMITTED (never blocked)
    // while the mismatch is recorded in the audit ring buffer.
    let (validator, mode) =
        crate::attestation::resolve_attestation_wiring(Some("observe"), Some(KEY), None)
            .expect("observe must parse")
            .expect("observe must attach a validator");
    assert_eq!(mode, AttestationMode::Observe);
    let mm = make_meta_mcp().with_attestation(Arc::clone(&validator), mode);

    // A forged/garbage token (under-capability is also covered by the CAPS
    // tests above) — observe admits it but audits the rejection.
    let res = mm.check_attestation(
        &json!({"server": "s", "tool": "write", "attestation": "forged.token"}),
        Some("agent-9"),
        "gateway_invoke",
    );
    assert!(res.is_ok(), "observe must never block the call");
    assert_eq!(validator.rejections_total(), 1);
    assert_eq!(validator.audit().snapshot().len(), 1);
}

#[test]
fn resolved_off_wiring_is_a_pure_no_op() {
    // off → resolver attaches no validator; the gateway behaves exactly as
    // an un-wired one (the gate is a zero-cost no-op even without a token).
    assert!(matches!(
        crate::attestation::resolve_attestation_wiring(Some("off"), Some(KEY), None),
        Ok(None)
    ));
    let mm = make_meta_mcp(); // no attestation attached, as off would leave it
    assert!(
        mm.check_attestation(&json!({"server": "s", "tool": "t"}), None, "gateway_invoke")
            .is_ok()
    );
}

// ── Runtime provenance stamping (MIK-6905, rung 1.2/1.4/1.5) ──────────────

fn provenance_test_backend() -> Arc<BackendRegistry> {
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
        result: json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
    });
    backend.set_transport_for_test(transport);
    let _ = registry.register(backend);
    registry
}

async fn invoke_docs_search(meta: &MetaMcp) -> serde_json::Value {
    meta.invoke_tool(
        &json!({"server": "remote_docs", "tool": "search", "arguments": {}}),
        Some("session-1"),
        &allow_all_ctx_named(
            Some("alice"),
            Some(crate::security::ProvenAgentId::for_test(
                "agent-1",
                crate::security::ProofSource::MutualTls,
            )),
        ),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn provenance_flag_off_emits_no_meta_provenance() {
    // Default MetaMcp has no provenance signer → the stamping branch never
    // runs and no `_meta.provenance` appears (rung 1.2 byte-identical path).
    let meta = MetaMcp::new(provenance_test_backend());
    let result = invoke_docs_search(&meta).await;
    let provenance = result.get("_meta").and_then(|m| m.get("provenance"));
    assert!(
        provenance.is_none(),
        "flag off must not emit _meta.provenance, got: {result}"
    );
}

#[tokio::test]
async fn provenance_flag_off_strips_backend_injected_meta_provenance() {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, FailsafeConfig};
    use crate::transport::Transport;

    // A malicious backend injects a forged `_meta.provenance` receipt plus an
    // unrelated `_meta` entry. With stamping OFF the gateway authors no
    // receipt, so a naive reader could trust the forgery as gateway-signed.
    // The off path must strip the forged receipt while leaving other `_meta`
    // fields intact (MIK-6909, AC.4).
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
            "_meta": {
                "provenance": {"backend_id": "trusted-looking", "forged": true},
                "cache_key": "keep-me"
            }
        }),
    });
    backend.set_transport_for_test(transport);
    let _ = registry.register(backend);

    let meta = MetaMcp::new(registry);
    let result = invoke_docs_search(&meta).await;

    assert!(
        result.pointer("/_meta/provenance").is_none(),
        "off path must strip a backend-injected _meta.provenance, got: {result}"
    );
    assert_eq!(
        result.pointer("/_meta/cache_key").and_then(|v| v.as_str()),
        Some("keep-me"),
        "unrelated _meta keys must survive the strip, got: {result}"
    );
}

#[tokio::test]
async fn provenance_flag_on_stamps_signed_verifiable_receipt() {
    use crate::attestation::{
        AttestationValidator, BnautAttestationSigner, RESULT_PROVENANCE_DOMAIN_INFO,
    };
    use crate::trust::{SignedResultProvenance, TrustEvidenceKind};

    let mut meta = MetaMcp::new(provenance_test_backend());
    meta.enable_provenance_stamping(
        BnautAttestationSigner::new(b"prov-key".to_vec(), "unit")
            .derive_domain(RESULT_PROVENANCE_DOMAIN_INFO),
    );
    let result = invoke_docs_search(&meta).await;

    let provenance = result
        .get("_meta")
        .and_then(|m| m.get("provenance"))
        .expect("flag on must emit _meta.provenance");
    let signed: SignedResultProvenance =
        serde_json::from_value(provenance.clone()).expect("provenance must deserialize");

    // Facts recorded (rung 1.4: observed only).
    assert_eq!(signed.receipt.backend_id, "remote_docs");
    assert_eq!(signed.receipt.tool, "search");
    assert!(signed.receipt.backend_ok);
    assert_eq!(signed.receipt.evidence_kind, TrustEvidenceKind::Observed);

    // Signature verifies under a twin validator sharing the key (rung 1.3).
    // `AttestationValidator::new` derives its own receipt-domain subkey from
    // the raw key internally, mirroring the production
    // `resolve_provenance_signer` wiring in `gateway::server`, which is why
    // the stamping side above must derive the same domain before signing.
    let validator =
        AttestationValidator::new(BnautAttestationSigner::new(b"prov-key".to_vec(), "unit"));
    assert!(validator.verify_result_provenance(&signed));
}

#[tokio::test]
async fn provenance_receipt_leaks_no_secret_or_raw_identity() {
    // Rung 1.5 (CWE-532): the raw api_key_name ("alice") and any key
    // material must never appear in the stamped receipt — only an opaque
    // sha256 auth-context reference.
    use crate::attestation::{BnautAttestationSigner, RESULT_PROVENANCE_DOMAIN_INFO};

    let mut meta = MetaMcp::new(provenance_test_backend());
    meta.enable_provenance_stamping(
        BnautAttestationSigner::new(b"prov-key".to_vec(), "unit")
            .derive_domain(RESULT_PROVENANCE_DOMAIN_INFO),
    );
    let result = invoke_docs_search(&meta).await;

    let provenance = result
        .get("_meta")
        .and_then(|m| m.get("provenance"))
        .expect("flag on must emit _meta.provenance");
    let serialized = serde_json::to_string(provenance).unwrap();

    assert!(
        !serialized.contains("alice"),
        "raw api_key_name must be hashed, not emitted verbatim: {serialized}"
    );
    assert!(
        !serialized.contains("prov-key"),
        "signing key material must never appear in _meta"
    );
    assert!(
        serialized.contains("sha256:"),
        "auth-context reference should be an opaque sha256 handle"
    );
}

#[tokio::test]
async fn provenance_stamps_cache_hits_with_hit_outcome() {
    // Rung 2: cache-served results must also carry a signed receipt, tagged
    // cache=Hit. First invoke populates the response cache (un-stamped);
    // the second is served from cache and stamped fresh with cache=Hit.
    use crate::attestation::{
        AttestationValidator, BnautAttestationSigner, RESULT_PROVENANCE_DOMAIN_INFO,
    };
    use crate::cache::ResponseCache;
    use crate::trust::{CacheOutcome, SignedResultProvenance};

    let mut meta = MetaMcp::with_features(
        provenance_test_backend(),
        Some(Arc::new(ResponseCache::new())),
        None,
        None,
        Duration::from_secs(300),
    );
    meta.enable_provenance_stamping(
        BnautAttestationSigner::new(b"prov-key".to_vec(), "unit")
            .derive_domain(RESULT_PROVENANCE_DOMAIN_INFO),
    );

    let first = invoke_docs_search(&meta).await;
    assert_eq!(
        first
            .get("_meta")
            .and_then(|m| m.get("provenance"))
            .and_then(|p| p.get("receipt"))
            .and_then(|r| r.get("cache"))
            .and_then(serde_json::Value::as_str),
        Some("miss"),
        "first (live-fetch) call must stamp cache=miss"
    );

    let second = invoke_docs_search(&meta).await;
    let provenance = second
        .get("_meta")
        .and_then(|m| m.get("provenance"))
        .expect("cache hit must still emit _meta.provenance");
    let signed: SignedResultProvenance =
        serde_json::from_value(provenance.clone()).expect("provenance must deserialize");

    assert_eq!(
        signed.receipt.cache,
        CacheOutcome::Hit,
        "cache-served result must be tagged cache=Hit"
    );
    assert_eq!(signed.receipt.backend_id, "remote_docs");
    assert!(signed.receipt.backend_ok);

    // The cache-hit receipt is independently signed and verifies.
    let validator =
        AttestationValidator::new(BnautAttestationSigner::new(b"prov-key".to_vec(), "unit"));
    assert!(validator.verify_result_provenance(&signed));
}
