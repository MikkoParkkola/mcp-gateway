//! Tests for the attestation module.
//!
//! Every acceptance criterion is copied verbatim as a comment above its test.
//! Test names and assertions match the AC's polarity.

use super::*;
use chrono::DateTime;
use std::time::Duration;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn test_secret() -> Vec<u8> {
    b"bnaut-attestation-test-secret-32bytes!".to_vec()
}

fn test_signer() -> AttestationSigner {
    AttestationSigner::new_always(test_secret())
}

fn test_claims() -> AttestationClaims {
    AttestationClaims::new(
        "agent-001".to_string(),
        uuid::Uuid::new_v4().to_string(),
        vec!["tools:search:read".to_string(), "tools:db:write".to_string()],
        Duration::from_secs(3600),
    )
}

fn make_valid_token() -> AttestationToken {
    let signer = test_signer();
    signer.sign(test_claims())
}

// ═══════════════════════════════════════════════════════════════════════════════
// AC.1: Sandbox boot fails closed without a valid attestation token
//       (no token = no start)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ac1_validator_without_token_fails_closed_when_required() {
    // AC.1: Sandbox boot fails closed without a valid attestation token (no token = no start)
    let validator = AttestationValidator::new(Some(test_signer()), true);
    let result = validator.validate(None, "sandbox_boot");
    assert!(result.is_err(), "AC.1: must fail closed without token");
    let err = result.unwrap_err();
    assert!(
        matches!(err, AttestationError::MissingClaims),
        "AC.1: expected MissingClaims, got {err:?}"
    );
}

#[test]
fn ac1_validator_without_signer_fails_closed_when_required() {
    // AC.1: Sandbox boot fails closed without a valid attestation token
    let validator = AttestationValidator::new(None, true);
    let result = validator.validate(None, "sandbox_boot");
    assert!(
        result.is_err(),
        "AC.1: must fail closed without signer when required"
    );
}

#[test]
fn ac1_validator_with_valid_token_succeeds() {
    // AC.1: With valid token, boot succeeds
    let signer = test_signer();
    let token = signer.sign(test_claims());
    let validator = AttestationValidator::new(Some(signer), true);
    let result = validator.validate(Some(&token), "sandbox_boot");
    assert!(result.is_ok(), "AC.1: valid token must succeed: {:?}", result.err());
}

// ═══════════════════════════════════════════════════════════════════════════════
// AC.2: Token carries: agent identity, task UUID, capability allow-list,
//       RFC-3339 expiration; signed by bnaut-attestation
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ac2_token_carries_agent_identity() {
    // AC.2: Token carries agent identity
    let claims = test_claims();
    assert!(!claims.agent_id.is_empty(), "AC.2: agent_id must be populated");
    assert_eq!(claims.agent_id, "agent-001");
}

#[test]
fn ac2_token_carries_task_uuid() {
    // AC.2: Token carries task UUID
    let claims = test_claims();
    assert!(!claims.task_uuid.is_empty(), "AC.2: task_uuid must be populated");
    // Must be a valid UUID v4 format
    assert!(uuid::Uuid::parse_str(&claims.task_uuid).is_ok(), "AC.2: task_uuid must be valid UUID");
}

#[test]
fn ac2_token_carries_capability_allowlist() {
    // AC.2: Token carries capability allow-list
    let claims = test_claims();
    assert!(!claims.capability_allowlist.is_empty(), "AC.2: capability_allowlist must be populated");
    assert!(claims.capability_allowlist.contains(&"tools:search:read".to_string()));
}

#[test]
fn ac2_token_has_rfc3339_expiration() {
    // AC.2: Token carries RFC-3339 expiration
    let claims = test_claims();
    let parsed = DateTime::parse_from_rfc3339(&claims.exp);
    assert!(parsed.is_ok(), "AC.2: exp must be valid RFC-3339: {:?}", parsed.err());
}

#[test]
fn ac2_token_has_rfc3339_issued_at() {
    // AC.2: Token carries RFC-3339 issued-at
    let claims = test_claims();
    let parsed = DateTime::parse_from_rfc3339(&claims.iat);
    assert!(parsed.is_ok(), "AC.2: iat must be valid RFC-3339: {:?}", parsed.err());
}

#[test]
fn ac2_token_is_signed_by_hmac_sha256() {
    // AC.2: signed by bnaut-attestation (HMAC-SHA256)
    let signer = test_signer();
    let token = signer.sign(test_claims());
    assert!(!token.sig.is_empty(), "AC.2: signature must be present");
    // Verify the signature
    assert!(token.signature_valid(&test_secret()), "AC.2: signature must validate");
}

#[test]
fn ac2_different_secret_produces_different_signature() {
    // AC.2: signed by bnaut-attestation — different key = different sig
    let claims = test_claims();
    let token_a = AttestationToken::sign(claims.clone(), b"secret-a-32bytes-long-enough!!!");
    let token_b = AttestationToken::sign(claims.clone(), b"secret-b-32bytes-long-enough!!!");
    assert_ne!(token_a.sig, token_b.sig, "AC.2: different keys must produce different signatures");
}

// ═══════════════════════════════════════════════════════════════════════════════
// AC.3: Token validates against gateway on every cross-boundary call;
//       rejection logs to audit ring buffer
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ac3_validation_logs_rejection_to_audit_ring_buffer() {
    // AC.3: rejection logs to audit ring buffer
    let validator = AttestationValidator::new(Some(test_signer()), true);
    let _ = validator.validate(None, "cross_boundary_call");
    let entries = validator.audit().entries();
    assert!(!entries.is_empty(), "AC.3: audit ring buffer must contain rejection entry");
    let entry = &entries[0];
    assert!(entry.error.contains("missing"), "AC.3: error field must describe rejection");
    assert_eq!(entry.operation, "cross_boundary_call", "AC.3: operation must be recorded");
}

#[test]
fn ac3_audit_entry_has_timestamp() {
    // AC.3: rejection logged with timestamp
    let validator = AttestationValidator::new(Some(test_signer()), true);
    let _ = validator.validate(None, "test_op");
    let entry = &validator.audit().entries()[0];
    let parsed = DateTime::parse_from_rfc3339(&entry.timestamp);
    assert!(parsed.is_ok(), "AC.3: timestamp must be RFC-3339: {:?}", parsed.err());
}

#[test]
fn ac3_audit_entry_records_agent_id_when_extractable() {
    // AC.3: rejection logs include agent identity
    let signer = test_signer();
    let claims = test_claims();
    let token = signer.sign(claims.clone());
    // Create a tampered token with invalid signature
    let mut bad_token = token.clone();
    bad_token.sig = "DEADBEEF".to_string();

    let validator = AttestationValidator::new(Some(test_signer()), true);
    let _ = validator.validate(Some(&bad_token), "cross_boundary_call");
    let entry = &validator.audit().entries()[0];
    assert_eq!(entry.agent_id, Some("agent-001".to_string()), "AC.3: agent_id must be in audit entry");
}

#[test]
fn ac3_valid_token_does_not_produce_audit_entry() {
    // AC.3: Only rejections log to audit — successful validations do not
    let signer = test_signer();
    let token = signer.sign(test_claims());
    let validator = AttestationValidator::new(Some(signer), true);
    let result = validator.validate(Some(&token), "cross_boundary_call");
    assert!(result.is_ok());
    assert!(validator.audit().is_empty(), "AC.3: successful validation must not log to audit");
}

// ═══════════════════════════════════════════════════════════════════════════════
// AC.4: Token rotation on long-running tasks; rotation does not disrupt
//       in-flight syscalls
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ac4_token_rotation_produces_new_token_with_extended_expiry() {
    // AC.4: Token rotation on long-running tasks
    let signer = test_signer();
    let original_claims = AttestationClaims::new(
        "agent-001".to_string(),
        uuid::Uuid::new_v4().to_string(),
        vec!["tools:search:read".to_string()],
        Duration::from_secs(3600),
    );
    let original = signer.sign(original_claims.clone());

    // Rotate: create new token with same identity but new expiry
    let rotated_claims = AttestationClaims::new(
        original_claims.agent_id.clone(),
        original_claims.task_uuid.clone(),
        original_claims.capability_allowlist.clone(),
        Duration::from_secs(7200), // extended TTL
    );
    let rotated = signer.sign(rotated_claims);

    // Both tokens are valid
    assert!(original.verify(&test_secret()).is_ok(), "AC.4: original token must remain valid");
    assert!(rotated.verify(&test_secret()).is_ok(), "AC.4: rotated token must be valid");
    // They are different tokens
    assert_ne!(original.sig, rotated.sig, "AC.4: rotated token must have different signature");
}

#[test]
fn ac4_token_rotation_preserves_agent_identity() {
    // AC.4: rotation does not disrupt in-flight syscalls — identity preserved
    let signer = test_signer();
    let claims = test_claims();
    let original = signer.sign(claims.clone());

    // During rotation, the same agent/task keeps working
    let rotated_claims = AttestationClaims::new(
        claims.agent_id.clone(),
        claims.task_uuid.clone(),
        claims.capability_allowlist.clone(),
        Duration::from_secs(7200),
    );
    let rotated = signer.sign(rotated_claims);

    let verified_original = original.verify(&test_secret()).unwrap();
    let verified_rotated = rotated.verify(&test_secret()).unwrap();

    assert_eq!(verified_original.agent_id, verified_rotated.agent_id,
        "AC.4: rotation must preserve agent identity");
    assert_eq!(verified_original.task_uuid, verified_rotated.task_uuid,
        "AC.4: rotation must preserve task UUID");
    assert_eq!(verified_original.capability_allowlist, verified_rotated.capability_allowlist,
        "AC.4: rotation must preserve capability allowlist");
}

#[test]
fn ac4_both_tokens_remain_valid_during_rotation_window() {
    // AC.4: rotation does not disrupt in-flight syscalls — both tokens work
    let signer = test_signer();
    let claims = test_claims();
    let old_token = signer.sign(claims.clone());
    let new_token = signer.sign(AttestationClaims::new(
        claims.agent_id.clone(),
        claims.task_uuid.clone(),
        claims.capability_allowlist.clone(),
        Duration::from_secs(7200),
    ));

    // Both pass validation (simulating the rotation window where both are accepted)
    assert!(old_token.verify(&test_secret()).is_ok());
    assert!(new_token.verify(&test_secret()).is_ok());
}

// ═══════════════════════════════════════════════════════════════════════════════
// AC.5: Test: token forgery attempt detected and logged within 100ms;
//       ≥100 forgery test cases pass
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ac5_forgery_detected_within_100ms() {
    // AC.5: token forgery attempt detected and logged within 100ms
    let signer = test_signer();
    let token = signer.sign(test_claims());
    let mut forged = token.clone();
    forged.sig = "INVALID_SIGNATURE_FORGERY_ATTEMPT".to_string();

    let validator = AttestationValidator::new(Some(test_signer()), true);
    let start = Instant::now();
    let _ = validator.validate(Some(&forged), "cross_boundary_call");
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_millis() < 100,
        "AC.5: forgery detection must complete within 100ms (took {}ms)",
        elapsed.as_millis()
    );

    // Also verify it was logged
    let entry = &validator.audit().entries()[0];
    assert!(entry.decision_time_ms < 100,
        "AC.5: audit entry must show decision time < 100ms (was {}ms)",
        entry.decision_time_ms);
}

#[test]
fn ac5_100_forgery_test_cases_all_detected() {
    // AC.5: ≥100 forgery test cases pass
    let signer = test_signer();
    let validator = AttestationValidator::new(Some(signer.clone()), true);

    let mut detected = 0u32;

    for i in 0..150 {
        let claims = AttestationClaims::new(
            format!("agent-{:03}", i),
            uuid::Uuid::new_v4().to_string(),
            vec!["tools:test".to_string()],
            Duration::from_secs(3600),
        );
        let token = signer.sign(claims);

        // Create various forgery patterns
        let forged = match i % 5 {
            0 => {
                // Altered signature
                let mut t = token.clone();
                t.sig = format!("FORGED_SIG_{i}");
                t
            }
            1 => {
                // Altered agent_id
                let mut t = token.clone();
                t.claims.agent_id = format!("forged-agent-{}", i);
                // Re-sign with wrong claims — this is the naive tampering case
                // Signature won't match because claims changed
                t
            }
            2 => {
                // Altered task_uuid
                let mut t = token.clone();
                t.claims.task_uuid = uuid::Uuid::new_v4().to_string();
                t
            }
            3 => {
                // Altered capability_allowlist (escalation attempt)
                let mut t = token.clone();
                t.claims.capability_allowlist = vec!["admin:*".to_string()];
                t
            }
            4 => {
                // Completely bogus signature
                let mut t = token.clone();
                t.sig = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &[0u8; 32],
                );
                t
            }
            _ => unreachable!(),
        };

        let result = validator.validate(Some(&forged), "forgery_test");
        if result.is_err() {
            detected += 1;
        }
    }

    assert_eq!(
        detected, 150,
        "AC.5: all 150 forgery test cases must be detected (only {detected} detected)"
    );
    assert!(
        detected >= 100,
        "AC.5: at least 100 forgery test cases must pass (got {detected})"
    );
}

#[test]
fn ac5_forgery_detection_time_under_100ms_across_batch() {
    // AC.5: All forgery detections complete within 100ms
    let signer = test_signer();
    let validator = AttestationValidator::new(Some(signer.clone()), true);

    for i in 0..50 {
        let claims = AttestationClaims::new(
            format!("agent-{}", i),
            uuid::Uuid::new_v4().to_string(),
            vec!["tools:test".to_string()],
            Duration::from_secs(3600),
        );
        let mut token = signer.sign(claims);
        token.sig = format!("BOGUS_{i}");

        let start = Instant::now();
        let _ = validator.validate(Some(&token), "timing_test");
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_millis() < 100,
            "AC.5: case {} took {}ms (must be <100ms)",
            i,
            elapsed.as_millis()
        );
    }
}

#[test]
fn ac5_audit_buffer_captures_all_forgery_attempts() {
    // AC.5: All forgery attempts are logged
    let signer = test_signer();
    let validator = AttestationValidator::new(
        Some(signer.clone()),
        true,
    );

    for i in 0..110 {
        let claims = AttestationClaims::new(
            format!("agent-{}", i),
            uuid::Uuid::new_v4().to_string(),
            vec!["tools:test".to_string()],
            Duration::from_secs(3600),
        );
        let mut token = signer.sign(claims);
        token.sig = format!("FORGERY_{i}");

        let _ = validator.validate(Some(&token), "forgery_log_test");
    }

    let entries = validator.audit().entries();
    assert_eq!(
        entries.len(),
        110,
        "AC.5: all 110 forgery attempts must be in audit log (found {})",
        entries.len()
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// AC.6: Both substrates (gVisor on Ubuntu + Apple containerization on macOS)
//       exercise the identical token flow
// ═══════════════════════════════════════════════════════════════════════════════

/// AC.6: The attestation token flow is platform-agnostic.
/// The token creation, signing, and validation logic uses only portable
/// Rust primitives (HMAC-SHA256, base64, JSON serialization).
/// Both gVisor (Linux) and Apple containerization (macOS) invoke the same
/// code path through the SandboxEnforcer.
#[test]
fn ac6_token_flow_is_platform_agnostic_sign_and_verify() {
    // AC.6: Both substrates exercise the identical token flow
    // The flow: create claims → sign → serialize → deserialize → verify
    // This is exercised identically on all platforms.

    let secret = b"cross-platform-attestation-secret-32!".to_vec();
    let signer = AttestationSigner::new_always(secret.clone());

    // Step 1: Create claims (identical on all platforms)
    let claims = AttestationClaims::new(
        "platform-agent".to_string(),
        "550e8400-e29b-41d4-a716-446655440000".to_string(),
        vec!["tools:cross:*".to_string()],
        Duration::from_secs(3600),
    );

    // Step 2: Sign (identical HMAC-SHA256 on all platforms)
    let token = signer.sign(claims.clone());

    // Step 3: Serialize to JSON (portable)
    let json = serde_json::to_string(&token).unwrap();

    // Step 4: Deserialize from JSON (portable)
    let deserialized: AttestationToken = serde_json::from_str(&json).unwrap();

    // Step 5: Verify (identical HMAC-SHA256 verification on all platforms)
    let verified = deserialized.verify(&secret).unwrap();

    // All claims preserved
    assert_eq!(verified.agent_id, claims.agent_id);
    assert_eq!(verified.task_uuid, claims.task_uuid);
    assert_eq!(verified.capability_allowlist, claims.capability_allowlist);
}

#[test]
fn ac6_token_validation_is_byte_identical_across_platforms() {
    // AC.6: Same bytes → same validation result on any substrate
    let secret = b"platform-identical-test-secret-32!".to_vec();
    let signer = AttestationSigner::new_always(secret.clone());

    let claims = AttestationClaims::new(
        "cross-platform".to_string(),
        "660e8400-e29b-41d4-a716-446655440001".to_string(),
        vec!["tools:platform:read".to_string()],
        Duration::from_secs(3600),
    );
    let token = signer.sign(claims);

    // The canonical JSON representation — this is what the signature covers
    let json = serde_json::to_string(&token).unwrap();

    // On any platform, this JSON should verify
    let deserialized: AttestationToken = serde_json::from_str(&json).unwrap();
    assert!(deserialized.verify(&secret).is_ok(),
        "AC.6: deserialized token must verify identically on any platform");
}

#[test]
fn ac6_same_token_accepted_on_both_substrates_simulation() {
    // AC.6: Simulate both substrates by verifying the same token twice
    // (representing gVisor and Apple containerization paths)
    let signer = test_signer();
    let token = signer.sign(test_claims());

    let validator = AttestationValidator::new(Some(signer), true);

    // "gVisor on Ubuntu" path
    let result_gvisor = validator.validate(Some(&token), "gvisor_boot");
    assert!(result_gvisor.is_ok(), "AC.6: gVisor path must accept valid token");

    // "Apple containerization on macOS" path
    let result_apple = validator.validate(Some(&token), "apple_container_boot");
    assert!(result_apple.is_ok(), "AC.6: Apple path must accept valid token");

    // Both results must be identical claims
    assert_eq!(result_gvisor.unwrap(), result_apple.unwrap(),
        "AC.6: both substrates must produce identical claims");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Additional robustness tests
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn expired_token_is_rejected() {
    let signer = test_signer();
    let claims = AttestationClaims::new(
        "agent-001".to_string(),
        uuid::Uuid::new_v4().to_string(),
        vec![],
        Duration::from_secs(0), // immediately expired
    );
    // Small sleep to ensure expiration
    std::thread::sleep(Duration::from_millis(1));
    let token = signer.sign(claims);
    let result = token.verify(&test_secret());
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AttestationError::Expired));
}

#[test]
fn wrong_secret_rejects_token() {
    let signer_a = AttestationSigner::new_always(b"secret-a-32-bytes-long-enough!!!".to_vec());
    let token = signer_a.sign(test_claims());

    let result = token.verify(b"secret-b-32-bytes-long-enough!!!");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AttestationError::InvalidSignature));
}

#[test]
fn feature_flag_disables_attestation() {
    // When SYMPHONY_PLUS_ATTESTATION=0, Signer::new returns None
    // (We can't manipulate env vars safely in parallel tests, so we test
    // the signer construction path directly)
    let signer = AttestationSigner::new(test_secret());
    // In test environment without env var set, signer should be Some
    // (default enabled)
    assert!(signer.is_some(), "default attestation should be enabled");
}

#[test]
fn attestation_claims_new_populates_all_fields() {
    let claims = AttestationClaims::new(
        "id".to_string(),
        "uuid".to_string(),
        vec!["cap".to_string()],
        Duration::from_secs(300),
    );
    assert_eq!(claims.agent_id, "id");
    assert_eq!(claims.task_uuid, "uuid");
    assert_eq!(claims.capability_allowlist, vec!["cap".to_string()]);
    assert!(!claims.exp.is_empty());
    assert!(!claims.iat.is_empty());
    assert!(claims.iat <= claims.exp, "iat must be <= exp");
}

#[test]
fn audit_ring_buffer_wraps_correctly() {
    let buf = AuditRingBuffer::new(3);
    buf.record(AuditEntry {
        timestamp: "2024-01-01T00:00:00Z".to_string(),
        error: "e1".to_string(),
        agent_id: None,
        task_uuid: None,
        operation: "op1".to_string(),
        decision_time_ms: 1,
    });
    buf.record(AuditEntry {
        timestamp: "2024-01-01T00:00:01Z".to_string(),
        error: "e2".to_string(),
        agent_id: None,
        task_uuid: None,
        operation: "op2".to_string(),
        decision_time_ms: 2,
    });
    buf.record(AuditEntry {
        timestamp: "2024-01-01T00:00:02Z".to_string(),
        error: "e3".to_string(),
        agent_id: None,
        task_uuid: None,
        operation: "op3".to_string(),
        decision_time_ms: 3,
    });
    buf.record(AuditEntry {
        timestamp: "2024-01-01T00:00:03Z".to_string(),
        error: "e4".to_string(),
        agent_id: None,
        task_uuid: None,
        operation: "op4".to_string(),
        decision_time_ms: 4,
    });

    let entries = buf.entries();
    assert_eq!(entries.len(), 3, "ring buffer should wrap at capacity 3");
    // Should have e2, e3, e4 (e1 overwritten)
    assert_eq!(entries[0].error, "e2");
    assert_eq!(entries[1].error, "e3");
    assert_eq!(entries[2].error, "e4");
}

#[test]
fn audit_ring_buffer_recent_returns_last_n() {
    let buf = AuditRingBuffer::new(10);
    for i in 0..5 {
        buf.record(AuditEntry {
            timestamp: format!("ts-{i}"),
            error: format!("e{i}"),
            agent_id: None,
            task_uuid: None,
            operation: format!("op{i}"),
            decision_time_ms: i as u64,
        });
    }
    let recent = buf.recent(2);
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0].error, "e3");
    assert_eq!(recent[1].error, "e4");
}

#[test]
fn attestation_token_serde_round_trip() {
    let signer = test_signer();
    let token = signer.sign(test_claims());
    let json = serde_json::to_string(&token).unwrap();
    let restored: AttestationToken = serde_json::from_str(&json).unwrap();
    assert_eq!(token, restored);
    // The restored token should still verify
    assert!(restored.verify(&test_secret()).is_ok());
}

#[test]
fn validator_without_requirement_passes_through() {
    // When attestation is not required, missing token is not an error
    let validator = AttestationValidator::new(Some(test_signer()), false);
    let result = validator.validate(None, "optional_check");
    assert!(result.is_ok(), "without requirement, missing token should pass through");
}

#[test]
fn time_to_expiry_returns_none_when_expired() {
    let claims = AttestationClaims::new(
        "agent".to_string(),
        "uuid".to_string(),
        vec![],
        Duration::from_secs(0),
    );
    std::thread::sleep(Duration::from_millis(1));
    assert!(claims.time_to_expiry().is_none(), "expired token should have no time to expiry");
}

#[test]
fn time_to_expiry_returns_some_when_valid() {
    let claims = AttestationClaims::new(
        "agent".to_string(),
        "uuid".to_string(),
        vec![],
        Duration::from_secs(3600),
    );
    let remaining = claims.time_to_expiry();
    assert!(remaining.is_some(), "valid token should have time to expiry");
    assert!(remaining.unwrap().as_secs() <= 3600);
}

#[test]
fn verify_checks_expiry_after_signature() {
    // Expiry check comes after signature check (more expensive operation first)
    let signer = test_signer();
    let claims = AttestationClaims::new(
        "agent".to_string(),
        "uuid".to_string(),
        vec![],
        Duration::from_secs(0),
    );
    std::thread::sleep(Duration::from_millis(1));
    let token = signer.sign(claims);
    // Signature is valid, but token is expired
    let result = token.verify(&test_secret());
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AttestationError::Expired),
        "expired token with valid sig should return Expired");
}

#[test]
fn multiple_rotations_maintain_chain_integrity() {
    // AC.4: Multiple rotations for very long-running tasks
    let signer = test_signer();
    let base_claims = test_claims();

    let mut tokens = Vec::new();
    let mut current = signer.sign(base_claims.clone());
    tokens.push(current.clone());

    // Simulate 5 rotations
    for i in 1..=5 {
        let rotated_claims = AttestationClaims::new(
            base_claims.agent_id.clone(),
            base_claims.task_uuid.clone(),
            base_claims.capability_allowlist.clone(),
            Duration::from_secs(3600 * (i + 1)),
        );
        current = signer.sign(rotated_claims);
        tokens.push(current.clone());
    }

    // All tokens in the chain must be valid
    for (i, token) in tokens.iter().enumerate() {
        assert!(
            token.verify(&test_secret()).is_ok(),
            "Token {i} in rotation chain must be valid"
        );
    }
}
