//! Acceptance-criterion tests for MIK-5223 — RUNTIME-A: attestation token
//! injection at sandbox creation (B1-IDENT).
//!
//! Each test carries its acceptance criterion verbatim and asserts it in the
//! same polarity the AC states.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use chrono::{TimeDelta, Utc};
use uuid::Uuid;

use mcp_gateway::attestation::{
    ATTESTATION_FLAG_ENV, AttestationEnforcement, AttestationRejection, AttestationToken,
    AttestationValidator, AttestedSandboxLauncher, BNAUT_ISSUER, BnautAttestationSigner,
    BootDenial, SIGNING_ALGORITHM, SandboxLaunchSpec, Substrate, TOKEN_ENV_VAR, TokenRequest,
};

const KEY: &[u8] = b"mik-5223-integration-test-key";

fn signer() -> BnautAttestationSigner {
    BnautAttestationSigner::new(KEY.to_vec(), "integration")
}

fn validator() -> Arc<AttestationValidator> {
    Arc::new(AttestationValidator::with_settings(
        signer(),
        4096,
        TimeDelta::seconds(30),
    ))
}

fn launcher(validator: Arc<AttestationValidator>) -> AttestedSandboxLauncher {
    AttestedSandboxLauncher::new(validator, AttestationEnforcement::Enforced)
}

fn request() -> TokenRequest {
    TokenRequest {
        agent_identity: "agent-fleet-7".to_string(),
        task_uuid: Uuid::new_v4(),
        capabilities: vec!["tools:search".to_string(), "tools:read".to_string()],
    }
}

fn spec(substrate: Substrate) -> SandboxLaunchSpec {
    SandboxLaunchSpec {
        sandbox_id: format!("sb-{}", substrate.runtime_label()),
        substrate,
        env: HashMap::new(),
    }
}

/// MIK-NEW.RUNTIME-A.1 Sandbox boot fails closed without a valid attestation
/// token (no token = no start)
#[test]
fn ac_1_sandbox_boot_fails_closed_without_valid_token() {
    let v = validator();
    let l = launcher(Arc::clone(&v));
    let now = Utc::now();

    // No token = no start.
    let denied = l.boot(spec(Substrate::GvisorLinux), None, now);
    assert_eq!(denied.unwrap_err(), BootDenial::MissingToken);

    // An invalid (forged) token = no start either.
    let forged = {
        let other = BnautAttestationSigner::new(b"attacker-key".to_vec(), "evil");
        other.issue(&request(), now, TimeDelta::minutes(5))
    };
    let denied = l.boot(spec(Substrate::GvisorLinux), Some(forged.encoded()), now);
    assert_eq!(
        denied.unwrap_err(),
        BootDenial::InvalidToken(AttestationRejection::BadSignature)
    );

    // Fail-closed means zero sandboxes started.
    assert_eq!(l.boots_attested_total(), 0);

    // And a valid token = start.
    let token = signer().issue(&request(), now, TimeDelta::minutes(5));
    let handle = l
        .boot(spec(Substrate::GvisorLinux), Some(token.encoded()), now)
        .expect("valid token must boot");
    assert!(handle.attested);
    assert_eq!(l.boots_attested_total(), 1);
}

/// MIK-NEW.RUNTIME-A.2 Token carries: agent identity, task UUID, capability
/// allow-list, RFC-3339 expiration; signed by bnaut-attestation
#[test]
fn ac_2_token_carries_identity_task_capabilities_expiry_signed_by_bnaut() {
    let now = Utc::now();
    let req = request();
    let token = signer().issue(&req, now, TimeDelta::minutes(5));
    let claims = token.claims();

    // Agent identity.
    assert_eq!(claims.agent_identity, "agent-fleet-7");
    // Task UUID — parseable as a UUID.
    assert_eq!(
        Uuid::parse_str(&claims.task_uuid).expect("task_uuid must be a UUID"),
        req.task_uuid
    );
    // Capability allow-list.
    assert_eq!(claims.capabilities, vec!["tools:search", "tools:read"]);
    // RFC-3339 expiration, in the future relative to issuance.
    let expires = claims
        .expires_at_utc()
        .expect("expires_at must be RFC-3339");
    assert!(expires > now);

    // Signed by bnaut-attestation: issuer claim, bnaut-namespaced key id,
    // and a signature that verifies with bnaut key material.
    assert_eq!(claims.issuer, BNAUT_ISSUER);
    assert!(claims.key_id.starts_with("bnaut/"));
    let (payload, sig) = AttestationToken::split_unverified(token.encoded()).unwrap();
    assert!(signer().verify_bytes(&payload, &sig));
}

/// MIK-NEW.RUNTIME-A.3 Token validates against gateway on every
/// cross-boundary call; rejection logs to audit ring buffer
#[test]
fn ac_3_every_cross_boundary_call_validates_and_rejections_hit_ring_buffer() {
    let v = validator();
    let now = Utc::now();
    let token = signer().issue(&request(), now, TimeDelta::minutes(5));

    // Every cross-boundary call goes through the gateway validator.
    for boundary in ["gateway_invoke", "gateway_search", "backend_proxy"] {
        let claims = v
            .validate_boundary_call(Some(token.encoded()), boundary, now)
            .expect("valid token must pass on every boundary");
        assert_eq!(claims.token_id, token.claims().token_id);
    }
    assert_eq!(v.validations_total(), 3);
    assert!(v.audit().is_empty(), "no rejections for valid calls");

    // A rejected call logs to the audit ring buffer.
    let tampered = format!("{}x", token.encoded());
    let err = v
        .validate_boundary_call(Some(&tampered), "gateway_invoke", now)
        .unwrap_err();
    assert!(matches!(
        err,
        AttestationRejection::BadSignature | AttestationRejection::MalformedToken { .. }
    ));
    let records = v.audit().snapshot();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].boundary, "gateway_invoke");
    assert_eq!(v.rejections_total(), 1);
}

/// MIK-NEW.RUNTIME-A.4 Token rotation on long-running tasks; rotation does
/// not disrupt in-flight syscalls
#[test]
fn ac_4_rotation_does_not_disrupt_in_flight_syscalls() {
    let v = validator();
    let now = Utc::now();
    let original = signer().issue(&request(), now, TimeDelta::hours(8));

    // Long-running task rotates its token mid-flight.
    let successor = v.rotate(original.claims(), now, TimeDelta::hours(8));
    assert_eq!(
        successor.claims().rotation_of.as_deref(),
        Some(original.claims().token_id.as_str())
    );

    // An in-flight syscall still carrying the predecessor token is NOT
    // disrupted: it validates inside the grace window.
    let in_flight = now + TimeDelta::seconds(5);
    v.validate_boundary_call(Some(original.encoded()), "syscall", in_flight)
        .expect("in-flight syscall with predecessor token must not be disrupted");

    // The successor validates too, on the same path.
    v.validate_boundary_call(Some(successor.encoded()), "syscall", in_flight)
        .expect("successor token must validate");

    // After the grace window closes, the predecessor is rejected.
    let after_grace = now + TimeDelta::seconds(31);
    let err = v
        .validate_boundary_call(Some(original.encoded()), "syscall", after_grace)
        .unwrap_err();
    assert!(matches!(err, AttestationRejection::RotatedOut { .. }));
    assert_eq!(v.rotations_total(), 1);
}

/// MIK-NEW.RUNTIME-A.5 Test: token forgery attempt detected and logged within
/// 100ms; ≥100 forgery test cases pass
#[test]
fn ac_5_forgery_detected_and_logged_within_100ms_over_100_cases() {
    let v = validator();
    let now = Utc::now();
    let genuine = signer().issue(&request(), now, TimeDelta::minutes(5));
    let attacker = BnautAttestationSigner::new(b"attacker-key".to_vec(), "evil");

    let mut forgeries: Vec<String> = Vec::new();
    // 40 cases: tokens signed by an attacker key with escalating capabilities.
    for i in 0..40 {
        let t = attacker.issue(
            &TokenRequest {
                agent_identity: format!("impostor-{i}"),
                task_uuid: Uuid::new_v4(),
                capabilities: vec!["tools:*".to_string()],
            },
            now,
            TimeDelta::minutes(5),
        );
        forgeries.push(t.encoded().to_string());
    }
    // 40 cases: genuine token with a tampered payload byte (claim mutation).
    let (payload, sig) = AttestationToken::split_unverified(genuine.encoded()).unwrap();
    for i in 0..40 {
        let mut mutated = payload.clone();
        let idx = (i * 7) % mutated.len();
        mutated[idx] ^= 0x01;
        forgeries.push(
            AttestationToken::from_parts(genuine.claims().clone(), &mutated, &sig)
                .encoded()
                .to_string(),
        );
    }
    // 20 cases: signature bit-flips on the genuine payload.
    for i in 0..20 {
        let mut bad_sig = sig.clone();
        let idx = i % bad_sig.len();
        bad_sig[idx] ^= 0x80;
        forgeries.push(
            AttestationToken::from_parts(genuine.claims().clone(), &payload, &bad_sig)
                .encoded()
                .to_string(),
        );
    }
    // 10 cases: structurally mangled tokens.
    for i in 0..10 {
        forgeries.push(format!("garbage-{i}-no-separator"));
    }
    assert!(forgeries.len() >= 100, "≥100 forgery test cases required");

    let before = v.audit().total_pushed();
    for (i, forged) in forgeries.iter().enumerate() {
        let started = Instant::now();
        let result = v.validate_boundary_call(Some(forged), "forgery_probe", now);
        let elapsed = started.elapsed();
        assert!(result.is_err(), "forgery case {i} must be detected");
        assert!(
            elapsed.as_millis() < 100,
            "forgery case {i} detection took {elapsed:?} (>100ms)"
        );
    }
    // Every forgery attempt was logged with its detection latency.
    assert_eq!(
        v.audit().total_pushed() - before,
        u64::try_from(forgeries.len()).expect("forgery count fits u64"),
        "every forgery must be logged to the audit ring buffer"
    );
    for record in v.audit().snapshot() {
        assert!(
            record.detection_micros < 100_000,
            "logged detection within 100ms"
        );
    }
}

/// MIK-NEW.RUNTIME-A.6 Both substrates (gVisor on Ubuntu + Apple
/// containerization on macOS) exercise the identical token flow
#[test]
fn ac_6_both_substrates_exercise_identical_token_flow() {
    let v = validator();
    let l = launcher(Arc::clone(&v));
    let now = Utc::now();
    let token = signer().issue(&request(), now, TimeDelta::minutes(5));

    let gvisor = l
        .boot(spec(Substrate::GvisorLinux), Some(token.encoded()), now)
        .expect("gVisor boot");
    let apple = l
        .boot(
            spec(Substrate::AppleContainerization),
            Some(token.encoded()),
            now,
        )
        .expect("Apple containerization boot");

    // The token flow — required, verified, validated, injected at the OCI
    // createRuntime hook, started — is identical on both substrates.
    assert_eq!(gvisor.flow_trace, apple.flow_trace);
    assert_eq!(
        gvisor.flow_trace,
        vec![
            "token_required",
            "token_signature_verified",
            "claims_validated",
            "oci_create_runtime_hook_token_injected",
            "sandbox_started",
        ]
    );
    // Same injection hook, same env var, same token bytes.
    assert_eq!(
        Substrate::GvisorLinux.token_injection_hook(),
        Substrate::AppleContainerization.token_injection_hook()
    );
    assert_eq!(gvisor.env.get(TOKEN_ENV_VAR), apple.env.get(TOKEN_ENV_VAR));
}

/// B1-IDENT: AC.1 IS the bet — direct delivery via bnaut-attestation
#[test]
fn ac_7_b1_ident_every_token_and_audit_record_uniquely_attributable() {
    let v = validator();
    let now = Utc::now();

    // Every issued token is uniquely attributable: distinct token_id (UUID).
    let a = signer().issue(&request(), now, TimeDelta::minutes(5));
    let b = signer().issue(&request(), now, TimeDelta::minutes(5));
    assert_ne!(a.claims().token_id, b.claims().token_id);
    assert!(Uuid::parse_str(&a.claims().token_id).is_ok());

    // Every audit record is uniquely attributable: monotonic seq numbers.
    for _ in 0..3 {
        let _ = v.validate_boundary_call(None, "probe", now);
    }
    let seqs: Vec<u64> = v.audit().snapshot().iter().map(|r| r.seq).collect();
    assert_eq!(seqs, vec![0, 1, 2]);

    // Telemetry distinguishable from pre-existing signals: dedicated
    // counters, not folded into existing gateway metrics.
    assert_eq!(v.rejections_total(), 3);
    assert_eq!(v.validations_total(), 0);
}

/// B2-MEM: N/A (downstream RUNTIME-B consumes the token for bridge auth)
#[test]
fn ac_8_b2_mem_na_token_consumable_downstream() {
    // B2-MEM is explicitly N/A for this ticket; what RUNTIME-B needs is a
    // token that round-trips its wire encoding for bridge auth. Verify that.
    let now = Utc::now();
    let token = signer().issue(&request(), now, TimeDelta::minutes(5));
    let v = validator();
    let claims = v
        .validate_boundary_call(Some(token.encoded()), "runtime_b_bridge", now)
        .expect("downstream consumer must be able to validate the token");
    assert_eq!(&claims, token.claims());
}

/// B3-DURABLE: token rotation persists across checkpoint (AC.4) ties to
/// RUNTIME-C
#[test]
fn ac_9_b3_durable_rotation_state_persists_across_checkpoint() {
    let v = validator();
    let now = Utc::now();
    let original = signer().issue(&request(), now, TimeDelta::hours(8));
    let successor = v.rotate(original.claims(), now, TimeDelta::hours(8));

    // Checkpoint, serialize, restore into a fresh validator (new process).
    let serialized = serde_json::to_string(&v.checkpoint()).unwrap();
    let restored: mcp_gateway::attestation::RotationCheckpoint =
        serde_json::from_str(&serialized).unwrap();
    let fresh = validator();
    fresh.restore(&restored);

    // Grace window honored after restore: in-flight predecessor still valid…
    let in_flight = now + TimeDelta::seconds(5);
    fresh
        .validate_boundary_call(Some(original.encoded()), "syscall", in_flight)
        .expect("grace window must survive checkpoint/restore");
    // …and post-grace rejection also survives the checkpoint.
    let after_grace = now + TimeDelta::seconds(31);
    let err = fresh
        .validate_boundary_call(Some(original.encoded()), "syscall", after_grace)
        .unwrap_err();
    assert!(matches!(err, AttestationRejection::RotatedOut { .. }));
    // The successor is unaffected.
    fresh
        .validate_boundary_call(Some(successor.encoded()), "syscall", after_grace)
        .expect("successor valid after restore");
}

/// B4-PLATFORM: reuses bnaut-attestation; no bespoke crypto
#[test]
fn ac_10_b4_platform_bnaut_issuer_standard_hmac_sha256() {
    let now = Utc::now();
    let token = signer().issue(&request(), now, TimeDelta::minutes(5));
    // Issued by the bnaut-attestation platform component…
    assert_eq!(token.claims().issuer, BNAUT_ISSUER);
    assert_eq!(BNAUT_ISSUER, "bnaut-attestation");
    // …using a standard algorithm (HMAC-SHA256 via RustCrypto), not bespoke
    // crypto: algorithm identifier is HS256 and the MAC is 32 bytes.
    assert_eq!(token.claims().algorithm, SIGNING_ALGORITHM);
    assert_eq!(SIGNING_ALGORITHM, "HS256");
    let (_, sig) = AttestationToken::split_unverified(token.encoded()).unwrap();
    assert_eq!(sig.len(), 32, "SHA-256 MAC output");
}

/// AC.deploy: Diff merged to `main` and deployed to prod by the deploy cron;
/// 30 min post-deploy telemetry confirms the change is active.
///
/// Merge + deploy are orchestrator-owned and cannot execute inside this test;
/// the in-repo deployable contract verified here is the rollback flag the
/// deploy relies on: `SYMPHONY_PLUS_ATTESTATION=0` boots without a token,
/// every other value (including unset, the prod default) enforces fail-closed.
#[test]
fn ac_11_deploy_rollback_flag_contract_holds() {
    // Flag semantics (pure, no process-global env mutation).
    assert_eq!(
        AttestationEnforcement::from_flag(Some("0")),
        AttestationEnforcement::BypassedByFlag
    );
    assert_eq!(
        AttestationEnforcement::from_flag(None),
        AttestationEnforcement::Enforced
    );
    assert_eq!(ATTESTATION_FLAG_ENV, "SYMPHONY_PLUS_ATTESTATION");

    // Rollback path: flag=0 boots without a token — still isolated, loses
    // identity attribution — and is counted on its own bypass counter.
    let l = AttestedSandboxLauncher::new(validator(), AttestationEnforcement::from_flag(Some("0")));
    let handle = l
        .boot(spec(Substrate::GvisorLinux), None, Utc::now())
        .expect("rollback flag must allow tokenless boot");
    assert!(!handle.attested);
    assert_eq!(l.boots_bypassed_total(), 1);
}
