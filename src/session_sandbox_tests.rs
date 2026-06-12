use super::*;

// ── helpers ───────────────────────────────────────────────────────────────

fn unlimited() -> SessionSandbox {
    SessionSandbox::default()
}

fn enforcer(s: SessionSandbox) -> SandboxEnforcer {
    SandboxEnforcer::new(s)
}

// ── default / unlimited ───────────────────────────────────────────────────

#[test]
fn default_sandbox_allows_everything() {
    let e = enforcer(unlimited());
    assert!(e.check("any_backend", "any_tool", usize::MAX).is_ok());
    assert!(e.check("other", "other_tool", 0).is_ok());
}

#[test]
fn call_count_increments_on_success() {
    let e = enforcer(unlimited());
    e.check("b", "t", 0).unwrap();
    e.check("b", "t", 0).unwrap();
    e.check("b", "t", 0).unwrap();
    assert_eq!(e.call_count(), 3);
}

// ── max_calls ─────────────────────────────────────────────────────────────

#[test]
fn call_limit_allows_up_to_max() {
    let e = enforcer(SessionSandbox {
        max_calls: 3,
        ..Default::default()
    });
    assert!(e.check("b", "t", 0).is_ok());
    assert!(e.check("b", "t", 0).is_ok());
    assert!(e.check("b", "t", 0).is_ok());
}

#[test]
fn call_limit_rejects_on_exceeded() {
    let e = enforcer(SessionSandbox {
        max_calls: 2,
        ..Default::default()
    });
    e.check("b", "t", 0).unwrap();
    e.check("b", "t", 0).unwrap();
    let err = e.check("b", "t", 0).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("call limit exceeded"), "unexpected msg: {msg}");
    assert!(msg.contains("limit 2"), "unexpected msg: {msg}");
}

#[test]
fn call_limit_count_does_not_increment_after_rejection() {
    let e = enforcer(SessionSandbox {
        max_calls: 1,
        ..Default::default()
    });
    e.check("b", "t", 0).unwrap();
    assert_eq!(e.call_count(), 1);
    let _ = e.check("b", "t", 0); // rejected
    assert_eq!(e.call_count(), 1); // still 1
}

#[test]
fn zero_max_calls_means_unlimited() {
    let e = enforcer(SessionSandbox {
        max_calls: 0, // unlimited
        ..Default::default()
    });
    for _ in 0..1000 {
        e.check("b", "t", 0).unwrap();
    }
    assert_eq!(e.call_count(), 1000);
}

// ── max_duration ──────────────────────────────────────────────────────────

#[test]
fn session_allows_calls_within_duration() {
    let e = enforcer(SessionSandbox {
        max_duration: Duration::from_secs(3600),
        ..Default::default()
    });
    assert!(e.check("b", "t", 0).is_ok());
}

#[test]
fn session_rejects_after_duration_elapsed() {
    // Start the enforcer 2 seconds in the past so it appears expired.
    let past = Instant::now().checked_sub(Duration::from_secs(2)).unwrap();
    let sandbox = SessionSandbox {
        max_duration: Duration::from_secs(1),
        ..Default::default()
    };
    let e = SandboxEnforcer::new_at(sandbox, past);
    let err = e.check("b", "t", 0).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("expired"), "unexpected msg: {msg}");
    assert!(msg.contains("limit 1s"), "unexpected msg: {msg}");
}

#[test]
fn zero_max_duration_means_no_timeout() {
    // Zero duration should never expire regardless of elapsed time.
    let past = Instant::now()
        .checked_sub(Duration::from_secs(999_999))
        .unwrap_or_else(Instant::now);
    let e = SandboxEnforcer::new_at(
        SessionSandbox {
            max_duration: Duration::ZERO,
            ..Default::default()
        },
        past,
    );
    assert!(e.check("b", "t", 0).is_ok());
}

// ── allowed_backends ─────────────────────────────────────────────────────

#[test]
fn backend_allowlist_permits_listed_backend() {
    let e = enforcer(SessionSandbox {
        allowed_backends: Some(vec!["search".to_string(), "db".to_string()]),
        ..Default::default()
    });
    assert!(e.check("search", "t", 0).is_ok());
    assert!(e.check("db", "t", 0).is_ok());
}

#[test]
fn backend_allowlist_rejects_unlisted_backend() {
    let e = enforcer(SessionSandbox {
        allowed_backends: Some(vec!["search".to_string()]),
        ..Default::default()
    });
    let err = e.check("exec", "t", 0).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("backend not allowed"), "unexpected msg: {msg}");
    assert!(msg.contains("exec"), "unexpected msg: {msg}");
}

#[test]
fn none_allowed_backends_permits_any_backend() {
    let e = enforcer(SessionSandbox {
        allowed_backends: None,
        ..Default::default()
    });
    assert!(e.check("any_backend", "t", 0).is_ok());
}

#[test]
fn empty_allowed_backends_list_rejects_all() {
    let e = enforcer(SessionSandbox {
        allowed_backends: Some(vec![]),
        ..Default::default()
    });
    let err = e.check("any", "t", 0).unwrap_err();
    assert!(err.to_string().contains("backend not allowed"));
}

// ── denied_tools ─────────────────────────────────────────────────────────

#[test]
fn denied_tool_is_rejected() {
    let e = enforcer(SessionSandbox {
        denied_tools: vec!["exec".to_string(), "shell".to_string()],
        ..Default::default()
    });
    let err = e.check("b", "exec", 0).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("tool denied"), "unexpected msg: {msg}");
    assert!(msg.contains("exec"), "unexpected msg: {msg}");
}

#[test]
fn denied_tool_second_entry_also_rejected() {
    let e = enforcer(SessionSandbox {
        denied_tools: vec!["exec".to_string(), "shell".to_string()],
        ..Default::default()
    });
    let err = e.check("b", "shell", 0).unwrap_err();
    assert!(err.to_string().contains("shell"));
}

#[test]
fn non_denied_tool_is_allowed() {
    let e = enforcer(SessionSandbox {
        denied_tools: vec!["exec".to_string()],
        ..Default::default()
    });
    assert!(e.check("b", "search", 0).is_ok());
}

#[test]
fn empty_denied_tools_allows_all() {
    let e = enforcer(SessionSandbox {
        denied_tools: vec![],
        ..Default::default()
    });
    assert!(e.check("b", "exec", 0).is_ok());
}

// ── max_payload_bytes ─────────────────────────────────────────────────────

#[test]
fn payload_within_limit_is_allowed() {
    let e = enforcer(SessionSandbox {
        max_payload_bytes: 1024,
        ..Default::default()
    });
    assert!(e.check("b", "t", 1024).is_ok());
    assert!(e.check("b", "t", 0).is_ok());
}

#[test]
fn payload_over_limit_is_rejected() {
    let e = enforcer(SessionSandbox {
        max_payload_bytes: 512,
        ..Default::default()
    });
    let err = e.check("b", "t", 513).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("payload too large"), "unexpected msg: {msg}");
    assert!(msg.contains("513"), "unexpected msg: {msg}");
    assert!(msg.contains("512"), "unexpected msg: {msg}");
}

#[test]
fn payload_exactly_at_limit_is_allowed() {
    let e = enforcer(SessionSandbox {
        max_payload_bytes: 256,
        ..Default::default()
    });
    assert!(e.check("b", "t", 256).is_ok());
}

#[test]
fn zero_max_payload_bytes_means_unlimited() {
    let e = enforcer(SessionSandbox {
        max_payload_bytes: 0,
        ..Default::default()
    });
    assert!(e.check("b", "t", usize::MAX).is_ok());
}

// ── check order ───────────────────────────────────────────────────────────

#[test]
fn expired_session_beats_backend_denylist() {
    // Both expire AND backend denylist would fire; expire comes first.
    let past = Instant::now().checked_sub(Duration::from_secs(10)).unwrap();
    let sandbox = SessionSandbox {
        max_duration: Duration::from_secs(1),
        allowed_backends: Some(vec!["allowed".to_string()]),
        ..Default::default()
    };
    let e = SandboxEnforcer::new_at(sandbox, past);
    let msg = e.check("blocked", "t", 0).unwrap_err().to_string();
    assert!(msg.contains("expired"), "expected expire first, got: {msg}");
}

#[test]
fn backend_check_before_tool_check() {
    // Backend not allowed AND tool denied; backend error comes first.
    let e = enforcer(SessionSandbox {
        allowed_backends: Some(vec!["ok".to_string()]),
        denied_tools: vec!["bad_tool".to_string()],
        ..Default::default()
    });
    let msg = e.check("blocked", "bad_tool", 0).unwrap_err().to_string();
    assert!(
        msg.contains("backend not allowed"),
        "expected backend error first, got: {msg}"
    );
}

// ── SandboxConfig / resolve ───────────────────────────────────────────────

#[test]
fn config_resolve_returns_named_profile() {
    let mut cfg = SandboxConfig::default();
    cfg.profiles.insert(
        "strict".to_string(),
        SessionSandbox {
            max_calls: 10,
            ..Default::default()
        },
    );
    let s = cfg.resolve(Some("strict"));
    assert_eq!(s.max_calls, 10);
}

#[test]
fn config_resolve_falls_back_to_default_profile() {
    let mut cfg = SandboxConfig {
        default_profile: "base".to_string(),
        profiles: HashMap::new(),
    };
    cfg.profiles.insert(
        "base".to_string(),
        SessionSandbox {
            max_calls: 50,
            ..Default::default()
        },
    );
    let s = cfg.resolve(None);
    assert_eq!(s.max_calls, 50);
}

#[test]
fn config_resolve_unknown_profile_returns_default_sandbox() {
    let cfg = SandboxConfig::default();
    let s = cfg.resolve(Some("nonexistent"));
    assert_eq!(s, SessionSandbox::default());
}

// ── serde round-trip ──────────────────────────────────────────────────────

#[test]
fn sandbox_serde_round_trip_json() {
    let original = SessionSandbox {
        max_calls: 42,
        max_duration: Duration::from_secs(300),
        allowed_backends: Some(vec!["a".to_string(), "b".to_string()]),
        denied_tools: vec!["exec".to_string()],
        max_payload_bytes: 8192,
    };
    let json = serde_json::to_string(&original).unwrap();
    let restored: SessionSandbox = serde_json::from_str(&json).unwrap();
    assert_eq!(original, restored);
}

#[test]
fn sandbox_config_serde_round_trip_json() {
    let mut cfg = SandboxConfig {
        default_profile: "prod".to_string(),
        profiles: HashMap::new(),
    };
    cfg.profiles.insert(
        "prod".to_string(),
        SessionSandbox {
            max_calls: 100,
            max_duration: Duration::from_secs(1800),
            allowed_backends: None,
            denied_tools: vec!["shell".to_string()],
            max_payload_bytes: 65536,
        },
    );
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: SandboxConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.default_profile, "prod");
    assert_eq!(restored.profiles["prod"].max_calls, 100);
    assert_eq!(
        restored.profiles["prod"].max_duration,
        Duration::from_secs(1800)
    );
}

#[test]
fn sandbox_defaults_deserialize_from_empty_object() {
    let s: SessionSandbox = serde_json::from_str("{}").unwrap();
    assert_eq!(s, SessionSandbox::default());
}

// ── SandboxViolation display ──────────────────────────────────────────────

#[test]
fn violation_display_call_limit() {
    let v = SandboxViolation::CallLimitExceeded {
        attempted: 11,
        limit: 10,
    };
    let s = v.to_string();
    assert!(s.contains("11"));
    assert!(s.contains("10"));
    assert!(s.contains("call limit"));
}

#[test]
fn violation_display_session_expired() {
    let v = SandboxViolation::SessionExpired {
        elapsed_secs: 120,
        limit_secs: 60,
    };
    let s = v.to_string();
    assert!(s.contains("120"));
    assert!(s.contains("60"));
    assert!(s.contains("expired"));
}

#[test]
fn violation_display_backend_not_allowed() {
    let v = SandboxViolation::BackendNotAllowed {
        backend: "dangerous".to_string(),
    };
    assert!(v.to_string().contains("dangerous"));
}

#[test]
fn violation_display_tool_denied() {
    let v = SandboxViolation::ToolDenied {
        tool: "exec".to_string(),
    };
    assert!(v.to_string().contains("exec"));
}

#[test]
fn violation_display_payload_too_large() {
    let v = SandboxViolation::PayloadTooLarge {
        actual_bytes: 2048,
        limit_bytes: 1024,
    };
    let s = v.to_string();
    assert!(s.contains("2048"));
    assert!(s.contains("1024"));
}

// ── combined limits ───────────────────────────────────────────────────────

#[test]
fn all_limits_combined_pass_when_all_satisfied() {
    let e = enforcer(SessionSandbox {
        max_calls: 5,
        max_duration: Duration::from_secs(3600),
        allowed_backends: Some(vec!["search".to_string()]),
        denied_tools: vec!["exec".to_string()],
        max_payload_bytes: 1024,
    });
    assert!(e.check("search", "web_search", 512).is_ok());
}

#[test]
fn all_limits_combined_rejects_when_tool_denied() {
    let e = enforcer(SessionSandbox {
        max_calls: 100,
        max_duration: Duration::from_secs(3600),
        allowed_backends: Some(vec!["search".to_string()]),
        denied_tools: vec!["exec".to_string()],
        max_payload_bytes: 65536,
    });
    let err = e.check("search", "exec", 100).unwrap_err();
    assert!(err.to_string().contains("tool denied"));
}

// ── Attestation tests (MIK-5223) ─────────────────────────────────────────

#[test]
fn attestation_enforcer_fails_closed_without_token_when_required_ac1() {
    // AC.1: Sandbox boot fails closed without a valid attestation token
    // (no token = no start)
    let signer = crate::attestation::AttestationSigner::new_always(b"test-secret-32-bytes-long!!".to_vec());
    let validator = std::sync::Arc::new(
        crate::attestation::AttestationValidator::new(Some(signer), true),
    );
    let sandbox = SessionSandbox {
        require_attestation: true,
        ..Default::default()
    };
    // No token provided → must fail.
    let result = SandboxEnforcer::new_with_attestation(sandbox, None, Some(validator));
    assert!(result.is_err(), "AC.1: must fail closed without attestation token");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("attestation") || err.contains("token"), "error should mention attestation: {err}");
}

#[test]
fn attestation_enforcer_succeeds_with_valid_token_ac2() {
    // AC.2: Token carries agent identity, task UUID, capability allow-list,
    // RFC-3339 expiration; signed by bnaut-attestation
    let signer = crate::attestation::AttestationSigner::new_always(b"test-secret-32-bytes-long!!".to_vec());
    let claims = crate::attestation::AttestationClaims::new(
        "agent-42".to_string(),
        "550e8400-e29b-41d4-a716-446655440000".to_string(),
        vec!["search".to_string(), "db".to_string()],
        std::time::Duration::from_secs(3600),
    );
    let token = signer.sign(claims);
    let validator = std::sync::Arc::new(
        crate::attestation::AttestationValidator::new(Some(signer.clone()), true),
    );
    let sandbox = SessionSandbox {
        require_attestation: true,
        ..Default::default()
    };
    let enforcer = SandboxEnforcer::new_with_attestation(
        sandbox,
        Some(token),
        Some(validator),
    )
    .unwrap();
    let att = enforcer.attestation().unwrap();
    assert_eq!(att.agent_id, "agent-42", "AC.2: agent identity must be present");
    assert_eq!(att.task_uuid, "550e8400-e29b-41d4-a716-446655440000", "AC.2: task UUID must be present");
    assert_eq!(att.capability_allowlist, vec!["search", "db"], "AC.2: capability allow-list must be present");
    assert!(!att.exp.is_empty(), "AC.2: RFC-3339 expiration must be present");
}

#[test]
fn attestation_check_attestation_rejects_expired_ac3_ac4() {
    // AC.3: Token validates against gateway on every cross-boundary call;
    // rejection logs to audit ring buffer.
    // AC.4: Rotation does not disrupt in-flight syscalls.
    let signer = crate::attestation::AttestationSigner::new_always(b"test-secret-32-bytes-long!!".to_vec());
    let validator = std::sync::Arc::new(
        crate::attestation::AttestationValidator::new(Some(signer.clone()), false),
    );
    // Create a token that is already expired.
    let expired_claims = crate::attestation::AttestationClaims {
        agent_id: "agent-1".to_string(),
        task_uuid: "e1e1e1e1-e1e1-e1e1-e1e1-e1e1e1e1e1e1".to_string(),
        capability_allowlist: vec!["search".to_string()],
        exp: "2020-01-01T00:00:00+00:00".to_string(),
        iat: "2020-01-01T00:00:00+00:00".to_string(),
    };
    let expired_token = signer.sign(expired_claims);

    // Build enforcer with the expired token.
    let mut sandbox = SessionSandbox::default();
    sandbox.require_attestation = true;
    let mut enforcer = SandboxEnforcer::new_with_attestation(
        sandbox,
        Some(expired_token),
        Some(validator.clone()),
    )
    .unwrap();

    // AC.3: cross-boundary check should detect expiry and log to audit.
    let result = enforcer.check_attestation("cross_boundary_call");
    assert!(result.is_err(), "AC.3: cross-boundary call must reject expired token");
    assert!(result.unwrap_err().to_string().contains("expired"));

    // AC.3: audit ring buffer must have a record of the rejection.
    let audit_entries = validator.audit().entries();
    assert!(!audit_entries.is_empty(), "AC.3: audit ring buffer must log rejections");

    // AC.4: rotation does not disrupt existing claims on failure.
    let bogus_token = crate::attestation::AttestationToken {
        claims: crate::attestation::AttestationClaims::new(
            "evil".to_string(),
            "bad-bad-bad-bad-bad-bad-bad-bad".to_string(),
            vec!["admin".to_string()],
            std::time::Duration::from_secs(3600),
        ),
        sig: "invalid_signature".to_string(),
    };
    let old_agent = enforcer.attestation().unwrap().agent_id.clone();
    let rot_result = enforcer.rotate_attestation(bogus_token);
    assert!(rot_result.is_err(), "AC.4: invalid rotation must be rejected");
    assert_eq!(enforcer.attestation().unwrap().agent_id, old_agent, "AC.4: existing claims preserved on rotation failure");
}
