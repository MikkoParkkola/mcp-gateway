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
