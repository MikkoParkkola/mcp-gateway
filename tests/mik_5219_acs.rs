//! Acceptance-criterion regression tests for MIK-5219.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, TimeDelta, Utc};
use mcp_gateway::agent_runtime::{
    AB_HARNESS_TASKS, ACTIVE_CHECKPOINT_INTERVAL_SECS, AgentRuntimeOrchestrator,
    AgentRuntimeRequest, CheckpointEvent, HEBB_BRIDGE_AUTH_HEADER, HEBB_BRIDGE_ENDPOINT,
    HEBB_WRITE_CAPABILITY, HarnessMetrics, HebbOperation, default_agent_runtime_descriptor,
};
use mcp_gateway::attestation::{
    AttestationEnforcement, AttestationValidator, AttestedSandboxLauncher, BnautAttestationSigner,
    SandboxLaunchSpec, Substrate as LaunchSubstrate, TOKEN_ENV_VAR,
};
use uuid::Uuid;

fn now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-06-24T12:00:00+00:00")
        .expect("fixed RFC3339 timestamp")
        .with_timezone(&Utc)
}

fn orchestrator() -> AgentRuntimeOrchestrator {
    AgentRuntimeOrchestrator::new(BnautAttestationSigner::new(
        b"MIK-5219-test-key".to_vec(),
        "MIK-5219",
    ))
}

fn request(capabilities: Vec<String>) -> AgentRuntimeRequest {
    AgentRuntimeRequest {
        sandbox: default_agent_runtime_descriptor("mik-5219-runtime"),
        agent_identity: "codex-native".to_string(),
        task_uuid: Uuid::parse_str("55d7824d-80ca-438c-a6d5-9cb4dd462dd4").expect("static UUID"),
        capabilities,
        token_ttl: TimeDelta::minutes(10),
        dogfood_ticket: Some("MIK-5219".to_string()),
    }
}

/// MIK-NEW.RUNTIME.1 **Attestation token injection at sandbox creation (B1-IDENT)**. Each sandbox boot receives a symphony+ attestation token via bnaut-attestation. Token carries: agent identity, task UUID, capability allow-list, expiration. Validates against gateway on every cross-boundary call. Failure mode: sandbox refuses to start without valid token.
#[test]
fn ac_1_attestation_token_injection_and_fail_closed_boot() {
    let plan = orchestrator()
        .launch(request(vec!["mcp:call".to_string()]), now())
        .expect("runtime launch");

    assert!(plan.boot.attested);
    assert!(plan.boot.env.contains_key(TOKEN_ENV_VAR));
    let claims = plan.boot.claims.as_ref().expect("verified claims");
    assert_eq!(claims.agent_identity, "codex-native");
    assert_eq!(claims.task_uuid, "55d7824d-80ca-438c-a6d5-9cb4dd462dd4");
    assert!(claims.capabilities.contains(&"mcp:call".to_string()));
    assert!(claims.expires_at_utc().expect("expiry parses") > now());
    assert!(plan.validate_cross_boundary_call("mcp:call", now()).is_ok());

    let validator = Arc::new(AttestationValidator::new(BnautAttestationSigner::new(
        b"MIK-5219-test-key".to_vec(),
        "MIK-5219",
    )));
    let denied =
        AttestedSandboxLauncher::new(Arc::clone(&validator), AttestationEnforcement::Enforced)
            .boot(
                SandboxLaunchSpec {
                    sandbox_id: "missing-token".to_string(),
                    substrate: LaunchSubstrate::GvisorLinux,
                    env: HashMap::new(),
                },
                None,
                now(),
            )
            .expect_err("missing boot token must fail closed");
    assert!(matches!(
        denied,
        mcp_gateway::attestation::BootDenial::MissingToken
    ));
}

/// MIK-NEW.RUNTIME.2 **hebb-memory bridge through controlled IPC (B2-MEM)**. Sandboxed agent reaches host hebb-serve daemon via egress allow-list on `127.0.0.1:39400/mcp` plus per-sandbox-bound auth header. Bridge enforces: read-only by default, write capability gated by attestation-token scope, audit log on every recall/remember call. Failure mode: bridge denied connection falls back to in-sandbox ephemeral memory with no host write-through.
#[test]
fn ac_2_hebb_bridge_is_scoped_audited_and_falls_back_ephemeral() {
    let plan = orchestrator()
        .launch(
            request(vec![
                "mcp:call".to_string(),
                HEBB_WRITE_CAPABILITY.to_string(),
            ]),
            now(),
        )
        .expect("runtime launch");

    assert_eq!(plan.hebb_bridge.endpoint, HEBB_BRIDGE_ENDPOINT);
    assert_eq!(plan.hebb_bridge.auth_header, HEBB_BRIDGE_AUTH_HEADER);
    assert!(plan.hebb_bridge.auth_value.contains("mik-5219-runtime"));
    assert!(plan.hebb_bridge.read_only_by_default);
    assert!(plan.hebb_bridge.write_capability_granted);
    let recall = plan.hebb_bridge.decide(HebbOperation::Recall, true);
    assert!(recall.host_write_through);
    assert!(recall.audit_event.contains("recall"));
    let fallback = plan.hebb_bridge.decide(HebbOperation::Remember, false);
    assert!(!fallback.host_write_through);
    assert!(fallback.uses_ephemeral_fallback);
    assert!(fallback.audit_event.contains("remember"));
}

/// MIK-NEW.RUNTIME.3 **Sandbox checkpoint/resume tied to symphony+ task lifecycle (B3-DURABLE)**. gVisor checkpoint primitive (runsc checkpoint) and Apple containerization snapshot capability both wired to symphony+ scheduler state machine. Resume after host restart picks up at last checkpoint without re-running completed sub-steps. Checkpoint cadence: every 30 seconds during active task plus on explicit symphony+ checkpoint event. Failure mode: checkpoint failure logs warning but task continues; replay-from-zero fallback documented.
#[test]
fn ac_3_checkpoint_resume_is_scheduler_bound_and_non_replaying() {
    let plan = orchestrator()
        .launch(request(vec!["mcp:call".to_string()]), now())
        .expect("runtime launch");

    assert_eq!(
        plan.checkpoint.cadence_secs,
        ACTIVE_CHECKPOINT_INTERVAL_SECS
    );
    assert_eq!(plan.checkpoint.gvisor_command, "runsc checkpoint");
    assert_eq!(
        plan.checkpoint.apple_snapshot_action,
        "apple-containerization snapshot"
    );
    assert!(
        plan.checkpoint
            .should_checkpoint(CheckpointEvent::Periodic, 30)
    );
    assert!(
        plan.checkpoint
            .should_checkpoint(CheckpointEvent::Explicit, 1)
    );
    assert!(plan.checkpoint.failure_mode.contains("warning"));
    assert!(
        plan.checkpoint
            .replay_from_zero_fallback
            .contains("replay from step zero")
    );
    let resume = plan
        .checkpoint
        .resume_after_restart(vec!["step-1".to_string()]);
    assert_eq!(resume.completed_steps, vec!["step-1".to_string()]);
    assert!(!resume.rerun_completed_steps);
}

/// MIK-NEW.RUNTIME.4 **Dual-substrate OCI abstraction layer (B4-PLATFORM)**. Single symphony+ Sandbox descriptor compiles to gVisor runsc OCI bundle on Ubuntu and Apple containerization VM-spec on macOS. Operator writes one Sandbox spec; runtime picks the substrate. Test matrix: same 10-task agent workload runs identically on Spark and on this Mac, identical attestation + memory bridge + audit trail.
#[test]
fn ac_4_single_descriptor_compiles_to_both_substrates_with_equivalent_matrix() {
    let plan = orchestrator()
        .launch(request(vec!["mcp:call".to_string()]), now())
        .expect("runtime launch");

    assert!(plan.substrate.gvisor_oci.get("oci_version").is_some());
    assert!(plan.substrate.apple_vm_spec.get("vm_name").is_some());
    assert_eq!(plan.substrate.ten_task_matrix.len(), 10);
    assert!(
        plan.substrate
            .ten_task_matrix
            .iter()
            .all(|row| row.outputs_identical
                && row.attestation_signal == "agent_runtime_boot_attested_total"
                && row.memory_bridge_signal == "agent_runtime_hebb_bridge_audit_total"
                && row.audit_trail_signal == "agent_runtime_cross_boundary")
    );
}

/// MIK-NEW.RUNTIME.5 **Threat-model document covering all four primitives**. Attack surface: token forgery, bridge MITM, checkpoint poisoning, substrate-divergence escape. Mitigations: token signing, bridge mTLS, checkpoint integrity hash, substrate test matrix. Published under docs/security/agent-runtime-threat-model.md.
#[test]
fn ac_5_threat_model_document_names_required_attacks_and_mitigations() {
    let threat_model = include_str!("../docs/security/agent-runtime-threat-model.md");
    for required in [
        "Token forgery",
        "Bridge MITM",
        "Checkpoint poisoning",
        "Substrate-divergence escape",
        "Tokens are signed by bnaut-attestation",
        "mTLS",
        "checkpoint integrity hash",
        "10-task matrix",
    ] {
        assert!(threat_model.contains(required), "missing {required}");
    }
}

/// MIK-NEW.RUNTIME.6 **A/B harness vs no-runtime baseline**. 100-task agent workload runs (a) with full agent-runtime stack and (b) directly on host. Measure: latency overhead (target <20%), task-completion parity (target equal), audit-trail richness (target order-of-magnitude more events), security incidents (target zero in stack, baseline measures incidents-per-run).
#[test]
fn ac_6_ab_harness_enforces_latency_parity_audit_and_security_targets() {
    let plan = orchestrator()
        .launch(request(vec!["mcp:call".to_string()]), now())
        .expect("runtime launch");

    assert_eq!(plan.ab_harness.task_count, AB_HARNESS_TASKS);
    let verdict = plan.ab_harness.evaluate(
        &HarnessMetrics {
            latency_ms: 119,
            completed_tasks: 100,
            audit_events: 1_000,
            security_incidents: 0,
        },
        &HarnessMetrics {
            latency_ms: 100,
            completed_tasks: 100,
            audit_events: 100,
            security_incidents: 2,
        },
    );
    assert!(verdict.passed);
    assert!(verdict.latency_overhead < 0.20);
    assert!(verdict.audit_richness_multiplier >= 10.0);
}

/// MIK-NEW.RUNTIME.7 **Composability with existing portfolio primitives**. mcp-gateway routes through the bridge; claude-elite skills load from sandbox-mounted filesystem; pithy live-docs accessible read-only via bridge; hebb stays on host daemon. No portfolio primitive bypasses the sandbox boundary.
#[test]
fn ac_7_portfolio_primitives_stay_behind_runtime_boundary() {
    let plan = orchestrator()
        .launch(request(vec!["mcp:call".to_string()]), now())
        .expect("runtime launch");

    assert_eq!(plan.portfolio.mcp_gateway_route, "bridge://mcp-gateway");
    assert_eq!(
        plan.portfolio.claude_elite_skills_mount,
        "/opt/claude-elite/skills"
    );
    assert_eq!(
        plan.portfolio.pithy_live_docs_route,
        "bridge://pithy/live-docs:read-only"
    );
    assert_eq!(plan.portfolio.hebb_host_daemon_route, HEBB_BRIDGE_ENDPOINT);
    assert!(!plan.portfolio.bypasses_sandbox_boundary);
}

/// MIK-NEW.RUNTIME.8 **Dogfood**: this ticket's own development runs inside the agent-runtime stack by ship-time. Operator validates the loop closes.
#[test]
fn ac_8_dogfood_metadata_records_mik_5219_runtime_loop() {
    let plan = orchestrator()
        .launch(request(vec!["mcp:call".to_string()]), now())
        .expect("runtime launch");

    assert_eq!(plan.dogfood.ticket.as_deref(), Some("MIK-5219"));
    assert!(plan.dogfood.runs_inside_agent_runtime);
    assert!(plan.dogfood.operator_validation_required);
}

/// B1-IDENT: AC.1 directly delivers attestation-at-sandbox-creation; bnaut-attestation is the platform owner
#[test]
fn ac_9_b1_ident_has_distinguishable_attestation_telemetry() {
    let plan = orchestrator()
        .launch(request(vec!["mcp:call".to_string()]), now())
        .expect("runtime launch");

    assert!(
        plan.telemetry
            .contains(&"agent_runtime_boot_attested_total")
    );
}

/// B2-MEM: AC.2 directly delivers hebb-bridge with audit + scope gating; hebb stays daemon-on-host, sandbox connects via bridge
#[test]
fn ac_10_b2_mem_denies_write_without_attested_scope() {
    let plan = orchestrator()
        .launch(request(vec!["mcp:call".to_string()]), now())
        .expect("runtime launch");

    assert!(!plan.hebb_bridge.write_capability_granted);
    let decision = plan.hebb_bridge.decide(HebbOperation::Remember, true);
    assert!(!decision.host_write_through);
    assert!(decision.uses_ephemeral_fallback);
}

/// B3-DURABLE: AC.3 directly delivers checkpoint/resume across sandbox lifecycle; symphony+ scheduler owns the state machine
#[test]
fn ac_11_b3_durable_binds_checkpoint_stream_to_task_uuid() {
    let plan = orchestrator()
        .launch(request(vec!["mcp:call".to_string()]), now())
        .expect("runtime launch");

    assert_eq!(
        plan.checkpoint.task_uuid.to_string(),
        "55d7824d-80ca-438c-a6d5-9cb4dd462dd4"
    );
}

/// B4-PLATFORM: AC.4 directly delivers the dual-substrate OCI abstraction; reuses upstream gVisor + Apple containerization primitives; no fork; weekly rebase
#[test]
fn ac_12_b4_platform_keeps_gvisor_and_apple_outputs_side_by_side() {
    let plan = orchestrator()
        .launch(request(vec!["mcp:call".to_string()]), now())
        .expect("runtime launch");

    assert!(plan.substrate.gvisor_oci.is_object());
    assert!(plan.substrate.apple_vm_spec.is_object());
}

/// AC.deploy: Diff merged to `main` and deployed to prod by the deploy cron; 30 min post-deploy telemetry confirms the change is active.
#[test]
fn ac_13_deploy_cron_has_distinct_runtime_telemetry_to_confirm() {
    let plan = orchestrator()
        .launch(request(vec!["mcp:call".to_string()]), now())
        .expect("runtime launch");

    assert!(
        plan.telemetry
            .contains(&"agent_runtime_ab_harness_runs_total")
    );
}
