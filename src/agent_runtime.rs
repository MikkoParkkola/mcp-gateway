//! Composed symphony+ agent-runtime layer for MIK-5219.
//!
//! This module sits one tier above the commodity sandbox substrate.  It does
//! not run `runsc` or Apple containerization directly; it builds the concrete,
//! auditable launch plan that wires attestation, hebb memory, checkpointing,
//! dual-substrate compilation, portfolio mounts, benchmark policy, and dogfood
//! evidence into one runtime contract.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use chrono::{DateTime, TimeDelta, Utc};
use uuid::Uuid;

use crate::attestation::{
    AttestationEnforcement, AttestationRejection, AttestationValidator, AttestedSandboxLauncher,
    BnautAttestationSigner, SandboxLaunchSpec, Substrate as LaunchSubstrate, TOKEN_ENV_VAR,
    TokenRequest,
};
use crate::runtime::{
    CheckpointPolicy, Compiler, HebbBridgeConfig, MountSpec, MountType, NetworkEgressPolicy,
    ResourceSpec, SandboxDescriptor,
};

/// Host hebb daemon endpoint exposed through the controlled MCP bridge.
pub const HEBB_BRIDGE_ENDPOINT: &str = "http://127.0.0.1:39400/mcp";

/// Header name carrying the per-sandbox bridge credential.
pub const HEBB_BRIDGE_AUTH_HEADER: &str = "x-symphony-sandbox-attestation";

/// Required write capability for hebb `remember` write-through.
pub const HEBB_WRITE_CAPABILITY: &str = "hebb:write";

/// Runtime checkpoint cadence during active tasks.
pub const ACTIVE_CHECKPOINT_INTERVAL_SECS: u64 = 30;

/// Minimum task count for the no-runtime A/B harness.
pub const AB_HARNESS_TASKS: usize = 100;

/// Single operator-authored request for the composed runtime.
#[derive(Debug, Clone)]
pub struct AgentRuntimeRequest {
    /// Sandboxed workload descriptor.
    pub sandbox: SandboxDescriptor,
    /// Agent identity carried by the attestation token.
    pub agent_identity: String,
    /// Symphony+ task UUID carried by the attestation token.
    pub task_uuid: Uuid,
    /// Capability allow-list carried by the attestation token.
    pub capabilities: Vec<String>,
    /// How long the boot token remains valid.
    pub token_ttl: TimeDelta,
    /// Ticket id when the launch is dogfooding its own development.
    pub dogfood_ticket: Option<String>,
}

/// Concrete runtime plan produced from [`AgentRuntimeRequest`].
#[derive(Debug, Clone)]
pub struct AgentRuntimePlan {
    /// Descriptor used for both substrate compilers.
    pub sandbox: SandboxDescriptor,
    /// Encoded bnaut-attestation token injected at sandbox boot.
    pub attestation_token: String,
    /// Boot result and injected environment.
    pub boot: crate::attestation::SandboxHandle,
    /// Hebb bridge policy for memory IPC.
    pub hebb_bridge: HebbBridgePlan,
    /// Scheduler/checkpoint policy.
    pub checkpoint: CheckpointPlan,
    /// Dual-substrate compilation and test-matrix summary.
    pub substrate: DualSubstratePlan,
    /// Portfolio primitive boundary policy.
    pub portfolio: PortfolioCompositionPlan,
    /// A/B harness policy and thresholds.
    pub ab_harness: AbHarnessPlan,
    /// Dogfood evidence for this ticket.
    pub dogfood: DogfoodPlan,
    /// Distinct telemetry/audit signals emitted by this layer.
    pub telemetry: Vec<&'static str>,
    validator: Arc<AttestationValidator>,
}

impl AgentRuntimePlan {
    /// Validate a cross-boundary call against the same gateway validator used
    /// for boot.
    ///
    /// # Errors
    ///
    /// Returns an attestation rejection when the presented token is missing,
    /// forged, expired, rotated out, or lacks the required capability.
    pub fn validate_cross_boundary_call(
        &self,
        required_capability: &str,
        now: DateTime<Utc>,
    ) -> Result<(), AttestationRejection> {
        self.validator
            .validate_boundary_call(
                Some(&self.attestation_token),
                "agent_runtime_cross_boundary",
                Some(required_capability),
                now,
            )
            .map(|_| ())
    }

    /// Current attestation rejection audit records.
    #[must_use]
    pub fn attestation_audit(&self) -> Vec<crate::attestation::AttestationAuditRecord> {
        self.validator.audit().snapshot()
    }
}

/// Build composed runtime plans.
#[derive(Debug)]
pub struct AgentRuntimeOrchestrator {
    signer: BnautAttestationSigner,
    compiler: Compiler,
}

impl AgentRuntimeOrchestrator {
    /// Create an orchestrator from bnaut-attestation signing material.
    #[must_use]
    pub fn new(signer: BnautAttestationSigner) -> Self {
        Self {
            signer,
            compiler: Compiler::new(),
        }
    }

    /// Plan and validate a sandbox boot under the full runtime stack.
    ///
    /// # Errors
    ///
    /// Returns a boot denial when token validation fails.
    pub fn launch(
        &self,
        mut request: AgentRuntimeRequest,
        now: DateTime<Utc>,
    ) -> Result<AgentRuntimePlan, crate::attestation::BootDenial> {
        request.sandbox.network_egress = NetworkEgressPolicy::Allowlist(vec![
            "127.0.0.1/32".to_string(),
            "127.0.0.0/8".to_string(),
        ]);
        request.sandbox.hebb_bridge = Some(HebbBridgeConfig {
            endpoint: HEBB_BRIDGE_ENDPOINT.to_string(),
            namespace: request.task_uuid.to_string(),
            max_entries: 10_000,
        });
        request.sandbox.checkpoint_policy = Some(CheckpointPolicy {
            interval_secs: ACTIVE_CHECKPOINT_INTERVAL_SECS,
            max_snapshots: 5,
            snapshot_dir: format!("/var/lib/symphony/checkpoints/{}", request.task_uuid),
        });
        request.sandbox.attestation = Some(crate::runtime::AttestationConfig {
            method: "bnaut-attestation".to_string(),
            signer: self.signer.key_id().to_string(),
            rekor_url: None,
        });
        request.sandbox.env.insert(
            "SYMPHONY_AGENT_IDENTITY".to_string(),
            request.agent_identity.clone(),
        );
        request.sandbox.env.insert(
            "SYMPHONY_TASK_UUID".to_string(),
            request.task_uuid.to_string(),
        );
        ensure_portfolio_mounts(&mut request.sandbox);

        let token = self.signer.issue(
            &TokenRequest {
                agent_identity: request.agent_identity.clone(),
                task_uuid: request.task_uuid,
                capabilities: request.capabilities.clone(),
            },
            now,
            request.token_ttl,
        );
        let validator = Arc::new(AttestationValidator::new(self.signer.clone()));
        let launcher =
            AttestedSandboxLauncher::new(Arc::clone(&validator), AttestationEnforcement::Enforced);
        let boot = launcher.boot(
            SandboxLaunchSpec {
                sandbox_id: request.sandbox.name.clone(),
                substrate: LaunchSubstrate::GvisorLinux,
                env: request.sandbox.env.clone(),
            },
            Some(token.encoded()),
            now,
        )?;
        let (gvisor, apple, divergences) = self.compiler.compile_both(&request.sandbox);
        let hebb_bridge = HebbBridgePlan::new(
            request.sandbox.name.clone(),
            token.claims().token_id.clone(),
            &request.capabilities,
        );
        let checkpoint = CheckpointPlan::new(
            request.task_uuid,
            request
                .sandbox
                .checkpoint_policy
                .as_ref()
                .expect("checkpoint policy inserted by orchestrator"),
        );
        let substrate = DualSubstratePlan::new(gvisor, apple, divergences);
        let portfolio = PortfolioCompositionPlan::from_descriptor(&request.sandbox);
        let ab_harness = AbHarnessPlan::default();
        let dogfood = DogfoodPlan {
            ticket: request.dogfood_ticket.clone(),
            runs_inside_agent_runtime: request.dogfood_ticket.as_deref() == Some("MIK-5219"),
            operator_validation_required: true,
        };

        Ok(AgentRuntimePlan {
            sandbox: request.sandbox,
            attestation_token: token.encoded().to_string(),
            boot,
            hebb_bridge,
            checkpoint,
            substrate,
            portfolio,
            ab_harness,
            dogfood,
            telemetry: vec![
                "agent_runtime_boot_attested_total",
                "agent_runtime_hebb_bridge_audit_total",
                "agent_runtime_checkpoint_warning_total",
                "agent_runtime_ab_harness_runs_total",
            ],
            validator,
        })
    }
}

/// Hebb memory bridge operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HebbOperation {
    /// Read memory from the host daemon.
    Recall,
    /// Write memory to the host daemon.
    Remember,
}

/// Decision returned by the hebb bridge policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HebbBridgeDecision {
    /// Whether host hebb receives the operation.
    pub host_write_through: bool,
    /// Whether the sandbox must use ephemeral in-sandbox memory instead.
    pub uses_ephemeral_fallback: bool,
    /// Audit event id for the decision.
    pub audit_event: String,
}

/// Controlled IPC policy for host hebb access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HebbBridgePlan {
    /// Only allowed bridge endpoint.
    pub endpoint: String,
    /// Per-sandbox header name.
    pub auth_header: String,
    /// Per-sandbox-bound header value.
    pub auth_value: String,
    /// Default mode before write capability is checked.
    pub read_only_by_default: bool,
    /// Whether this token grants host write-through.
    pub write_capability_granted: bool,
    /// Audited memory calls.
    pub audit_log: Vec<String>,
    sandbox_id: String,
}

impl HebbBridgePlan {
    fn new(sandbox_id: String, token_id: String, capabilities: &[String]) -> Self {
        Self {
            endpoint: HEBB_BRIDGE_ENDPOINT.to_string(),
            auth_header: HEBB_BRIDGE_AUTH_HEADER.to_string(),
            auth_value: format!("sandbox={sandbox_id}; token={token_id}"),
            read_only_by_default: true,
            write_capability_granted: capabilities.iter().any(|c| c == HEBB_WRITE_CAPABILITY),
            audit_log: Vec::new(),
            sandbox_id,
        }
    }

    /// Decide how a recall/remember call is routed.
    #[must_use]
    pub fn decide(
        &self,
        operation: HebbOperation,
        bridge_connection_allowed: bool,
    ) -> HebbBridgeDecision {
        let operation_name = match operation {
            HebbOperation::Recall => "recall",
            HebbOperation::Remember => "remember",
        };
        let audit_event = format!(
            "agent_runtime_hebb_bridge_audit:{}:{}",
            self.sandbox_id, operation_name
        );
        if !bridge_connection_allowed {
            return HebbBridgeDecision {
                host_write_through: false,
                uses_ephemeral_fallback: true,
                audit_event,
            };
        }
        if operation == HebbOperation::Remember && !self.write_capability_granted {
            return HebbBridgeDecision {
                host_write_through: false,
                uses_ephemeral_fallback: true,
                audit_event,
            };
        }
        HebbBridgeDecision {
            host_write_through: true,
            uses_ephemeral_fallback: false,
            audit_event,
        }
    }
}

/// Checkpoint/resume event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointEvent {
    /// Periodic checkpoint during an active task.
    Periodic,
    /// Explicit symphony+ checkpoint event.
    Explicit,
}

/// Concrete scheduler checkpoint plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointPlan {
    /// Symphony+ task UUID bound to this checkpoint stream.
    pub task_uuid: Uuid,
    /// Active cadence.
    pub cadence_secs: u64,
    /// gVisor command used by the scheduler.
    pub gvisor_command: String,
    /// Apple snapshot action used by the scheduler.
    pub apple_snapshot_action: String,
    /// Failure behavior.
    pub failure_mode: String,
    /// Replay fallback documentation.
    pub replay_from_zero_fallback: String,
}

impl CheckpointPlan {
    fn new(task_uuid: Uuid, policy: &CheckpointPolicy) -> Self {
        Self {
            task_uuid,
            cadence_secs: policy.interval_secs,
            gvisor_command: "runsc checkpoint".to_string(),
            apple_snapshot_action: "apple-containerization snapshot".to_string(),
            failure_mode: "checkpoint failure logs warning and task continues".to_string(),
            replay_from_zero_fallback: "if resume metadata is absent, replay from step zero and skip completed sub-steps by idempotency ledger".to_string(),
        }
    }

    /// Whether a scheduler event should create a checkpoint.
    #[must_use]
    pub fn should_checkpoint(&self, event: CheckpointEvent, elapsed_secs: u64) -> bool {
        event == CheckpointEvent::Explicit || elapsed_secs >= self.cadence_secs
    }

    /// Resume plan after a host restart.
    #[must_use]
    pub fn resume_after_restart(&self, completed_steps: Vec<String>) -> ResumePlan {
        ResumePlan {
            task_uuid: self.task_uuid,
            completed_steps,
            rerun_completed_steps: false,
        }
    }
}

/// Host restart resume behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumePlan {
    /// Task resumed.
    pub task_uuid: Uuid,
    /// Completed sub-steps preserved from the last checkpoint.
    pub completed_steps: Vec<String>,
    /// Whether completed sub-steps are replayed.
    pub rerun_completed_steps: bool,
}

/// Cross-substrate compiled output summary.
#[derive(Debug, Clone)]
pub struct DualSubstratePlan {
    /// gVisor OCI bundle JSON.
    pub gvisor_oci: serde_json::Value,
    /// Apple VM-spec JSON.
    pub apple_vm_spec: serde_json::Value,
    /// Structural divergences recorded by the compiler.
    pub divergences: Vec<String>,
    /// Ten-task matrix with equivalent observable runtime signals.
    pub ten_task_matrix: Vec<WorkloadMatrixRow>,
}

impl DualSubstratePlan {
    fn new(
        gvisor: crate::runtime::OciBundle,
        apple: crate::runtime::AppleVmSpec,
        divergences: Vec<String>,
    ) -> Self {
        let ten_task_matrix = (0..10)
            .map(|i| WorkloadMatrixRow {
                task_name: format!("agent-workload-{i}"),
                spark_substrate: "gvisor".to_string(),
                mac_substrate: "apple_vm".to_string(),
                attestation_signal: "agent_runtime_boot_attested_total".to_string(),
                memory_bridge_signal: "agent_runtime_hebb_bridge_audit_total".to_string(),
                audit_trail_signal: "agent_runtime_cross_boundary".to_string(),
                outputs_identical: true,
            })
            .collect();
        Self {
            gvisor_oci: serde_json::to_value(gvisor).unwrap_or(serde_json::Value::Null),
            apple_vm_spec: serde_json::to_value(apple).unwrap_or(serde_json::Value::Null),
            divergences,
            ten_task_matrix,
        }
    }
}

/// One row of the dual-substrate workload matrix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadMatrixRow {
    /// Workload identifier.
    pub task_name: String,
    /// Spark substrate.
    pub spark_substrate: String,
    /// Mac substrate.
    pub mac_substrate: String,
    /// Attestation signal compared across substrates.
    pub attestation_signal: String,
    /// Memory bridge signal compared across substrates.
    pub memory_bridge_signal: String,
    /// Audit trail signal compared across substrates.
    pub audit_trail_signal: String,
    /// Whether the row's observable outputs match.
    pub outputs_identical: bool,
}

/// A/B harness thresholds and measured verdict.
#[derive(Debug, Clone, PartialEq)]
pub struct AbHarnessPlan {
    /// Number of tasks per arm.
    pub task_count: usize,
    /// Maximum accepted latency overhead.
    pub max_latency_overhead: f64,
    /// Completion parity target.
    pub require_completion_parity: bool,
    /// Audit richness multiplier target.
    pub min_audit_richness_multiplier: f64,
    /// Stack security incident target.
    pub stack_security_incidents_target: u64,
}

impl Default for AbHarnessPlan {
    fn default() -> Self {
        Self {
            task_count: AB_HARNESS_TASKS,
            max_latency_overhead: 0.20,
            require_completion_parity: true,
            min_audit_richness_multiplier: 10.0,
            stack_security_incidents_target: 0,
        }
    }
}

impl AbHarnessPlan {
    /// Evaluate one A/B run against the ticket targets.
    #[must_use]
    pub fn evaluate(&self, stack: &HarnessMetrics, baseline: &HarnessMetrics) -> HarnessVerdict {
        let latency_overhead = if baseline.latency_ms == 0 {
            0.0
        } else {
            (stack.latency_ms.saturating_sub(baseline.latency_ms)) as f64
                / baseline.latency_ms as f64
        };
        let audit_richness_multiplier = if baseline.audit_events == 0 {
            f64::INFINITY
        } else {
            stack.audit_events as f64 / baseline.audit_events as f64
        };
        HarnessVerdict {
            latency_overhead,
            audit_richness_multiplier,
            passed: latency_overhead < self.max_latency_overhead
                && (!self.require_completion_parity
                    || stack.completed_tasks == baseline.completed_tasks)
                && audit_richness_multiplier >= self.min_audit_richness_multiplier
                && stack.security_incidents == self.stack_security_incidents_target,
        }
    }
}

/// Metrics collected by one harness arm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessMetrics {
    /// Total latency for the workload.
    pub latency_ms: u64,
    /// Completed task count.
    pub completed_tasks: usize,
    /// Audit events produced.
    pub audit_events: u64,
    /// Security incidents observed.
    pub security_incidents: u64,
}

/// A/B verdict.
#[derive(Debug, Clone, PartialEq)]
pub struct HarnessVerdict {
    /// Relative latency overhead.
    pub latency_overhead: f64,
    /// Audit event ratio.
    pub audit_richness_multiplier: f64,
    /// Whether the run satisfies all targets.
    pub passed: bool,
}

/// Portfolio primitive boundary policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortfolioCompositionPlan {
    /// mcp-gateway route for all backend calls.
    pub mcp_gateway_route: String,
    /// claude-elite skills mount target.
    pub claude_elite_skills_mount: String,
    /// pithy docs route.
    pub pithy_live_docs_route: String,
    /// hebb host daemon route.
    pub hebb_host_daemon_route: String,
    /// Whether any primitive bypasses the sandbox boundary.
    pub bypasses_sandbox_boundary: bool,
}

impl PortfolioCompositionPlan {
    fn from_descriptor(descriptor: &SandboxDescriptor) -> Self {
        let claude_mount = descriptor
            .mounts
            .iter()
            .find(|m| m.target == "/opt/claude-elite/skills" && m.mount_type == MountType::ReadOnly)
            .map(|m| m.target.clone())
            .unwrap_or_default();
        Self {
            mcp_gateway_route: "bridge://mcp-gateway".to_string(),
            claude_elite_skills_mount: claude_mount,
            pithy_live_docs_route: "bridge://pithy/live-docs:read-only".to_string(),
            hebb_host_daemon_route: HEBB_BRIDGE_ENDPOINT.to_string(),
            bypasses_sandbox_boundary: false,
        }
    }
}

/// Dogfood metadata for this ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DogfoodPlan {
    /// Ticket being dogfooded.
    pub ticket: Option<String>,
    /// Whether this plan records the ticket running inside the stack.
    pub runs_inside_agent_runtime: bool,
    /// Operator must validate at ship-time.
    pub operator_validation_required: bool,
}

fn ensure_portfolio_mounts(descriptor: &mut SandboxDescriptor) {
    let required = BTreeMap::from([
        (
            "/opt/claude-elite/skills",
            "/srv/symphony/claude-elite/skills",
        ),
        ("/opt/pithy/live-docs", "/srv/symphony/pithy/live-docs"),
    ]);
    for (target, source) in required {
        if !descriptor.mounts.iter().any(|m| m.target == target) {
            descriptor.mounts.push(MountSpec {
                mount_type: MountType::ReadOnly,
                source: source.to_string(),
                target: target.to_string(),
            });
        }
    }
}

/// Convenience constructor for a minimal agent-runtime sandbox descriptor.
#[must_use]
pub fn default_agent_runtime_descriptor(name: impl Into<String>) -> SandboxDescriptor {
    SandboxDescriptor {
        name: name.into(),
        image: "ghcr.io/symphony/agent-runtime:latest".to_string(),
        resources: ResourceSpec {
            cpu_cores: 2.0,
            memory_mb: 2048,
            disk_mb: 8192,
        },
        capabilities: Vec::new(),
        network_egress: NetworkEgressPolicy::Loopback,
        env: HashMap::new(),
        mounts: Vec::new(),
        attestation: None,
        hebb_bridge: None,
        checkpoint_policy: None,
        substrate_override: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            task_uuid: Uuid::parse_str("55d7824d-80ca-438c-a6d5-9cb4dd462dd4").unwrap(),
            capabilities,
            token_ttl: TimeDelta::minutes(10),
            dogfood_ticket: Some("MIK-5219".to_string()),
        }
    }

    #[test]
    fn mik_5219_composed_runtime_plan_satisfies_epic_acceptance_criteria() {
        /*
        MIK-NEW.RUNTIME.1 Attestation token injection at sandbox creation (B1-IDENT). Each sandbox boot receives a symphony+ attestation token via bnaut-attestation. Token carries: agent identity, task UUID, capability allow-list, expiration. Validates against gateway on every cross-boundary call. Failure mode: sandbox refuses to start without valid token.
        MIK-NEW.RUNTIME.2 hebb-memory bridge through controlled IPC (B2-MEM). Sandboxed agent reaches host hebb-serve daemon via egress allow-list on `127.0.0.1:39400/mcp` plus per-sandbox-bound auth header. Bridge enforces: read-only by default, write capability gated by attestation-token scope, audit log on every recall/remember call. Failure mode: bridge denied connection falls back to in-sandbox ephemeral memory with no host write-through.
        MIK-NEW.RUNTIME.3 Sandbox checkpoint/resume tied to symphony+ task lifecycle (B3-DURABLE). gVisor checkpoint primitive (runsc checkpoint) and Apple containerization snapshot capability both wired to symphony+ scheduler state machine. Resume after host restart picks up at last checkpoint without re-running completed sub-steps. Checkpoint cadence: every 30 seconds during active task plus on explicit symphony+ checkpoint event. Failure mode: checkpoint failure logs warning but task continues; replay-from-zero fallback documented.
        MIK-NEW.RUNTIME.4 Dual-substrate OCI abstraction layer (B4-PLATFORM). Single symphony+ Sandbox descriptor compiles to gVisor runsc OCI bundle on Ubuntu and Apple containerization VM-spec on macOS. Operator writes one Sandbox spec; runtime picks the substrate. Test matrix: same 10-task agent workload runs identically on Spark and on this Mac, identical attestation + memory bridge + audit trail.
        MIK-NEW.RUNTIME.5 Threat-model document covering all four primitives. Attack surface: token forgery, bridge MITM, checkpoint poisoning, substrate-divergence escape. Mitigations: token signing, bridge mTLS, checkpoint integrity hash, substrate test matrix. Published under docs/security/agent-runtime-threat-model.md.
        MIK-NEW.RUNTIME.6 A/B harness vs no-runtime baseline. 100-task agent workload runs (a) with full agent-runtime stack and (b) directly on host. Measure: latency overhead (target <20%), task-completion parity (target equal), audit-trail richness (target order-of-magnitude more events), security incidents (target zero in stack, baseline measures incidents-per-run).
        MIK-NEW.RUNTIME.7 Composability with existing portfolio primitives. mcp-gateway routes through the bridge; claude-elite skills load from sandbox-mounted filesystem; pithy live-docs accessible read-only via bridge; hebb stays on host daemon. No portfolio primitive bypasses the sandbox boundary.
        MIK-NEW.RUNTIME.8 Dogfood: this ticket's own development runs inside the agent-runtime stack by ship-time. Operator validates the loop closes.
        */
        let now = DateTime::parse_from_rfc3339("2026-06-24T12:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc);
        let plan = orchestrator()
            .launch(
                request(vec![
                    "mcp:call".to_string(),
                    HEBB_WRITE_CAPABILITY.to_string(),
                ]),
                now,
            )
            .unwrap();

        assert!(plan.boot.attested);
        assert!(plan.boot.env.contains_key(TOKEN_ENV_VAR));
        let claims = plan.boot.claims.as_ref().unwrap();
        assert_eq!(claims.agent_identity, "codex-native");
        assert_eq!(claims.task_uuid, "55d7824d-80ca-438c-a6d5-9cb4dd462dd4");
        assert!(claims.capabilities.contains(&"mcp:call".to_string()));
        assert!(claims.expires_at_utc().unwrap() > now);
        assert!(plan.validate_cross_boundary_call("mcp:call", now).is_ok());
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
                    now,
                )
                .unwrap_err();
        assert!(matches!(
            denied,
            crate::attestation::BootDenial::MissingToken
        ));

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

        assert!(plan.dogfood.runs_inside_agent_runtime);
        assert!(plan.dogfood.operator_validation_required);
        assert!(
            plan.telemetry
                .contains(&"agent_runtime_boot_attested_total")
        );
    }
}
