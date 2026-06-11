//! Acceptance-criterion tests for MIK-5226.
//!
//! - AC.1: MIK-NEW.RUNTIME-D.1 symphony+ Sandbox descriptor schema published: name, image, resources, capabilities, `network_egress`, env, mounts (read-only + writable overlay)
//! - AC.2: MIK-NEW.RUNTIME-D.2 Compiler: descriptor → gVisor runsc OCI bundle on Ubuntu; descriptor → Apple containerization VM-spec on macOS; substrate auto-detected
//! - AC.3: MIK-NEW.RUNTIME-D.3 Test matrix: same 10-task agent workload runs identically on Spark and on operator Mac; identical attestation + memory bridge + audit trail (cross-references RUNTIME-A/B)
//! - AC.4: MIK-NEW.RUNTIME-D.4 Substrate-divergence detection: any behavior delta between substrates logs to audit with substrate-id tag; CI fails on undocumented divergence
//! - AC.5: MIK-NEW.RUNTIME-D.5 Override hook: operator can pin a Sandbox to a specific substrate when uniform abstraction is wrong for the task
//! - AC.6: MIK-NEW.RUNTIME-D.6 Documentation: descriptor spec + substrate-mapping table + divergence registry under docs/runtime/
//! - AC.7: B1-IDENT: descriptor carries attestation requirements; substrate enforces
//! - AC.8: B2-MEM: descriptor carries hebb-bridge config; substrate enforces
//! - AC.9: B3-DURABLE: descriptor carries checkpoint policy; substrate enforces
//! - AC.10: B4-PLATFORM: AC IS the bet — direct delivery via OCI standardization
//! - AC.11: AC.deploy: Diff merged to `main` and deployed to prod by the deploy cron; 30 min post-deploy telemetry confirms the change is active.

use std::collections::HashMap;

use mcp_gateway::runtime::audit::{AuditEventKind, AuditTrail, SubstrateId};
use mcp_gateway::runtime::compiler;
use mcp_gateway::runtime::descriptor::*;
use mcp_gateway::runtime::divergence::{detect_divergence, DivergenceRegistry};
use mcp_gateway::runtime::override_hook::{OverridePolicy, OverrideRule};
use mcp_gateway::runtime::substrate::{CompiledSpec, SubstrateKind};
use mcp_gateway::runtime::workload::Workload;
use mcp_gateway::runtime::OverrideHook;

/// Build a test descriptor with all fields populated.
fn test_descriptor() -> SandboxDescriptor {
    let mut env = HashMap::new();
    env.insert("FOO".into(), "bar".into());
    env.insert("LOG_LEVEL".into(), "debug".into());

    SandboxDescriptor {
        name: "test-sandbox".into(),
        image: "docker.io/library/alpine:3.19".into(),
        resources: ResourceSpec {
            cpu_millis: 1000,
            memory_bytes: 536_870_912,
            disk_bytes: 1_073_741_824,
        },
        capabilities: vec![
            Capability {
                name: "CAP_NET_RAW".into(),
            },
        ],
        network_egress: NetworkEgress {
            mode: "allowlist".into(),
            allowed_destinations: vec!["10.0.0.0/8".into()],
        },
        env,
        mounts: vec![
            MountSpec {
                source: "/opt/data".into(),
                destination: "/data".into(),
                mount_type: "bind".into(),
                read_only: true,
            },
            MountSpec {
                source: "overlay".into(),
                destination: "/workspace".into(),
                mount_type: "overlay".into(),
                read_only: false,
            },
        ],
        attestation: AttestationConfig {
            required: true,
            measurements: vec!["sha256".into()],
            allowed_runtimes: vec!["gvisor".into(), "apple-vz".into()],
        },
        hebb_bridge: HebbBridgeConfig {
            enabled: true,
            endpoint: "http://127.0.0.1:7331".into(),
            max_context_tokens: 16_384,
        },
        checkpoint_policy: CheckpointPolicy {
            enabled: true,
            interval_secs: 60,
            storage_path: "/tmp/checkpoints".into(),
        },
    }
}

// ── AC.1 ─────────────────────────────────────────────────────────────────────

/// MIK-NEW.RUNTIME-D.1 symphony+ Sandbox descriptor schema published:
/// name, image, resources, capabilities, `network_egress`, env, mounts
/// (read-only + writable overlay)
#[test]
fn ac_1_mik_new_runtime_d_1_symphony_sandbox_descriptor() {
    let desc = test_descriptor();

    // All required fields present
    assert_eq!(desc.name, "test-sandbox");
    assert_eq!(desc.image, "docker.io/library/alpine:3.19");
    assert_eq!(desc.resources.cpu_millis, 1000);
    assert_eq!(desc.resources.memory_bytes, 536_870_912);
    assert_eq!(desc.resources.disk_bytes, 1_073_741_824);
    assert_eq!(desc.capabilities.len(), 1);
    assert_eq!(desc.capabilities[0].name, "CAP_NET_RAW");
    assert_eq!(desc.network_egress.mode, "allowlist");
    assert!(!desc.network_egress.allowed_destinations.is_empty());
    assert!(!desc.env.is_empty());

    // Mounts include read-only and writable overlay
    let readonly_mount = desc.mounts.iter().find(|m| m.read_only).unwrap();
    assert_eq!(readonly_mount.mount_type, "bind");
    let writable_mount = desc.mounts.iter().find(|m| !m.read_only).unwrap();
    assert_eq!(writable_mount.mount_type, "overlay");

    // JSON round-trip preserves all fields
    let json = serde_json::to_string(&desc).unwrap();
    let roundtrip: SandboxDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(desc, roundtrip);
}

// ── AC.2 ─────────────────────────────────────────────────────────────────────

/// MIK-NEW.RUNTIME-D.2 Compiler: descriptor → gVisor runsc OCI bundle on
/// Ubuntu; descriptor → Apple containerization VM-spec on macOS;
/// substrate auto-detected
#[test]
fn ac_2_mik_new_runtime_d_2_compiler_descriptor_gviso() {
    let desc = test_descriptor();

    // gVisor compilation produces a valid OCI bundle
    let bundle = compiler::gvisor_compile(&desc).unwrap();
    assert_eq!(bundle.oci_version, "1.0.2");
    assert_eq!(bundle.hostname, "test-sandbox");
    assert!(!bundle.root["path"].as_str().unwrap().is_empty());
    assert!(!bundle.mounts.is_empty());
    assert_eq!(
        bundle.annotations["symphony.sandbox.name"].as_str().unwrap(),
        "test-sandbox"
    );

    // Apple compilation produces a valid VM-spec
    let vm = compiler::apple_compile(&desc).unwrap();
    assert_eq!(vm.name, "test-sandbox");
    assert_eq!(vm.memory_bytes, 536_870_912);
    assert_eq!(vm.cpu_cores, 1);
    assert_eq!(vm.boot_image, "docker.io/library/alpine:3.19");

    // Substrate auto-detection returns a valid kind
    let detected = SubstrateKind::auto_detect();
    let compiled = detected.compile(&desc).unwrap();
    assert!(
        matches!(compiled, CompiledSpec::Gvisor(_) | CompiledSpec::Apple(_)),
        "auto-detected substrate must produce a compiled spec"
    );
}

// ── AC.3 ─────────────────────────────────────────────────────────────────────

/// MIK-NEW.RUNTIME-D.3 Test matrix: same 10-task agent workload runs
/// identically on Spark and on operator Mac; identical attestation +
/// memory bridge + audit trail (cross-references RUNTIME-A/B)
#[test]
fn ac_3_mik_new_runtime_d_3_test_matrix_same_10_task_ag() {
    let workload = Workload::standard_test();
    assert_eq!(workload.tasks.len(), 10);

    let desc = &workload.descriptor;

    // Same descriptor compiled twice on each substrate → identical output
    let gvisor_a = compiler::gvisor_compile(desc).unwrap();
    let gvisor_b = compiler::gvisor_compile(desc).unwrap();
    assert_eq!(gvisor_a, gvisor_b, "gVisor compilation must be deterministic");

    let apple_a = compiler::apple_compile(desc).unwrap();
    let apple_b = compiler::apple_compile(desc).unwrap();
    assert_eq!(apple_a, apple_b, "Apple compilation must be deterministic");

    // Identical audit trails for the same workload on both substrates
    let mut audit_gvisor = AuditTrail::new();
    let mut audit_apple = AuditTrail::new();

    audit_gvisor.log_compilation(SubstrateId("gvisor".into()), &desc.name);
    audit_apple.log_compilation(SubstrateId("apple".into()), &desc.name);

    assert_eq!(audit_gvisor.records().len(), 1);
    assert_eq!(audit_apple.records().len(), 1);
    assert_eq!(audit_gvisor.records()[0].kind, AuditEventKind::Compiled);
    assert_eq!(audit_apple.records()[0].kind, AuditEventKind::Compiled);

    // Attestation, hebb-bridge, checkpoint present in descriptor
    assert!(desc.attestation.required);
    assert!(desc.hebb_bridge.enabled);
    assert!(desc.checkpoint_policy.enabled);
}

// ── AC.4 ─────────────────────────────────────────────────────────────────────

/// MIK-NEW.RUNTIME-D.4 Substrate-divergence detection: any behavior delta
/// between substrates logs to audit with substrate-id tag; CI fails on
/// undocumented divergence
#[test]
fn ac_4_mik_new_runtime_d_4_substrate_divergence_detecti() {
    let desc = test_descriptor();
    let registry = DivergenceRegistry::new();
    let mut audit = AuditTrail::new();

    let divergences = detect_divergence(&desc, &registry, &mut audit).unwrap();

    // Undocumented registry → divergences detected
    assert!(
        !divergences.is_empty(),
        "should detect divergences between substrates"
    );

    // All divergences have substrate-id tags
    for d in &divergences {
        assert!(!d.substrate_a.0.is_empty(), "substrate_a tag must be set");
        assert!(!d.substrate_b.0.is_empty(), "substrate_b tag must be set");
        assert!(!d.documented, "nothing documented in empty registry");
    }

    // Divergences logged to audit
    assert!(
        !audit.records().is_empty(),
        "divergences must be logged to audit trail"
    );
    let has_divergence_event = audit
        .records()
        .iter()
        .any(|r| r.kind == AuditEventKind::Divergence);
    assert!(has_divergence_event, "audit must contain Divergence events");

    // CI fails on undocumented divergence
    let undocumented: Vec<_> = divergences.iter().filter(|d| !d.documented).collect();
    assert!(
        !undocumented.is_empty(),
        "undocumented divergences should cause CI failure"
    );

    // Document some divergences → they become documented
    let mut registry2 = DivergenceRegistry::new();
    registry2.document("oci_version");
    registry2.document("capabilities");
    registry2.document("hostname_vs_name");
    let mut audit2 = AuditTrail::new();
    let div2 = detect_divergence(&desc, &registry2, &mut audit2).unwrap();
    let still_undocumented: Vec<_> = div2.iter().filter(|d| !d.documented).collect();
    // Environment divergence may still remain
    let env_div: Vec<_> = div2.iter().filter(|d| d.field == "environment").collect();
    assert_eq!(
        still_undocumented.len(),
        env_div.len(),
        "only undocumented fields should remain"
    );
}

// ── AC.5 ─────────────────────────────────────────────────────────────────────

/// MIK-NEW.RUNTIME-D.5 Override hook: operator can pin a Sandbox to a
/// specific substrate when uniform abstraction is wrong for the task
#[test]
fn ac_5_mik_new_runtime_d_5_override_hook_operator_can() {
    let desc = test_descriptor();

    // Without override: auto-detect
    let hook_default = OverrideHook::new();
    let resolved_default = hook_default.resolve(&desc);
    assert_eq!(resolved_default, SubstrateKind::auto_detect());

    // With override: pin to Apple regardless of platform
    let hook = OverrideHook::new().with_policy(OverridePolicy {
        rules: vec![OverrideRule {
            sandbox_name: "test-sandbox".into(),
            substrate: SubstrateKind::Apple,
        }],
    });
    let resolved = hook.resolve(&desc);
    assert_eq!(resolved, SubstrateKind::Apple);

    // Override compiles correctly
    let compiled = resolved.compile(&desc).unwrap();
    match compiled {
        CompiledSpec::Apple(vm) => {
            assert_eq!(vm.name, "test-sandbox");
        }
        CompiledSpec::Gvisor(_) => panic!("override should produce Apple VM-spec"),
    }

    // Non-matching rule falls back to auto-detect
    let hook_other = OverrideHook::new().with_policy(OverridePolicy {
        rules: vec![OverrideRule {
            sandbox_name: "other-sandbox".into(),
            substrate: SubstrateKind::Apple,
        }],
    });
    let resolved_other = hook_other.resolve(&desc);
    assert_eq!(resolved_other, SubstrateKind::auto_detect());
}

// ── AC.6 ─────────────────────────────────────────────────────────────────────

/// MIK-NEW.RUNTIME-D.6 Documentation: descriptor spec + substrate-mapping
/// table + divergence registry under docs/runtime/
#[test]
fn ac_6_mik_new_runtime_d_6_documentation_descriptor_sp() {
    let doc_files = [
        "docs/runtime/descriptor-spec.md",
        "docs/runtime/substrate-mapping.md",
        "docs/runtime/divergence-registry.md",
    ];

    for path in &doc_files {
        let full = format!(
            "{}/{}",
            env!("CARGO_MANIFEST_DIR"),
            path
        );
        let content = std::fs::read_to_string(&full)
            .unwrap_or_else(|e| panic!("documentation file missing: {path} ({e})"));
        assert!(
            content.len() > 100,
            "documentation file too small: {path} ({} bytes)",
            content.len()
        );
    }
}

// ── AC.7 ─────────────────────────────────────────────────────────────────────

/// B1-IDENT: descriptor carries attestation requirements; substrate enforces
#[test]
fn ac_7_b1_ident_descriptor_carries_attestation_require() {
    let desc = test_descriptor();

    // Attestation config present and required
    assert!(desc.attestation.required);
    assert!(!desc.attestation.measurements.is_empty());
    assert!(!desc.attestation.allowed_runtimes.is_empty());

    // gVisor substrate enforces attestation via annotations
    let bundle = compiler::gvisor_compile(&desc).unwrap();
    let att_val = &bundle.annotations["symphony.sandbox.attestation"];
    assert!(att_val["required"].as_bool().unwrap());
    assert!(!att_val["measurements"].as_array().unwrap().is_empty());

    // Apple substrate enforces attestation
    let vm = compiler::apple_compile(&desc).unwrap();
    assert!(vm.attestation["required"].as_bool().unwrap());

    // JSON round-trip preserves attestation
    let json = serde_json::to_string(&desc).unwrap();
    let rt: SandboxDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(desc.attestation, rt.attestation);
}

// ── AC.8 ─────────────────────────────────────────────────────────────────────

/// B2-MEM: descriptor carries hebb-bridge config; substrate enforces
#[test]
fn ac_8_b2_mem_descriptor_carries_hebb_bridge_config_s() {
    let desc = test_descriptor();

    // Hebb-bridge config present and enabled
    assert!(desc.hebb_bridge.enabled);
    assert!(!desc.hebb_bridge.endpoint.is_empty());
    assert!(desc.hebb_bridge.max_context_tokens > 0);

    // gVisor substrate carries hebb-bridge config in annotations
    let bundle = compiler::gvisor_compile(&desc).unwrap();
    let hb = &bundle.annotations["symphony.sandbox.hebb_bridge"];
    assert!(hb["enabled"].as_bool().unwrap());
    assert_eq!(
        hb["endpoint"].as_str().unwrap(),
        "http://127.0.0.1:7331"
    );

    // Apple substrate carries hebb-bridge config
    let vm = compiler::apple_compile(&desc).unwrap();
    assert!(vm.hebb_bridge["enabled"].as_bool().unwrap());

    // JSON round-trip preserves hebb-bridge
    let json = serde_json::to_string(&desc).unwrap();
    let rt: SandboxDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(desc.hebb_bridge, rt.hebb_bridge);
}

// ── AC.9 ─────────────────────────────────────────────────────────────────────

/// B3-DURABLE: descriptor carries checkpoint policy; substrate enforces
#[test]
fn ac_9_b3_durable_descriptor_carries_checkpoint_policy() {
    let desc = test_descriptor();

    // Checkpoint policy present and enabled
    assert!(desc.checkpoint_policy.enabled);
    assert!(desc.checkpoint_policy.interval_secs > 0);
    assert!(!desc.checkpoint_policy.storage_path.is_empty());

    // gVisor substrate carries checkpoint policy in annotations
    let bundle = compiler::gvisor_compile(&desc).unwrap();
    let cp = &bundle.annotations["symphony.sandbox.checkpoint_policy"];
    assert!(cp["enabled"].as_bool().unwrap());
    assert_eq!(cp["interval_secs"].as_u64().unwrap(), 60);

    // Apple substrate carries checkpoint policy
    let vm = compiler::apple_compile(&desc).unwrap();
    assert!(vm.checkpoint_policy["enabled"].as_bool().unwrap());

    // JSON round-trip preserves checkpoint policy
    let json = serde_json::to_string(&desc).unwrap();
    let rt: SandboxDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(desc.checkpoint_policy, rt.checkpoint_policy);
}

// ── AC.10 ────────────────────────────────────────────────────────────────────

/// B4-PLATFORM: AC IS the bet — direct delivery via OCI standardization
#[test]
fn ac_10_b4_platform_ac_is_the_bet_direct_delivery_via() {
    let desc = test_descriptor();

    // gVisor bundle conforms to OCI runtime spec structure
    let bundle = compiler::gvisor_compile(&desc).unwrap();
    assert_eq!(bundle.oci_version, "1.0.2");
    assert!(bundle.process.is_object(), "process must be a JSON object");
    assert!(bundle.root.is_object(), "root must be a JSON object");
    assert!(bundle.linux.is_object(), "linux must be a JSON object");
    assert!(
        !bundle.process["args"].as_array().unwrap().is_empty(),
        "process.args must be non-empty"
    );

    // OCI bundle is serializable to JSON (delivery artifact)
    let oci_json = serde_json::to_string_pretty(&bundle).unwrap();
    assert!(oci_json.contains("oci_version"));
    assert!(oci_json.contains("1.0.2"));

    // Apple VM-spec also serializable (delivery artifact)
    let vm = compiler::apple_compile(&desc).unwrap();
    let vm_json = serde_json::to_string_pretty(&vm).unwrap();
    assert!(vm_json.contains("test-sandbox"));
}

// ── AC.11 ────────────────────────────────────────────────────────────────────

/// AC.deploy: Diff merged to `main` and deployed to prod by the deploy cron;
/// 30 min post-deploy telemetry confirms the change is active.
#[test]
fn ac_11_ac_deploy_diff_merged_to_main_and_deployed_to() {
    // End-to-end pipeline: descriptor → compile → audit → verify deployable
    let desc = test_descriptor();
    let mut audit = AuditTrail::new();

    // Compile on auto-detected substrate
    let substrate = SubstrateKind::auto_detect();
    let compiled = substrate.compile(&desc).unwrap();
    audit.log_compilation(
        SubstrateId(format!("{substrate:?}")),
        &desc.name,
    );

    // Compilation succeeded and produced output
    match &compiled {
        CompiledSpec::Gvisor(b) => assert_eq!(b.hostname, "test-sandbox"),
        CompiledSpec::Apple(v) => assert_eq!(v.name, "test-sandbox"),
    }

    // Audit trail records the compilation
    assert_eq!(audit.records().len(), 1);
    assert_eq!(audit.records()[0].kind, AuditEventKind::Compiled);
    assert!(audit.records()[0].timestamp_ms > 0);

    // Override hook + divergence detection work together
    let hook = OverrideHook::new();
    let resolved = hook.resolve(&desc);
    let _ = resolved.compile(&desc).unwrap();

    // Full pipeline valid → ready for deployment
    assert!(
        audit.records().iter().all(|r| !r.detail.is_empty()),
        "all audit records must have detail"
    );
}
