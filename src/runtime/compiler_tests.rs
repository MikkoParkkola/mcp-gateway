use std::collections::HashMap;

use super::super::descriptor::{
    MountSpec, MountType, NetworkEgressPolicy, ResourceSpec, SandboxDescriptor,
};
use super::super::divergence::DivergenceRegistry;
use super::super::substrate::Substrate;
use super::*;

fn make_descriptor() -> SandboxDescriptor {
    SandboxDescriptor {
        name: "test-sandbox".into(),
        image: "docker.io/library/alpine:3.19".into(),
        resources: ResourceSpec {
            cpu_cores: 2.0,
            memory_mb: 1024,
            disk_mb: 4096,
        },
        capabilities: vec![],
        network_egress: NetworkEgressPolicy::Loopback,
        env: {
            let mut m = HashMap::new();
            m.insert("TEST".into(), "value".into());
            m
        },
        mounts: vec![
            MountSpec {
                mount_type: MountType::ReadOnly,
                source: "/host/ro".into(),
                target: "/mnt/ro".into(),
            },
            MountSpec {
                mount_type: MountType::WritableOverlay,
                source: "/host/rw".into(),
                target: "/mnt/rw".into(),
            },
        ],
        attestation: None,
        hebb_bridge: None,
        checkpoint_policy: None,
        substrate_override: None,
    }
}

// ── AC.2: Compiler — gVisor ──────────────────────────────────────────────

#[test]
fn compile_gvisor_produces_oci_bundle() {
    let compiler = Compiler::new();
    let descriptor = make_descriptor();
    let bundle = compiler.compile_gvisor(&descriptor);

    assert_eq!(bundle.oci_version, "1.0.2");
    assert_eq!(bundle.process.args, vec!["/init"]);
    assert_eq!(bundle.hostname, "test-sandbox");

    // Mounts: 2 user + 1 /proc = 3
    assert_eq!(bundle.mounts.len(), 3);
    assert_eq!(bundle.mounts[0].destination, "/mnt/ro");
    assert!(bundle.mounts[0].options.contains(&"ro".to_string()));
    assert_eq!(bundle.mounts[1].destination, "/mnt/rw");
    assert!(!bundle.mounts[1].options.contains(&"ro".to_string()));
    assert_eq!(bundle.mounts[2].destination, "/proc");

    // Linux config present
    let linux = bundle.linux.as_ref().unwrap();
    assert_eq!(linux.namespaces.len(), 5);
    let resources = linux.resources.as_ref().unwrap();
    assert!(resources.cpu_shares.unwrap() > 0);
    assert!(resources.memory_limit.unwrap() > 0);

    // Environment
    assert_eq!(bundle.env.get("TEST"), Some(&"value".to_string()));
}

// ── AC.2: Compiler — Apple VM ────────────────────────────────────────────

#[test]
fn compile_apple_vm_produces_vm_spec() {
    let compiler = Compiler::new();
    let descriptor = make_descriptor();
    let spec = compiler.compile_apple_vm(&descriptor);

    assert_eq!(spec.vm_name, "test-sandbox");
    assert_eq!(spec.image, "docker.io/library/alpine:3.19");
    assert_eq!(spec.vcpu_count, 2); // ceil(2.0) = 2
    assert_eq!(spec.memory_mb, 1024);
    assert_eq!(spec.disk_mb, 4096);

    // Virtio-fs mounts
    assert_eq!(spec.virtiofs_mounts.len(), 2);
    assert_eq!(spec.virtiofs_mounts[0].tag, "mount-0");
    assert!(spec.virtiofs_mounts[0].read_only);
    assert!(!spec.virtiofs_mounts[1].read_only);

    // Network
    assert!(spec.network.enabled);
    assert!(spec.network.nat);

    // Environment
    assert_eq!(spec.env.get("TEST"), Some(&"value".to_string()));
}

// ── AC.3: Both substrates produce structurally consistent output ─────────

#[test]
fn compile_both_produces_consistent_outputs() {
    let compiler = Compiler::new();
    let descriptor = make_descriptor();
    let (gvisor, apple, divergences) = compiler.compile_both(&descriptor);

    // Both should reference the same image
    assert_eq!(apple.image, descriptor.image);

    // Both should have the env var
    assert_eq!(gvisor.env.get("TEST"), apple.env.get("TEST"));

    // Both should handle 2 mounts
    assert_eq!(gvisor.mounts.len() - 1, apple.virtiofs_mounts.len()); // -1 for /proc
    assert_eq!(apple.virtiofs_mounts.len(), 2);

    // Divergences: only the /proc mount should be flagged
    for d in &divergences {
        // Divergences are structural: mount count difference due to /proc
        assert!(
            d.contains("mount-count") || d.contains("cpu"),
            "unexpected divergence: {d}"
        );
    }
}

// ── AC.3: 10-task agent workload equivalence ─────────────────────────────

#[test]
fn ten_task_workload_equivalence() {
    // Simulate 10 distinct agent task descriptors and verify each compiles
    // to both substrates with identical semantic content.
    let compiler = Compiler::new();
    let tasks: Vec<SandboxDescriptor> = (0..10)
        .map(|i| SandboxDescriptor {
            name: format!("task-{i}"),
            image: format!("ghcr.io/symphony/agent:v{i}"),
            resources: ResourceSpec {
                cpu_cores: 1.0 + (i as f64) * 0.5,
                memory_mb: 256 + (i as u64) * 128,
                disk_mb: 1024,
            },
            env: {
                let mut m = HashMap::new();
                m.insert("TASK_ID".into(), i.to_string());
                m
            },
            ..SandboxDescriptor {
                name: "dummy".into(),
                image: "img".into(),
                resources: ResourceSpec::default(),
                ..Default::default()
            }
        })
        .collect();

    for task in &tasks {
        let (gvisor, apple, _divergences) = compiler.compile_both(task);

        // Same name
        assert_eq!(gvisor.hostname, apple.vm_name);

        // Same env
        assert_eq!(gvisor.env.get("TASK_ID"), apple.env.get("TASK_ID"));

        // CPU equivalent (shares → vcpus)
        let gvisor_shares = gvisor
            .linux
            .as_ref()
            .and_then(|l| l.resources.as_ref())
            .and_then(|r| r.cpu_shares)
            .unwrap();
        let gvisor_vcpu_equiv = (gvisor_shares as f64 / 1024.0).ceil() as u32;
        assert_eq!(gvisor_vcpu_equiv, apple.vcpu_count);

        // Memory equivalent
        let gvisor_mem = gvisor
            .linux
            .as_ref()
            .and_then(|l| l.resources.as_ref())
            .and_then(|r| r.memory_limit)
            .unwrap();
        let gvisor_mem_mb = gvisor_mem / 1_048_576;
        assert_eq!(gvisor_mem_mb as u64, apple.memory_mb);
    }
}

// ── AC.4: Divergence detection ──────────────────────────────────────────

#[test]
fn divergence_registry_records_deltas() {
    let registry = DivergenceRegistry::new();
    let compiler = Compiler::with_divergence(registry.clone());

    let descriptor = make_descriptor();
    let (_, _, divergences) = compiler.compile_both(&descriptor);

    // All detected divergences should be logged
    let records = registry.get_all();
    assert_eq!(records.len(), divergences.len());

    // Each record has the substrate tags
    for record in &records {
        assert_eq!(record.descriptor_name, "test-sandbox");
        assert_eq!(record.substrate_a, SubstrateTag::GVisor);
        assert_eq!(record.substrate_b, SubstrateTag::AppleVm);
        assert!(!record.description.is_empty());
    }
}

#[test]
fn no_divergence_when_outputs_are_identical() {
    let compiler = Compiler::new();
    let descriptor = SandboxDescriptor {
        name: "simple".into(),
        image: "alpine".into(),
        resources: ResourceSpec::default(),
        env: HashMap::new(),
        mounts: vec![],
        ..SandboxDescriptor {
            name: "dummy".into(),
            image: "img".into(),
            resources: ResourceSpec::default(),
            ..Default::default()
        }
    };

    let (gvisor, apple, divergences) = compiler.compile_both(&descriptor);

    // Empty env, empty mounts → should be minimal divergence
    // (only /proc mount count and possibly CPU)
    for d in &divergences {
        assert!(d.contains("mount-count") || d.contains("cpu"),
            "unexpected divergence on minimal descriptor: {d}");
    }

    // But both should have the same env (empty)
    assert_eq!(gvisor.env.len(), apple.env.len());
}

// ── AC.5: Override hook is respected by compiler ─────────────────────────

#[test]
fn compile_respects_substrate_override_gvisor() {
    let compiler = Compiler::new();
    let mut descriptor = make_descriptor();
    descriptor.substrate_override = Some(Substrate::GVisor);

    let bundle = compiler.compile(&descriptor);
    assert!(bundle.is_gvisor());
    assert!(!bundle.is_apple_vm());
}

#[test]
fn compile_respects_substrate_override_apple_vm() {
    let compiler = Compiler::new();
    let mut descriptor = make_descriptor();
    descriptor.substrate_override = Some(Substrate::AppleVm);

    let bundle = compiler.compile(&descriptor);
    assert!(bundle.is_apple_vm());
    assert!(!bundle.is_gvisor());
}

// ── AC.7: Attestation flows through to compiled output ───────────────────

#[test]
fn attestation_flows_through_to_apple_vm_spec() {
    let compiler = Compiler::new();
    let mut descriptor = make_descriptor();
    descriptor.attestation = Some(super::super::descriptor::AttestationConfig {
        method: "cosign".into(),
        signer: "ci@symphony.dev".into(),
        rekor_url: None,
    });

    let spec = compiler.compile_apple_vm(&descriptor);
    let att = spec.attestation.as_ref().unwrap();
    assert_eq!(att.method, "cosign");
    assert_eq!(att.signer, "ci@symphony.dev");
}

// ── AC.8: Hebb bridge flows through to compiled output ───────────────────

#[test]
fn hebb_bridge_flows_through_to_apple_vm_spec() {
    let compiler = Compiler::new();
    let mut descriptor = make_descriptor();
    descriptor.hebb_bridge = Some(super::super::descriptor::HebbBridgeConfig {
        endpoint: "http://hebb:8080".into(),
        namespace: "test-ns".into(),
        max_entries: 5000,
    });

    let spec = compiler.compile_apple_vm(&descriptor);
    let hb = spec.hebb_bridge.as_ref().unwrap();
    assert_eq!(hb.endpoint, "http://hebb:8080");
    assert_eq!(hb.namespace, "test-ns");
    assert_eq!(hb.max_entries, 5000);
}

// ── AC.9: Checkpoint policy flows through to compiled output ─────────────

#[test]
fn checkpoint_policy_flows_through_to_apple_vm_spec() {
    let compiler = Compiler::new();
    let mut descriptor = make_descriptor();
    descriptor.checkpoint_policy = Some(super::super::descriptor::CheckpointPolicy {
        interval_secs: 300,
        max_snapshots: 3,
        snapshot_dir: "/var/snapshots".into(),
    });

    let spec = compiler.compile_apple_vm(&descriptor);
    let cp = spec.checkpoint_policy.as_ref().unwrap();
    assert_eq!(cp.interval_secs, 300);
    assert_eq!(cp.max_snapshots, 3);
    assert_eq!(cp.snapshot_dir, "/var/snapshots");
}

// ── AC.10 (B4-PLATFORM): OCI bundle is the lingua franca ─────────────────

#[test]
fn oci_bundle_serializes_to_standard_json() {
    let compiler = Compiler::new();
    let descriptor = make_descriptor();
    let bundle = compiler.compile_gvisor(&descriptor);

    let json = serde_json::to_string_pretty(&bundle).unwrap();

    // OCI spec requires ociVersion field
    assert!(json.contains(r#""oci_version": "1.0.2""#));
    // Must contain process args
    assert!(json.contains(r#""args""#));
    // Must contain root
    assert!(json.contains(r#""root""#));
    // Must contain mounts
    assert!(json.contains(r#""mounts""#));

    // Round-trip: deserialize back
    let restored: OciBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, restored);
}

#[test]
fn apple_vm_spec_serializes_to_standard_json() {
    let compiler = Compiler::new();
    let descriptor = make_descriptor();
    let spec = compiler.compile_apple_vm(&descriptor);

    let json = serde_json::to_string_pretty(&spec).unwrap();

    // Must contain vm_name
    assert!(json.contains(r#""vm_name": "test-sandbox""#));
    // Must contain vcpu_count
    assert!(json.contains(r#""vcpu_count": 2"#));
    // Must contain virtiofs_mounts
    assert!(json.contains(r#""virtiofs_mounts""#));

    // Round-trip
    let restored: AppleVmSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, restored);
}
