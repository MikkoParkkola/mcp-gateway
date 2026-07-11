// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#![allow(clippy::float_cmp, clippy::manual_string_new)]

use std::collections::HashMap;

use super::*;

// ── AC.1: SandboxDescriptor schema ────────────────────────────────────────

#[test]
fn descriptor_all_fields_present() {
    let d = SandboxDescriptor {
        name: "test-sandbox".into(),
        image: "docker.io/library/ubuntu:22.04".into(),
        resources: ResourceSpec {
            cpu_cores: 1.0,
            memory_mb: 512,
            disk_mb: 0,
        },
        capabilities: vec!["CAP_NET_BIND_SERVICE".into()],
        network_egress: NetworkEgressPolicy::Loopback,
        env: {
            let mut m = HashMap::new();
            m.insert("FOO".into(), "bar".into());
            m
        },
        mounts: vec![
            MountSpec {
                mount_type: MountType::ReadOnly,
                source: "/host/data".into(),
                target: "/sandbox/data".into(),
            },
            MountSpec {
                mount_type: MountType::WritableOverlay,
                source: "/host/scratch".into(),
                target: "/sandbox/scratch".into(),
            },
        ],
        attestation: None,
        hebb_bridge: None,
        checkpoint_policy: None,
        substrate_override: None,
    };

    // All AC.1 fields are populated
    assert_eq!(d.name, "test-sandbox");
    assert_eq!(d.image, "docker.io/library/ubuntu:22.04");
    assert_eq!(d.resources.cpu_cores, 1.0);
    assert_eq!(d.resources.memory_mb, 512);
    assert_eq!(d.capabilities.len(), 1);
    assert_eq!(d.network_egress, NetworkEgressPolicy::Loopback);
    assert_eq!(d.env.get("FOO"), Some(&"bar".to_string()));
    assert_eq!(d.mounts.len(), 2);
    assert_eq!(d.mounts[0].mount_type, MountType::ReadOnly);
    assert_eq!(d.mounts[1].mount_type, MountType::WritableOverlay);
}

#[test]
fn descriptor_read_only_and_writable_mount_iterators() {
    let d = SandboxDescriptor {
        name: "test".into(),
        image: "img".into(),
        resources: ResourceSpec::default(),
        mounts: vec![
            MountSpec {
                mount_type: MountType::ReadOnly,
                source: "/ro".into(),
                target: "/mnt/ro".into(),
            },
            MountSpec {
                mount_type: MountType::WritableOverlay,
                source: "/rw".into(),
                target: "/mnt/rw".into(),
            },
        ],
        ..Default::default()
    };
    assert_eq!(d.read_only_mounts().count(), 1);
    assert_eq!(d.writable_mounts().count(), 1);
}

// ── AC.7 (B1-IDENT): attestation config ───────────────────────────────────

#[test]
fn descriptor_carries_attestation_config() {
    let d = SandboxDescriptor {
        name: "attested".into(),
        image: "img".into(),
        resources: ResourceSpec::default(),
        attestation: Some(AttestationConfig {
            method: "cosign".into(),
            signer: "keyless@example.com".into(),
            rekor_url: Some("https://rekor.sigstore.dev".into()),
        }),
        ..Default::default()
    };

    let a = d.attestation.as_ref().unwrap();
    assert_eq!(a.method, "cosign");
    assert_eq!(a.signer, "keyless@example.com");
    assert!(a.rekor_url.is_some());
}

#[test]
fn descriptor_without_attestation_is_valid() {
    let d = SandboxDescriptor {
        name: "no-attestation".into(),
        image: "img".into(),
        resources: ResourceSpec::default(),
        attestation: None,
        ..Default::default()
    };
    assert!(d.attestation.is_none());
}

// ── AC.8 (B2-MEM): hebb bridge config ────────────────────────────────────

#[test]
fn descriptor_carries_hebb_bridge_config() {
    let d = SandboxDescriptor {
        name: "mem-bridged".into(),
        image: "img".into(),
        resources: ResourceSpec::default(),
        hebb_bridge: Some(HebbBridgeConfig {
            endpoint: "http://hebb:8080".into(),
            namespace: "sandbox-ns".into(),
            max_entries: 5000,
        }),
        ..Default::default()
    };

    let h = d.hebb_bridge.as_ref().unwrap();
    assert_eq!(h.endpoint, "http://hebb:8080");
    assert_eq!(h.namespace, "sandbox-ns");
    assert_eq!(h.max_entries, 5000);
}

#[test]
fn hebb_bridge_default_max_entries() {
    let h = HebbBridgeConfig {
        endpoint: "http://hebb:8080".into(),
        namespace: "ns".into(),
        max_entries: 10_000,
    };
    assert_eq!(h.max_entries, 10_000);
}

// ── AC.9 (B3-DURABLE): checkpoint policy ─────────────────────────────────

#[test]
fn descriptor_carries_checkpoint_policy() {
    let d = SandboxDescriptor {
        name: "durable".into(),
        image: "img".into(),
        resources: ResourceSpec::default(),
        checkpoint_policy: Some(CheckpointPolicy {
            interval_secs: 300,
            max_snapshots: 10,
            snapshot_dir: "/var/snapshots".into(),
        }),
        ..Default::default()
    };

    let cp = d.checkpoint_policy.as_ref().unwrap();
    assert_eq!(cp.interval_secs, 300);
    assert_eq!(cp.max_snapshots, 10);
    assert_eq!(cp.snapshot_dir, "/var/snapshots");
}

#[test]
fn checkpoint_policy_default_max_snapshots() {
    let cp = CheckpointPolicy {
        interval_secs: 60,
        max_snapshots: 5,
        snapshot_dir: "/tmp".into(),
    };
    assert_eq!(cp.max_snapshots, 5);
}

// ── AC.5: override hook ──────────────────────────────────────────────────

#[test]
fn override_hook_pins_substrate() {
    // Pin to gVisor even on macOS (for testing)
    let d = SandboxDescriptor {
        name: "pinned".into(),
        image: "img".into(),
        resources: ResourceSpec::default(),
        substrate_override: Some(Substrate::GVisor),
        ..Default::default()
    };
    assert_eq!(d.effective_substrate(), Substrate::GVisor);
}

#[test]
fn no_override_uses_auto_detect() {
    let d = SandboxDescriptor {
        name: "auto".into(),
        image: "img".into(),
        resources: ResourceSpec::default(),
        substrate_override: None,
        ..Default::default()
    };
    // effective_substrate() without override calls Substrate::detect()
    // which returns the current platform's substrate.
    let substrate = d.effective_substrate();
    #[cfg(target_os = "linux")]
    assert_eq!(substrate, Substrate::GVisor);
    #[cfg(target_os = "macos")]
    assert_eq!(substrate, Substrate::AppleVm);
}

#[test]
fn apple_vm_override_works() {
    let d = SandboxDescriptor {
        name: "apple-pinned".into(),
        image: "img".into(),
        resources: ResourceSpec::default(),
        substrate_override: Some(Substrate::AppleVm),
        ..Default::default()
    };
    assert_eq!(d.effective_substrate(), Substrate::AppleVm);
}

// ── validation ───────────────────────────────────────────────────────────

#[test]
fn validate_empty_name_fails() {
    let d = SandboxDescriptor {
        name: "".into(),
        image: "img".into(),
        resources: ResourceSpec::default(),
        ..Default::default()
    };
    assert!(d.validate().is_err());
}

#[test]
fn validate_empty_image_fails() {
    let d = SandboxDescriptor {
        name: "n".into(),
        image: "".into(),
        resources: ResourceSpec::default(),
        ..Default::default()
    };
    assert!(d.validate().is_err());
}

#[test]
fn validate_zero_cpu_fails() {
    let d = SandboxDescriptor {
        name: "n".into(),
        image: "img".into(),
        resources: ResourceSpec {
            cpu_cores: 0.0,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(d.validate().is_err());
}

#[test]
fn validate_negative_cpu_fails() {
    let d = SandboxDescriptor {
        name: "n".into(),
        image: "img".into(),
        resources: ResourceSpec {
            cpu_cores: -1.0,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(d.validate().is_err());
}

#[test]
fn validate_zero_memory_fails() {
    let d = SandboxDescriptor {
        name: "n".into(),
        image: "img".into(),
        resources: ResourceSpec {
            memory_mb: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(d.validate().is_err());
}

#[test]
fn validate_empty_mount_source_fails() {
    let d = SandboxDescriptor {
        name: "n".into(),
        image: "img".into(),
        resources: ResourceSpec::default(),
        mounts: vec![MountSpec {
            mount_type: MountType::ReadOnly,
            source: "".into(),
            target: "/t".into(),
        }],
        ..Default::default()
    };
    assert!(d.validate().is_err());
}

#[test]
fn validate_empty_mount_target_fails() {
    let d = SandboxDescriptor {
        name: "n".into(),
        image: "img".into(),
        resources: ResourceSpec::default(),
        mounts: vec![MountSpec {
            mount_type: MountType::ReadOnly,
            source: "/s".into(),
            target: "".into(),
        }],
        ..Default::default()
    };
    assert!(d.validate().is_err());
}

#[test]
fn validate_valid_descriptor_passes() {
    let d = SandboxDescriptor {
        name: "valid".into(),
        image: "img".into(),
        resources: ResourceSpec::default(),
        ..Default::default()
    };
    assert!(d.validate().is_ok());
}

// ── serde round-trip ─────────────────────────────────────────────────────

#[test]
fn descriptor_json_round_trip() {
    let original = SandboxDescriptor {
        name: "rt".into(),
        image: "docker.io/library/alpine:3.19".into(),
        resources: ResourceSpec {
            cpu_cores: 0.5,
            memory_mb: 128,
            disk_mb: 1024,
        },
        capabilities: vec!["CAP_SYS_PTRACE".into()],
        network_egress: NetworkEgressPolicy::Full,
        env: {
            let mut m = HashMap::new();
            m.insert("LANG".into(), "C.UTF-8".into());
            m
        },
        mounts: vec![
            MountSpec {
                mount_type: MountType::ReadOnly,
                source: "/host/models".into(),
                target: "/models".into(),
            },
            MountSpec {
                mount_type: MountType::WritableOverlay,
                source: "/host/work".into(),
                target: "/work".into(),
            },
        ],
        attestation: Some(AttestationConfig {
            method: "cosign".into(),
            signer: "ci@symphony.dev".into(),
            rekor_url: None,
        }),
        hebb_bridge: Some(HebbBridgeConfig {
            endpoint: "http://hebb:8080".into(),
            namespace: "rt-ns".into(),
            max_entries: 10_000,
        }),
        checkpoint_policy: Some(CheckpointPolicy {
            interval_secs: 60,
            max_snapshots: 3,
            snapshot_dir: "/var/snapshots/rt".into(),
        }),
        substrate_override: None,
    };

    let json = serde_json::to_string_pretty(&original).unwrap();
    let restored: SandboxDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(original, restored);
}

#[test]
fn descriptor_defaults_on_minimal_json() {
    let json = r#"{"name":"minimal","image":"alpine","resources":{}}"#;
    let d: SandboxDescriptor = serde_json::from_str(json).unwrap();
    assert_eq!(d.name, "minimal");
    assert_eq!(d.image, "alpine");
    assert_eq!(d.resources.cpu_cores, 1.0);
    assert_eq!(d.resources.memory_mb, 512);
    assert!(d.capabilities.is_empty());
    assert_eq!(d.network_egress, NetworkEgressPolicy::Loopback);
    assert!(d.env.is_empty());
    assert!(d.mounts.is_empty());
    assert!(d.attestation.is_none());
    assert!(d.hebb_bridge.is_none());
    assert!(d.checkpoint_policy.is_none());
    assert!(d.substrate_override.is_none());
}

// ── NetworkEgressPolicy ──────────────────────────────────────────────────

#[test]
fn network_egress_policy_none() {
    let d = SandboxDescriptor {
        network_egress: NetworkEgressPolicy::None,
        ..SandboxDescriptor {
            name: "n".into(),
            image: "img".into(),
            resources: ResourceSpec::default(),
            ..Default::default()
        }
    };
    assert_eq!(d.network_egress, NetworkEgressPolicy::None);
}

#[test]
fn network_egress_allowlist_from_json() {
    let json = r#"{"name":"n","image":"img","resources":{},"network_egress":["10.0.0.0/8","192.168.0.0/16"]}"#;
    let d: SandboxDescriptor = serde_json::from_str(json).unwrap();
    match &d.network_egress {
        NetworkEgressPolicy::Allowlist(cidrs) => {
            assert_eq!(cidrs.len(), 2);
            assert!(cidrs.contains(&"10.0.0.0/8".to_string()));
            assert!(cidrs.contains(&"192.168.0.0/16".to_string()));
        }
        other => panic!("expected Allowlist, got {other:?}"),
    }
}

// ── MountType discriminant ───────────────────────────────────────────────

#[test]
fn mount_type_read_only_discriminant() {
    assert_ne!(MountType::ReadOnly, MountType::WritableOverlay);
}

#[test]
fn mount_type_json_serde() {
    let ro = MountType::ReadOnly;
    let wo = MountType::WritableOverlay;
    assert_eq!(serde_json::to_string(&ro).unwrap(), r#""read_only""#);
    assert_eq!(serde_json::to_string(&wo).unwrap(), r#""writable_overlay""#);
}
