//! Wiring tests for the runtime-substrate provisioning call path.
//!
//! These exercise [`super`] — the hardened entry point that turns the dormant
//! [`Compiler`](crate::runtime::compiler::Compiler) into a reachable,
//! gate-checked call path. Every test names the adversarial-review finding it
//! covers.

use super::*;
use crate::runtime::descriptor::{
    MountSpec, MountType, NetworkEgressPolicy, ResourceSpec, SandboxDescriptor,
};

/// Build a minimal valid descriptor for mutation in tests.
fn base() -> SandboxDescriptor {
    SandboxDescriptor {
        name: "wiring-test".to_string(),
        image: "docker.io/library/ubuntu:22.04".to_string(),
        resources: ResourceSpec {
            cpu_cores: 1.0,
            memory_mb: 256,
            disk_mb: 0,
        },
        ..Default::default()
    }
}

// ── Happy path ──────────────────────────────────────────────────────────────

#[test]
fn wiring_compiles_valid_descriptor() {
    let report = compile_descriptor(&base(), false).expect("valid descriptor must compile");
    // It actually reached the compiler and produced a bundle.
    assert!(report.bundle.is_gvisor() || report.bundle.is_apple_vm());
}

#[test]
fn wiring_compile_both_records_known_divergence() {
    // --both path must populate divergences (AC.3/AC.4 reachable from wiring).
    let report = compile_descriptor(&base(), true).expect("compile both");
    assert!(
        !report.divergences.is_empty(),
        "compile_both should record at least the /proc mount-count divergence"
    );
}

// ── Finding #2: compile() never validates ────────────────────────────────────

#[test]
fn wiring_rejects_empty_name() {
    let mut d = base();
    d.name = String::new();
    let err = compile_descriptor(&d, false).unwrap_err();
    assert!(matches!(
        err,
        ProvisionError::Preflight(PreflightError::Schema(_))
    ));
}

#[test]
fn wiring_rejects_zero_memory() {
    let mut d = base();
    d.resources.memory_mb = 0;
    let err = compile_descriptor(&d, false).unwrap_err();
    assert!(matches!(
        err,
        ProvisionError::Preflight(PreflightError::Schema(_))
    ));
}

// ── Finding #8: NaN cpu slips past validate() ─────────────────────────────────

#[test]
fn wiring_rejects_nan_cpu() {
    let mut d = base();
    d.resources.cpu_cores = f64::NAN;
    let err = compile_descriptor(&d, false).unwrap_err();
    assert!(
        matches!(err, ProvisionError::Preflight(PreflightError::NonFiniteCpu)),
        "NaN cpu_cores must be rejected (validate() lets it through)"
    );
}

#[test]
fn wiring_rejects_infinite_cpu() {
    let mut d = base();
    d.resources.cpu_cores = f64::INFINITY;
    let err = compile_descriptor(&d, false).unwrap_err();
    assert!(matches!(
        err,
        ProvisionError::Preflight(PreflightError::NonFiniteCpu)
    ));
}

// ── Finding #4: privilege boundaries / dangerous capabilities ────────────────

#[test]
fn wiring_rejects_forbidden_capability() {
    let mut d = base();
    d.capabilities = vec!["CAP_SYS_ADMIN".to_string()];
    let err = compile_descriptor(&d, false).unwrap_err();
    assert!(matches!(
        err,
        ProvisionError::Preflight(PreflightError::ForbiddenCapability(_))
    ));
}

#[test]
fn wiring_forbidden_capability_is_case_insensitive() {
    let mut d = base();
    d.capabilities = vec!["cap_sys_admin".to_string()];
    let err = compile_descriptor(&d, false).unwrap_err();
    assert!(matches!(
        err,
        ProvisionError::Preflight(PreflightError::ForbiddenCapability(_))
    ));
}

// ── Finding #5: injection / unsafe mount sources ─────────────────────────────

#[test]
fn wiring_rejects_path_traversal_mount() {
    let mut d = base();
    d.mounts = vec![MountSpec {
        mount_type: MountType::ReadOnly,
        source: "/srv/data/../../etc".to_string(),
        target: "/data".to_string(),
    }];
    let err = compile_descriptor(&d, false).unwrap_err();
    assert!(matches!(
        err,
        ProvisionError::Preflight(PreflightError::UnsafeMountSource(_))
    ));
}

#[test]
fn wiring_rejects_host_root_mount() {
    let mut d = base();
    d.mounts = vec![MountSpec {
        mount_type: MountType::WritableOverlay,
        source: "/".to_string(),
        target: "/host".to_string(),
    }];
    let err = compile_descriptor(&d, false).unwrap_err();
    assert!(matches!(
        err,
        ProvisionError::Preflight(PreflightError::UnsafeMountSource(_))
    ));
}

#[test]
fn wiring_rejects_sensitive_prefix_mount() {
    let mut d = base();
    d.mounts = vec![MountSpec {
        mount_type: MountType::ReadOnly,
        source: "/etc/shadow".to_string(),
        target: "/x".to_string(),
    }];
    let err = compile_descriptor(&d, false).unwrap_err();
    assert!(matches!(
        err,
        ProvisionError::Preflight(PreflightError::UnsafeMountSource(_))
    ));
}

#[test]
fn wiring_rejects_relative_mount_source() {
    let mut d = base();
    d.mounts = vec![MountSpec {
        mount_type: MountType::ReadOnly,
        source: "relative/path".to_string(),
        target: "/x".to_string(),
    }];
    let err = compile_descriptor(&d, false).unwrap_err();
    assert!(matches!(
        err,
        ProvisionError::Preflight(PreflightError::RelativeMountSource(_))
    ));
}

#[test]
fn wiring_allows_safe_mount() {
    let mut d = base();
    d.mounts = vec![MountSpec {
        mount_type: MountType::ReadOnly,
        source: "/srv/workspace".to_string(),
        target: "/workspace".to_string(),
    }];
    assert!(compile_descriptor(&d, false).is_ok());
}

// ── MIK-5226.SEC.2: egress is compiled into an enforceable config ────────────

#[test]
fn wiring_emits_none_egress_as_deny_all() {
    let mut d = base();
    d.network_egress = NetworkEgressPolicy::None;
    let report = compile_descriptor(&d, false).expect("None egress still compiles");
    // Informational note references the policy.
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("network_egress=None")),
        "operator should be told None compiles to deny-all and needs launcher enforcement"
    );
    // The emitted bundle proves a blocked destination is unreachable.
    match &report.bundle {
        crate::runtime::compiler::CompiledBundle::GVisor(b) => {
            assert!(!b.egress.allows("8.8.8.8"));
            assert!(!b.egress.allows("127.0.0.1"));
        }
        crate::runtime::compiler::CompiledBundle::AppleVm(s) => {
            assert!(!s.egress.allows("8.8.8.8"));
            assert!(!s.egress.allows("127.0.0.1"));
        }
    }
}

#[test]
fn wiring_emits_allowlist_egress_as_restricted() {
    let mut d = base();
    d.network_egress = NetworkEgressPolicy::Allowlist(vec!["10.0.0.0/8".to_string()]);
    let report = compile_descriptor(&d, false).expect("allowlist still compiles");
    assert!(
        report.warnings.iter().any(|w| w.contains("allowlist")),
        "operator should be told the allowlist compiles to a restricted config"
    );
    // The emitted bundle proves a destination outside the allowlist is blocked.
    match &report.bundle {
        crate::runtime::compiler::CompiledBundle::GVisor(b) => {
            assert!(b.egress.allows("10.1.2.3"));
            assert!(!b.egress.allows("8.8.8.8"));
        }
        crate::runtime::compiler::CompiledBundle::AppleVm(s) => {
            assert!(s.egress.allows("10.1.2.3"));
            assert!(!s.egress.allows("8.8.8.8"));
        }
    }
}

// ── MIK-5226.SEC.1: gVisor now EMITS capabilities (no silent drop) ───────────

#[test]
fn wiring_gvisor_no_longer_warns_dropped_capabilities() {
    let mut d = base();
    d.substrate_override = Some(Substrate::GVisor);
    d.capabilities = vec!["CAP_NET_BIND_SERVICE".to_string()];
    let report = compile_descriptor(&d, false).expect("benign cap compiles");
    assert!(
        !report
            .warnings
            .iter()
            .any(|w| w.contains("silently dropped")),
        "capabilities are now emitted into the OCI bundle — the drop warning must be gone"
    );
    // And they are actually present in the emitted gVisor bundle.
    match &report.bundle {
        crate::runtime::compiler::CompiledBundle::GVisor(b) => {
            let caps = b
                .process
                .capabilities
                .as_ref()
                .expect("gVisor bundle must carry capabilities");
            assert!(caps.bounding.contains(&"CAP_NET_BIND_SERVICE".to_string()));
            assert!(caps.effective.contains(&"CAP_NET_BIND_SERVICE".to_string()));
            assert!(caps.permitted.contains(&"CAP_NET_BIND_SERVICE".to_string()));
        }
        crate::runtime::compiler::CompiledBundle::AppleVm(_) => {
            panic!("substrate_override=GVisor must yield a gVisor bundle")
        }
    }
}

// ── File path entry point ─────────────────────────────────────────────────────

#[test]
fn wiring_file_entry_parses_yaml_and_compiles() {
    let dir = std::env::temp_dir();
    let path = dir.join("mik5226_wiring_descriptor.yaml");
    std::fs::write(
        &path,
        "name: file-test\nimage: docker.io/library/alpine:3\nresources:\n  cpu_cores: 1.0\n  memory_mb: 128\n",
    )
    .unwrap();
    let report = compile_descriptor_file(&path, false).expect("yaml file must compile");
    assert_eq!(
        report.substrate,
        SandboxDescriptor {
            name: "x".into(),
            image: "y".into(),
            ..Default::default()
        }
        .effective_substrate()
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn wiring_file_entry_reports_missing_file() {
    let path = std::path::Path::new("/nonexistent/mik5226/does-not-exist.yaml");
    let err = compile_descriptor_file(path, false).unwrap_err();
    assert!(matches!(err, ProvisionError::Io(_)));
}

#[test]
fn wiring_file_entry_reports_parse_error() {
    let dir = std::env::temp_dir();
    let path = dir.join("mik5226_wiring_bad.yaml");
    std::fs::write(&path, "name: [this is: not valid: yaml").unwrap();
    let err = compile_descriptor_file(&path, false).unwrap_err();
    assert!(matches!(err, ProvisionError::Parse(_)));
    let _ = std::fs::remove_file(&path);
}
