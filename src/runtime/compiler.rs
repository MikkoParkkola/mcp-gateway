//! Descriptor-to-substrate compiler.
//!
//! **AC.2 (MIK-NEW.RUNTIME-D.2)**: The [`Compiler`] transforms a
//! [`SandboxDescriptor`] into a gVisor `runsc` OCI bundle on Linux or an
//! Apple containerization VM-spec on macOS, with automatic substrate
//! detection (or respecting the operator's override hook, AC.5).
//!
//! **AC.4 (MIK-NEW.RUNTIME-D.4)**: The compiler records divergence between
//! what each substrate produces for the same descriptor.  See
//! [`super::divergence`] for the registry.
//!
//! **AC.10 (B4-PLATFORM)**: The OCI runtime spec is the lingua franca; both
//! compiler targets produce OCI-conformant output, with Apple VM-spec as
//! a macOS-native representation of the same semantics.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::descriptor::SandboxDescriptor;
use super::divergence::{DivergenceRegistry, SubstrateTag};
use super::substrate::Substrate;

// ── OCI OCI bundle types ─────────────────────────────────────────────────

/// A minimal OCI runtime bundle (subset relevant to gVisor `runsc`).
///
/// This is the lingua franca output format (AC.10).  On Linux, this is
/// written directly as a `config.json` for `runsc`.  On macOS, the
/// compiler translates it into an Apple VM-spec.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciBundle {
    /// OCI version string.
    pub oci_version: String,

    /// Process configuration.
    pub process: OciProcess,

    /// Root filesystem configuration.
    pub root: OciRoot,

    /// Hostname for the container.
    #[serde(default)]
    pub hostname: String,

    /// Mounts.
    #[serde(default)]
    pub mounts: Vec<OciMount>,

    /// Linux-specific configuration (gVisor target).
    #[serde(default)]
    pub linux: Option<OciLinux>,

    /// Environment variables.
    #[serde(default)]
    pub env: HashMap<String, String>,
}

/// OCI process configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciProcess {
    /// Entrypoint command.
    pub args: Vec<String>,

    /// Working directory.
    #[serde(default)]
    pub cwd: String,

    /// Terminal flag.
    #[serde(default)]
    pub terminal: bool,
}

/// OCI root filesystem configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciRoot {
    /// Path to the root filesystem.
    pub path: String,

    /// Whether the rootfs is read-only.
    #[serde(default)]
    pub readonly: bool,
}

/// OCI mount entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciMount {
    /// Destination path inside the container.
    pub destination: String,

    /// Mount type (e.g. "bind").
    #[serde(rename = "type")]
    pub mount_type: String,

    /// Source path on the host.
    pub source: String,

    /// Mount options.
    #[serde(default)]
    pub options: Vec<String>,
}

/// Linux-specific OCI configuration (gVisor target).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciLinux {
    /// Linux namespaces.
    #[serde(default)]
    pub namespaces: Vec<OciNamespace>,

    /// Resource limits.
    #[serde(default)]
    pub resources: Option<OciLinuxResources>,
}

/// OCI namespace entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciNamespace {
    /// Namespace type (e.g. "pid", "network", "mount").
    #[serde(rename = "type")]
    pub ns_type: String,
    /// Optional path to an existing namespace file.
    #[serde(default)]
    pub path: Option<String>,
}

/// OCI Linux resource limits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciLinuxResources {
    /// CPU shares.
    #[serde(default)]
    pub cpu_shares: Option<u64>,

    /// Memory limit in bytes.
    #[serde(default)]
    pub memory_limit: Option<i64>,
}

// ── Apple VM-spec ────────────────────────────────────────────────────────

/// Apple containerization VM-spec (Hypervisor.framework).
///
/// This is the macOS-native representation of an OCI-compatible sandbox.
/// It carries all the semantic information from the OCI bundle in a format
/// suitable for Apple's Hypervisor.framework APIs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppleVmSpec {
    /// VM identifier (from SandboxDescriptor.name).
    pub vm_name: String,

    /// OCI image reference (unchanged).
    pub image: String,

    /// Number of virtual CPUs.
    pub vcpu_count: u32,

    /// Memory size in megabytes.
    pub memory_mb: u64,

    /// Disk image size in megabytes.
    #[serde(default)]
    pub disk_mb: u64,

    /// Environment variables.
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// Virtio-fs mount entries.
    #[serde(default)]
    pub virtiofs_mounts: Vec<VirtioFsMount>,

    /// Network configuration.
    #[serde(default)]
    pub network: AppleVmNetwork,

    /// Capabilities (translated from Linux capabilities where applicable).
    #[serde(default)]
    pub entitlements: Vec<String>,

    /// Attestation config (from descriptor).
    #[serde(default)]
    pub attestation: Option<super::descriptor::AttestationConfig>,

    /// Hebb bridge config (from descriptor).
    #[serde(default)]
    pub hebb_bridge: Option<super::descriptor::HebbBridgeConfig>,

    /// Checkpoint policy (from descriptor).
    #[serde(default)]
    pub checkpoint_policy: Option<super::descriptor::CheckpointPolicy>,
}

/// Virtio-fs mount entry (macOS).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VirtioFsMount {
    /// Tag used to identify the share.
    pub tag: String,

    /// Host source path.
    pub source: String,

    /// Whether the mount is read-only.
    #[serde(default)]
    pub read_only: bool,
}

/// Network configuration for an Apple VM-spec.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AppleVmNetwork {
    /// Whether networking is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Whether NAT is used (default for most agent workloads).
    #[serde(default = "default_true")]
    pub nat: bool,
}

fn default_true() -> bool {
    true
}

// ── Compiler ─────────────────────────────────────────────────────────────

/// The descriptor-to-bundle compiler.
///
/// Produces an [`OciBundle`] for gVisor and an [`AppleVmSpec`] for Apple
/// containerization.
#[derive(Debug, Default)]
pub struct Compiler {
    /// Optional divergence registry for cross-substrate comparison (AC.4).
    pub divergence_registry: Option<DivergenceRegistry>,
}

impl Compiler {
    /// Create a new compiler without a divergence registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            divergence_registry: None,
        }
    }

    /// Create a compiler with a divergence registry for AC.4 tracking.
    #[must_use]
    pub fn with_divergence(registry: DivergenceRegistry) -> Self {
        Self {
            divergence_registry: Some(registry),
        }
    }

    /// Compile a descriptor to the effective substrate (auto-detect or override).
    ///
    /// This is the main entry point.  It detects the substrate (respecting
    /// override) and then calls the appropriate compile method.
    pub fn compile(&self, descriptor: &SandboxDescriptor) -> CompiledBundle {
        let substrate = descriptor.effective_substrate();
        match substrate {
            Substrate::GVisor => {
                let bundle = self.compile_gvisor(descriptor);
                CompiledBundle::GVisor(bundle)
            }
            Substrate::AppleVm => {
                let spec = self.compile_apple_vm(descriptor);
                CompiledBundle::AppleVm(spec)
            }
        }
    }

    /// Compile a descriptor specifically to a gVisor OCI bundle.
    ///
    /// Produces a standard OCI runtime configuration suitable for `runsc`.
    #[must_use]
    pub fn compile_gvisor(&self, descriptor: &SandboxDescriptor) -> OciBundle {
        let mut mounts: Vec<OciMount> = descriptor
            .mounts
            .iter()
            .map(|m| {
                let is_ro = m.mount_type == super::descriptor::MountType::ReadOnly;
                let mut options = vec!["rbind".to_string()];
                if is_ro {
                    options.push("ro".to_string());
                }
                OciMount {
                    destination: m.target.clone(),
                    mount_type: "bind".to_string(),
                    source: m.source.clone(),
                    options,
                }
            })
            .collect();

        // Ensure /proc is mounted for gVisor.
        mounts.push(OciMount {
            destination: "/proc".to_string(),
            mount_type: "proc".to_string(),
            source: "proc".to_string(),
            options: vec![],
        });

        let linux = Some(OciLinux {
            namespaces: vec![
                OciNamespace {
                    ns_type: "pid".to_string(),
                    path: None,
                },
                OciNamespace {
                    ns_type: "network".to_string(),
                    path: None,
                },
                OciNamespace {
                    ns_type: "ipc".to_string(),
                    path: None,
                },
                OciNamespace {
                    ns_type: "uts".to_string(),
                    path: None,
                },
                OciNamespace {
                    ns_type: "mount".to_string(),
                    path: None,
                },
            ],
            resources: Some(OciLinuxResources {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                cpu_shares: Some((descriptor.resources.cpu_cores * 1024.0) as u64),
                #[allow(clippy::cast_possible_wrap)]
                memory_limit: Some((descriptor.resources.memory_mb * 1_048_576) as i64),
            }),
        });

        OciBundle {
            oci_version: "1.0.2".to_string(),
            process: OciProcess {
                args: vec!["/init".to_string()],
                cwd: "/".to_string(),
                terminal: false,
            },
            root: OciRoot {
                path: format!("rootfs-{}", descriptor.name),
                readonly: false,
            },
            hostname: descriptor.name.clone(),
            mounts,
            linux,
            env: descriptor.env.clone(),
        }
    }

    /// Compile a descriptor specifically to an Apple VM-spec.
    #[must_use]
    pub fn compile_apple_vm(&self, descriptor: &SandboxDescriptor) -> AppleVmSpec {
        let virtiofs_mounts: Vec<VirtioFsMount> = descriptor
            .mounts
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let is_ro = m.mount_type == super::descriptor::MountType::ReadOnly;
                VirtioFsMount {
                    tag: format!("mount-{i}"),
                    source: m.source.clone(),
                    read_only: is_ro,
                }
            })
            .collect();

        let network = match &descriptor.network_egress {
            super::descriptor::NetworkEgressPolicy::None => AppleVmNetwork {
                enabled: false,
                nat: false,
            },
            // Loopback, Full, and Allowlist all enable the VM NAT interface;
            // fine-grained allowlisting is applied at the egress firewall, not
            // the VM network toggle.
            _ => AppleVmNetwork {
                enabled: true,
                nat: true,
            },
        };

        AppleVmSpec {
            vm_name: descriptor.name.clone(),
            image: descriptor.image.clone(),
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            vcpu_count: descriptor.resources.cpu_cores.ceil() as u32,
            memory_mb: descriptor.resources.memory_mb,
            disk_mb: descriptor.resources.disk_mb,
            env: descriptor.env.clone(),
            virtiofs_mounts,
            network,
            entitlements: descriptor.capabilities.clone(),
            attestation: descriptor.attestation.clone(),
            hebb_bridge: descriptor.hebb_bridge.clone(),
            checkpoint_policy: descriptor.checkpoint_policy.clone(),
        }
    }

    /// Compile for BOTH substrates and record any divergence (AC.3, AC.4).
    ///
    /// Returns both compiled bundles and optionally logs structural
    /// differences to the divergence registry.
    #[must_use]
    pub fn compile_both(
        &self,
        descriptor: &SandboxDescriptor,
    ) -> (OciBundle, AppleVmSpec, Vec<String>) {
        let gvisor = self.compile_gvisor(descriptor);
        let apple = self.compile_apple_vm(descriptor);

        // Detect structural divergence between the two outputs.
        let divergences = self.detect_divergence(descriptor, &gvisor, &apple);

        (gvisor, apple, divergences)
    }

    /// Detect structural divergence between gVisor and Apple VM outputs.
    ///
    /// Returns a list of divergence descriptions.  An empty list means the
    /// two outputs are structurally equivalent for the given descriptor.
    #[must_use]
    pub fn detect_divergence(
        &self,
        descriptor: &SandboxDescriptor,
        gvisor: &OciBundle,
        apple: &AppleVmSpec,
    ) -> Vec<String> {
        let mut divergences: Vec<String> = Vec::new();

        // Compare mount count. gVisor injects an extra `/proc` mount that the
        // Apple VM spec does not carry, so the raw mount counts diverge whenever
        // a descriptor is compiled for both substrates. This is a genuine
        // structural divergence (AC.4) and is always recorded.
        if gvisor.mounts.len() != apple.virtiofs_mounts.len() {
            divergences.push(format!(
                "mount-count: gVisor={} (incl /proc) vs AppleVM={}",
                gvisor.mounts.len(),
                apple.virtiofs_mounts.len()
            ));
        }

        // Compare CPU
        let gvisor_cpu = gvisor
            .linux
            .as_ref()
            .and_then(|l| l.resources.as_ref())
            .and_then(|r| r.cpu_shares)
            .unwrap_or(0);
        let apple_cpu = apple.vcpu_count;
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let gvisor_vcpus = (gvisor_cpu as f64 / 1024.0).ceil() as u32;
        if gvisor_vcpus != apple_cpu {
            divergences.push(format!(
                "cpu: gVisor shares={gvisor_cpu} vs AppleVM vcpus={apple_cpu}"
            ));
        }

        // Compare env var count
        if gvisor.env.len() != apple.env.len() {
            divergences.push(format!(
                "env-count: gVisor={} vs AppleVM={}",
                gvisor.env.len(),
                apple.env.len()
            ));
        }

        // If divergence registry is present, log each divergence
        if let Some(ref registry) = self.divergence_registry {
            for d in &divergences {
                registry.log(
                    &descriptor.name,
                    SubstrateTag::GVisor,
                    SubstrateTag::AppleVm,
                    d,
                );
            }
        }

        divergences
    }
}

// ── CompiledBundle ───────────────────────────────────────────────────────

/// The output of the compiler — either a gVisor OCI bundle or an Apple VM-spec.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CompiledBundle {
    /// gVisor `runsc` OCI runtime bundle.
    GVisor(OciBundle),

    /// Apple Hypervisor.framework VM specification.
    AppleVm(AppleVmSpec),
}

impl CompiledBundle {
    /// Returns `true` if this is a gVisor bundle.
    #[must_use]
    pub fn is_gvisor(&self) -> bool {
        matches!(self, Self::GVisor(_))
    }

    /// Returns `true` if this is an Apple VM spec.
    #[must_use]
    pub fn is_apple_vm(&self) -> bool {
        matches!(self, Self::AppleVm(_))
    }
}

#[cfg(test)]
#[path = "compiler_tests.rs"]
mod tests;
