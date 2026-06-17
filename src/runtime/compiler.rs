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

use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use super::descriptor::{NetworkEgressPolicy, SandboxDescriptor};
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

    /// Enforceable network-egress configuration emitted to the substrate.
    ///
    /// **MIK-5226.SEC.2**: previously `network_egress` was decorative — the
    /// gVisor compiler never emitted it, so every sandbox got a full network
    /// namespace regardless of policy (fail-open). This field carries the
    /// compiled, enforceable policy so a launcher applies it deterministically
    /// and so the two substrates can be compared for divergence.
    #[serde(default)]
    pub egress: EgressConfig,
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

    /// Linux capabilities granted to the process.
    ///
    /// **MIK-5226.SEC.1**: previously `descriptor.capabilities` were silently
    /// dropped by the gVisor compiler while the Apple VM target passed them
    /// through as entitlements — the same descriptor therefore ran at a
    /// different privilege level depending on the host. The compiler now emits
    /// the requested capabilities here so the privilege grant is explicit and
    /// comparable across substrates.
    #[serde(default)]
    pub capabilities: Option<OciCapabilities>,
}

/// OCI process capability sets (subset of the runtime-spec `Capabilities`).
///
/// The requested descriptor capabilities are emitted into the `bounding`,
/// `effective`, and `permitted` sets — the sets that actually constrain what
/// the process may do. `inheritable`/`ambient` are intentionally left empty
/// (capabilities are not propagated to `execve`'d children by default).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct OciCapabilities {
    /// Bounding set — the ceiling of capabilities the process may ever hold.
    #[serde(default)]
    pub bounding: Vec<String>,
    /// Effective set — capabilities currently in force.
    #[serde(default)]
    pub effective: Vec<String>,
    /// Permitted set — capabilities the process may raise into effective.
    #[serde(default)]
    pub permitted: Vec<String>,
    /// Inheritable set — preserved across `execve` (empty by default).
    #[serde(default)]
    pub inheritable: Vec<String>,
    /// Ambient set — inheritable + permitted on `execve` (empty by default).
    #[serde(default)]
    pub ambient: Vec<String>,
}

impl OciCapabilities {
    /// Build capability sets from a flat list of requested capabilities.
    ///
    /// The list is mirrored into bounding/effective/permitted.
    #[must_use]
    pub fn from_list(caps: &[String]) -> Self {
        Self {
            bounding: caps.to_vec(),
            effective: caps.to_vec(),
            permitted: caps.to_vec(),
            inheritable: Vec::new(),
            ambient: Vec::new(),
        }
    }

    /// The set of granted capabilities (the bounding set), for comparison.
    #[must_use]
    pub fn granted(&self) -> BTreeSet<String> {
        self.bounding.iter().cloned().collect()
    }
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

    /// Enforceable network-egress configuration (MIK-5226.SEC.2).
    ///
    /// Carries the same compiled policy as the gVisor bundle so egress is
    /// restricted identically on both substrates.
    #[serde(default)]
    pub egress: EgressConfig,

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

// ── EgressConfig ─────────────────────────────────────────────────────────

/// Compiled, enforceable network-egress configuration.
///
/// **MIK-5226.SEC.2**: this is the substrate-agnostic representation of a
/// [`NetworkEgressPolicy`] that is emitted into *both* the gVisor OCI bundle
/// and the Apple VM-spec, so the same descriptor restricts egress identically
/// regardless of host. [`EgressConfig::allows`] is the single decision
/// procedure a launcher (gVisor netstack filter, or Apple VM packet filter)
/// applies; the test suite asserts on it directly so a blocked destination is
/// provably unreachable in the emitted config.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EgressConfig {
    /// Whether any non-loopback egress is permitted.
    ///
    /// `false` means the sandbox can reach loopback only (if `loopback`) or
    /// nothing at all.
    pub enabled: bool,

    /// Whether loopback (localhost) traffic is permitted.
    pub loopback: bool,

    /// Allowlisted destination CIDRs.
    ///
    /// When `enabled` and this is **non-empty**, egress is restricted to
    /// exactly these CIDRs. When `enabled` and this is **empty**, egress is
    /// unrestricted (full internet). When `!enabled`, this is ignored.
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
}

impl EgressConfig {
    /// Compile a [`NetworkEgressPolicy`] into an enforceable config.
    #[must_use]
    pub fn from_policy(policy: &NetworkEgressPolicy) -> Self {
        match policy {
            NetworkEgressPolicy::None => Self {
                enabled: false,
                loopback: false,
                allowed_cidrs: Vec::new(),
            },
            NetworkEgressPolicy::Loopback => Self {
                enabled: false,
                loopback: true,
                allowed_cidrs: Vec::new(),
            },
            NetworkEgressPolicy::Full => Self {
                enabled: true,
                loopback: true,
                allowed_cidrs: Vec::new(),
            },
            NetworkEgressPolicy::Allowlist(cidrs) => Self {
                enabled: true,
                loopback: true,
                allowed_cidrs: cidrs.clone(),
            },
        }
    }

    /// Decide whether traffic to `dest` (an IPv4 literal) is permitted by this
    /// config. Unparseable destinations and unparseable allowlist entries are
    /// treated as **denied** (fail-closed).
    #[must_use]
    pub fn allows(&self, dest: &str) -> bool {
        let Ok(ip) = dest.parse::<Ipv4Addr>() else {
            return false;
        };
        if ip.is_loopback() {
            return self.loopback;
        }
        if !self.enabled {
            return false;
        }
        if self.allowed_cidrs.is_empty() {
            // Full egress.
            return true;
        }
        self.allowed_cidrs.iter().any(|cidr| ipv4_in_cidr(ip, cidr))
    }
}

/// Returns `true` if `ip` falls within the IPv4 `cidr` (e.g. `"10.0.0.0/8"`).
///
/// A bare address (no `/prefix`) is treated as a `/32`. Malformed CIDRs return
/// `false` (fail-closed).
fn ipv4_in_cidr(ip: Ipv4Addr, cidr: &str) -> bool {
    let (base, prefix) = match cidr.split_once('/') {
        Some((b, p)) => (b, p),
        None => (cidr, "32"),
    };
    let Ok(base_addr) = base.trim().parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix.trim().parse::<u32>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    if prefix == 0 {
        return true;
    }
    let mask: u32 = u32::MAX << (32 - prefix);
    (u32::from(ip) & mask) == (u32::from(base_addr) & mask)
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
                // MIK-5226.SEC.1: emit the requested capabilities instead of
                // silently dropping them. Empty list ⇒ empty sets (no extra
                // privilege), never a dropped grant.
                capabilities: Some(OciCapabilities::from_list(&descriptor.capabilities)),
            },
            root: OciRoot {
                path: format!("rootfs-{}", descriptor.name),
                readonly: false,
            },
            hostname: descriptor.name.clone(),
            mounts,
            linux,
            env: descriptor.env.clone(),
            // MIK-5226.SEC.2: emit the enforceable egress policy.
            egress: EgressConfig::from_policy(&descriptor.network_egress),
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

        // MIK-5226.SEC.2: derive the VM network toggle faithfully from the
        // policy. Previously Loopback/Full/Allowlist all collapsed to
        // NAT-enabled (fail-open) — Loopback-only sandboxes silently got full
        // outbound NAT. Now only Full/Allowlist enable the NAT interface; the
        // egress firewall (see `egress` below) applies the fine-grained rules.
        let egress = EgressConfig::from_policy(&descriptor.network_egress);
        let network = AppleVmNetwork {
            enabled: egress.enabled,
            nat: egress.enabled,
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
            egress,
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

        // MIK-5226.SEC.3: compare the *granted capability set* on each
        // substrate. The historical bug was that gVisor dropped capabilities
        // entirely while Apple VM passed them through as entitlements, so the
        // same descriptor ran at different privilege per host with no record.
        // We now emit caps on both sides; this check fails CI if they ever
        // drift apart again.
        let gvisor_caps: BTreeSet<String> = gvisor
            .process
            .capabilities
            .as_ref()
            .map(OciCapabilities::granted)
            .unwrap_or_default();
        let apple_caps: BTreeSet<String> = apple.entitlements.iter().cloned().collect();
        if gvisor_caps != apple_caps {
            divergences.push(format!(
                "capabilities: gVisor={gvisor_caps:?} vs AppleVM entitlements={apple_caps:?}"
            ));
        }

        // MIK-5226.SEC.3: compare the compiled egress policy on each substrate.
        // Both are derived from `descriptor.network_egress`; any inequality
        // means one substrate restricts egress differently from the other
        // (the original fail-open divergence) and must be recorded.
        if gvisor.egress != apple.egress {
            divergences.push(format!(
                "egress: gVisor={:?} vs AppleVM={:?}",
                gvisor.egress, apple.egress
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
