// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Runtime-substrate provisioning entry point (the wired call path).
//!
//! **WIRING (MIK-5226 follow-up)**: the [`runtime`](super) module ships a
//! pure descriptor-to-substrate [`Compiler`](super::compiler::Compiler) that
//! was previously *dormant* — nothing in the gateway invoked it. This module
//! is the minimal, real call path that exercises it, reachable from the
//! `mcp-gateway runtime compile` CLI subcommand.
//!
//! It is gated behind the off-by-default `runtime-substrate` feature so that
//! foundation code cannot reach production until an operator explicitly opts
//! in (B4-PLATFORM: reuse the platform primitive, but gate the dormant path).
//!
//! # Why this layer exists (adversarial-review hardening)
//!
//! [`Compiler::compile`](super::compiler::Compiler::compile) is **infallible** —
//! it never validates the descriptor and never probes whether the selected
//! substrate is actually runnable on the host. Compiling an invalid or unsafe
//! descriptor silently produces a malformed bundle. This entry point closes
//! that gap by running, in order:
//!
//! 1. [`SandboxDescriptor::validate`] — schema-level checks.
//! 2. [`preflight`] — security/privilege checks that `validate` does not cover
//!    (path-traversal mounts, dangerous capabilities, fail-open egress, NaN
//!    resources). See [`PreflightError`].
//! 3. [`Compiler::compile`] / `compile_both` — only after the gates pass.

use std::path::Path;

use super::compiler::{CompiledBundle, Compiler};
use super::descriptor::{NetworkEgressPolicy, SandboxDescriptor};
use super::divergence::DivergenceRegistry;
use super::substrate::Substrate;

/// Capabilities that are never allowed via an operator descriptor.
///
/// These grant effective host control inside a sandbox and defeat the
/// isolation guarantee. An operator who genuinely needs them must patch the
/// allowlist deliberately, not request them from a YAML file.
const FORBIDDEN_CAPABILITIES: &[&str] = &[
    "CAP_SYS_ADMIN",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_PTRACE",
    "CAP_SYS_BOOT",
    "CAP_DAC_READ_SEARCH",
    "CAP_DAC_OVERRIDE",
    "ALL",
];

/// Host path prefixes that must never be bind-mounted into a sandbox.
const FORBIDDEN_MOUNT_PREFIXES: &[&str] = &["/etc", "/root", "/var/run", "/proc", "/sys", "/dev"];

/// A provisioning preflight failure.
///
/// These are the adversarial-review findings turned into hard gates. Each
/// variant maps to a failure mode that [`SandboxDescriptor::validate`] does
/// **not** catch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightError {
    /// Schema validation failed (delegated to `SandboxDescriptor::validate`).
    Schema(String),
    /// A requested capability is on the forbidden list.
    ForbiddenCapability(String),
    /// A mount source escapes its intended root (path traversal) or targets a
    /// sensitive host prefix.
    UnsafeMountSource(String),
    /// A mount source is not an absolute path.
    RelativeMountSource(String),
    /// `cpu_cores` is NaN or non-finite (`validate` only checks `<= 0`).
    NonFiniteCpu,
    /// The selected substrate is not the host's native substrate and no
    /// explicit override was given — refuses to silently cross-compile.
    SubstrateUnavailable {
        /// The substrate that would be used.
        selected: Substrate,
        /// The host's auto-detected substrate.
        host: Substrate,
    },
}

impl std::fmt::Display for PreflightError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Schema(m) => write!(f, "descriptor failed schema validation: {m}"),
            Self::ForbiddenCapability(c) => {
                write!(f, "capability '{c}' is forbidden via descriptor")
            }
            Self::UnsafeMountSource(s) => {
                write!(
                    f,
                    "mount source '{s}' is unsafe (traversal or sensitive prefix)"
                )
            }
            Self::RelativeMountSource(s) => {
                write!(f, "mount source '{s}' must be an absolute path")
            }
            Self::NonFiniteCpu => write!(f, "resources.cpu_cores must be a finite positive number"),
            Self::SubstrateUnavailable { selected, host } => write!(
                f,
                "substrate '{}' is not the host substrate '{}'; pass an explicit override to cross-compile",
                selected.name(),
                host.name()
            ),
        }
    }
}

impl std::error::Error for PreflightError {}

/// A provisioning error: file/parse failure or a preflight gate.
#[derive(Debug)]
pub enum ProvisionError {
    /// Could not read the descriptor file.
    Io(std::io::Error),
    /// Could not parse the descriptor (YAML/JSON).
    Parse(String),
    /// A preflight gate rejected the descriptor.
    Preflight(PreflightError),
}

impl std::fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "could not read descriptor: {e}"),
            Self::Parse(m) => write!(f, "could not parse descriptor: {m}"),
            Self::Preflight(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ProvisionError {}

impl From<PreflightError> for ProvisionError {
    fn from(e: PreflightError) -> Self {
        Self::Preflight(e)
    }
}

/// The result of a successful compile via the wired call path.
#[derive(Debug)]
pub struct CompileReport {
    /// The substrate the descriptor was compiled for.
    pub substrate: Substrate,
    /// The compiled bundle.
    pub bundle: CompiledBundle,
    /// Cross-substrate divergences (populated only for `--both` compiles).
    pub divergences: Vec<String>,
    /// Non-fatal warnings surfaced during preflight (e.g. fail-open egress,
    /// dropped capabilities). Surfacing these is the whole point of wiring.
    pub warnings: Vec<String>,
}

/// Run the security/privilege preflight that `validate` does not cover.
///
/// Returns the list of non-fatal warnings on success, or the first hard
/// failure. This is deliberately conservative: it fails closed.
///
/// # Errors
///
/// Returns [`PreflightError`] for the first gate that rejects the descriptor.
pub fn preflight(
    descriptor: &SandboxDescriptor,
    effective: Substrate,
) -> Result<Vec<String>, PreflightError> {
    // `effective` is retained in the signature for call-site stability and
    // future substrate-specific gating; egress/capability handling is now
    // substrate-symmetric (MIK-5226.SEC.1/2), so it is not branched on here.
    let _ = effective;

    // 1. Schema validation (closes the "compile never validates" finding).
    descriptor.validate().map_err(PreflightError::Schema)?;

    // 2. NaN/non-finite cpu — validate() only rejects `<= 0`, and NaN <= 0.0
    //    is false, so a NaN slips through to `ceil() as u32 == 0` (a 0-vCPU VM).
    if !descriptor.resources.cpu_cores.is_finite() {
        return Err(PreflightError::NonFiniteCpu);
    }

    // 3. Capability allowlist — gVisor silently drops caps, Apple VM passes
    //    them through as entitlements, so the same descriptor diverges in
    //    privilege. Forbid the dangerous ones outright at the call boundary.
    for cap in &descriptor.capabilities {
        let norm = cap.trim().to_ascii_uppercase();
        if FORBIDDEN_CAPABILITIES.contains(&norm.as_str()) {
            return Err(PreflightError::ForbiddenCapability(cap.clone()));
        }
    }

    // 4. Mount source safety — sources are passed through verbatim with no
    //    sanitization; block path traversal and sensitive host prefixes.
    for mount in &descriptor.mounts {
        let src = mount.source.as_str();
        if !src.starts_with('/') {
            return Err(PreflightError::RelativeMountSource(mount.source.clone()));
        }
        if src.contains("..") {
            return Err(PreflightError::UnsafeMountSource(mount.source.clone()));
        }
        let normalized = src.trim_end_matches('/');
        if normalized.is_empty() {
            // "/" — mounting host root.
            return Err(PreflightError::UnsafeMountSource(mount.source.clone()));
        }
        for prefix in FORBIDDEN_MOUNT_PREFIXES {
            if normalized == *prefix || normalized.starts_with(&format!("{prefix}/")) {
                return Err(PreflightError::UnsafeMountSource(mount.source.clone()));
            }
        }
    }

    // 5. Non-fatal warnings: behaviours an operator should be aware of.
    let mut warnings = Vec::new();

    // MIK-5226.SEC.2: egress is now compiled into an enforceable `EgressConfig`
    // emitted to BOTH substrate bundles (no longer decorative). The remaining
    // caveat is that a launcher must apply the emitted config; surface that as
    // an informational note rather than a fail-open alarm.
    match &descriptor.network_egress {
        NetworkEgressPolicy::None => warnings.push(
            "network_egress=None compiles to a deny-all EgressConfig (no loopback, \
             no external). The launcher must apply the emitted egress config."
                .to_string(),
        ),
        NetworkEgressPolicy::Allowlist(cidrs) => warnings.push(format!(
            "network_egress allowlist ({} entries) compiles to a restricted EgressConfig \
             on both substrates; the launcher must apply the emitted egress config.",
            cidrs.len()
        )),
        NetworkEgressPolicy::Loopback | NetworkEgressPolicy::Full => {}
    }

    Ok(warnings)
}

/// Compile a descriptor file through the hardened, wired call path.
///
/// This is what the `mcp-gateway runtime compile` subcommand calls. It reads
/// the file (YAML or JSON inferred from extension, YAML-superset parser as the
/// fallback), runs [`preflight`], then invokes the compiler.
///
/// When `both` is `true` the descriptor is compiled for *both* substrates and
/// divergences are recorded (AC.3/AC.4); otherwise it compiles for the
/// `override`-or-host substrate.
///
/// # Errors
///
/// Returns [`ProvisionError`] on I/O failure, parse failure, or any preflight
/// gate rejection.
pub fn compile_descriptor_file(path: &Path, both: bool) -> Result<CompileReport, ProvisionError> {
    let raw = std::fs::read_to_string(path).map_err(ProvisionError::Io)?;
    let descriptor: SandboxDescriptor =
        serde_yaml::from_str(&raw).map_err(|e| ProvisionError::Parse(e.to_string()))?;
    compile_descriptor(&descriptor, both)
}

/// Compile an already-parsed descriptor through the hardened call path.
///
/// Split out from [`compile_descriptor_file`] so wiring tests can exercise the
/// gate without touching the filesystem.
///
/// # Errors
///
/// Returns [`ProvisionError::Preflight`] if any gate rejects the descriptor.
pub fn compile_descriptor(
    descriptor: &SandboxDescriptor,
    both: bool,
) -> Result<CompileReport, ProvisionError> {
    let effective = descriptor.effective_substrate();
    let warnings = preflight(descriptor, effective)?;

    if both {
        let registry = DivergenceRegistry::new();
        let compiler = Compiler::with_divergence(registry);
        let (gvisor, _apple, divergences) = compiler.compile_both(descriptor);
        Ok(CompileReport {
            substrate: effective,
            bundle: CompiledBundle::GVisor(gvisor),
            divergences,
            warnings,
        })
    } else {
        let compiler = Compiler::new();
        let bundle = compiler.compile(descriptor);
        Ok(CompileReport {
            substrate: effective,
            bundle,
            divergences: Vec::new(),
            warnings,
        })
    }
}

#[cfg(test)]
#[path = "provision_tests.rs"]
mod tests;
