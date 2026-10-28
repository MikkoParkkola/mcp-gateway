// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8382 fixture switches for the direct-audit fixture: each is off
//! unless a cell lists it in `Setup::extras`. Own file because
//! `direct_audit_tests.rs` sits near the 800-line ceiling.

use std::sync::Arc;
use std::time::Duration;

use super::{
    AuditFailurePolicy, BackendConfig, MetaMcp, Setup, TransparencyLogConfig, TransparencyLogger,
};

/// MIK-8382 fixture switches, each off unless listed in `Setup::extras`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Extra {
    /// Every backend's `tools/list` fails at the transport.
    ListFail,
    /// Every backend request is counted, then never answered, so a stage
    /// that waits on a backend before answering never answers.
    Hang,
    /// `beta` is a `passthrough: true` backend.
    BetaPassthrough,
    /// `security.posture: hardened` (auth stays off).
    Hardened,
    /// Attestation enforced on both routes.
    Attestation,
    /// `alpha` requires passthrough identity propagation (shared slot), so a
    /// caller with no credential to pass is refused.
    AlphaRequiresIdentity,
    /// Message signing on, scoped by the posture (`gateway_invoke` only,
    /// every `tools/call` under [`Extra::Hardened`]).
    Signing,
    /// Context integrity enforces and strips every finding, so an answer
    /// carrying an injected instruction is rebuilt without it.
    ContextIntegrityStrips,
}

impl Setup {
    pub(super) fn has(&self, extra: Extra) -> bool {
        self.extras.contains(&extra)
    }
}

/// A fixture backend's config: `beta` passthrough and `alpha`'s required
/// identity propagation follow the cell's [`Extra`] switches.
pub(super) fn backend_config(setup: &Setup, name: &str) -> BackendConfig {
    BackendConfig {
        signature_chain: setup.chain,
        passthrough: setup.has(Extra::BetaPassthrough) && name == "beta",
        identity_propagation: (setup.has(Extra::AlphaRequiresIdentity) && name == "alpha").then(
            || crate::identity_propagation::IdentityPropagationConfig {
                strategy: crate::identity_propagation::PropagationStrategyKind::Passthrough,
                audience: "https://alpha".to_string(),
                required: true,
                session_mode: crate::identity_propagation::SessionMode::Stateless,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            },
        ),
        ..BackendConfig::default()
    }
}

/// Run `state` under `security.posture: hardened`. The route reads the
/// posture the process started with, so the running config is replaced.
pub(super) fn harden(state: &mut crate::gateway::router::AppState) {
    let mut config = (*state.live_config.get()).clone();
    config.security.posture = crate::security::SecurityPosture::Hardened;
    state.live_config = Arc::new(crate::config_reload::LiveConfig::new(config));
}

/// `meta` with attestation enforced.
fn attested(meta: MetaMcp) -> MetaMcp {
    let validator = Arc::new(crate::attestation::AttestationValidator::new(
        crate::attestation::BnautAttestationSigner::new(b"k".to_vec(), "route")
            .with_audience("test-gateway"),
    ));
    meta.with_attestation(validator, crate::attestation::AttestationMode::Enforce)
}

/// Turn message signing on in `meta`, scoped as `posture` scopes it.
fn signed(meta: &mut MetaMcp, posture: crate::security::SecurityPosture) {
    meta.enable_message_signing(
        crate::security::message_signing::MessageSigner::new(
            b"mik-8382-signing-secret-32-bytes".to_vec(),
            None,
            "anon".to_owned(),
        ),
        Duration::from_secs(300),
        false,
    );
    meta.set_signing_scope(crate::gateway::meta_mcp::signing::SigningScope::of(posture));
}

/// `meta` with the meta-layer switches in `extras` turned on: attestation,
/// then signing scoped by the posture [`Extra::Hardened`] selects.
pub(super) fn arm_extras(mut meta: MetaMcp, extras: &[Extra]) -> MetaMcp {
    if extras.contains(&Extra::Attestation) {
        meta = attested(meta);
    }
    if extras.contains(&Extra::ContextIntegrityStrips) {
        meta = meta.with_context_integrity_kernel(stripping_kernel());
    }
    if extras.contains(&Extra::Signing) {
        let posture = if extras.contains(&Extra::Hardened) {
            crate::security::SecurityPosture::Hardened
        } else {
            crate::security::SecurityPosture::Standard
        };
        signed(&mut meta, posture);
    }
    meta
}

/// A context-integrity kernel that enforces and strips every finding kind.
fn stripping_kernel() -> crate::context_integrity::ContextIntegrityKernel {
    use crate::context_integrity::{
        ContextIntegrityDecisionKind, ContextIntegrityKernel, ContextIntegrityPolicy,
        ContextIntegrityPolicyMode,
    };
    let strip = ContextIntegrityDecisionKind::Strip;
    ContextIntegrityKernel::new(ContextIntegrityPolicy {
        mode: ContextIntegrityPolicyMode::Enforce,
        untrusted_instruction_decision: strip,
        guarded_material_decision: strip,
        personal_data_decision: strip,
        destructive_instruction_decision: strip,
        tool_poisoning_decision: strip,
        high_risk_action_decision: strip,
        allow_benign_read_only: true,
        non_bypassable: false,
    })
}

/// Whether both routes have a transparency log (T21).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Log {
    #[default]
    On,
    Off,
}

/// The logger both routes share, in its own directory, failing closed when
/// `fail_closed`.
pub(super) fn audit_log(
    fail_closed: bool,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    Arc<TransparencyLogger>,
) {
    let audit = tempfile::tempdir().unwrap();
    let path = audit.path().join("audit.jsonl");
    let policy = if fail_closed {
        AuditFailurePolicy::FailClosed
    } else {
        AuditFailurePolicy::BestEffort
    };
    let log = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: path.to_string_lossy().into_owned(),
            key_id: "d2".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("open log")
        .with_failure_policy(policy),
    );
    (audit, path, log)
}
