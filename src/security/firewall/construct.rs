// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Building a [`Firewall`]: from its config, and the builder options that set
//! the env, the security posture and the continuation keyring it exempts.
//! Nothing here checks a call.

use std::sync::Arc;

#[cfg(test)]
use super::response_observer;
use super::{
    Firewall, FirewallConfig, FirewallPolicy, allowed_root, anomaly, audit, budget_guard,
    collusion_gate, input_scanner, memory_scanner, redactor, tenant_guard, tenant_reads,
};
use crate::security::ResponseScanner;
use crate::transition::TransitionTracker;

impl Firewall {
    /// Read the input scanner's operator overrides from `env` rather than the
    /// process environment, so an env file can set them.
    #[must_use]
    pub fn with_env(mut self, env: Arc<crate::config::LiveEnv>) -> Self {
        self.input_scanner = input_scanner::InputScanner::with_env(env);
        self
    }

    /// Apply the security posture: under `hardened`, a call whose transition
    /// the anomaly detector cannot learn (pair map full) is refused.
    #[must_use]
    pub(crate) fn with_posture(
        mut self,
        posture: crate::security::posture::SecurityPosture,
    ) -> Self {
        if posture == crate::security::posture::SecurityPosture::Hardened {
            self.anomaly = self
                .anomaly
                .map(anomaly::AnomalyDetector::refusing_unlearnable);
        }
        self
    }

    /// Leave the envelopes `state` minted unredacted in responses: random
    /// ciphertext can hold a credential shape (#2210). Only a value that opens
    /// under its keyring is exempt.
    #[must_use]
    pub fn with_continuations(
        mut self,
        state: Arc<crate::protocol::continuation::ContinuationState>,
    ) -> Self {
        self.continuations = Some(state);
        self
    }

    /// Test-only: a firewall built with a fresh keyring, for a fixture that
    /// builds its firewall before the gateway it guards; the gateway then
    /// adopts it ([`crate::gateway::meta_mcp::MetaMcp::share_keyring_with_for_test`]),
    /// so the pair matches the gateway's own (#2210).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn keyed_for_test(self) -> Self {
        self.with_continuations(Arc::new(
            crate::protocol::continuation::ContinuationState::new(),
        ))
    }

    /// Test-only: the keyring this firewall exempts, if any.
    #[cfg(test)]
    pub(crate) fn continuations_for_test(
        &self,
    ) -> Option<Arc<crate::protocol::continuation::ContinuationState>> {
        self.continuations.clone()
    }

    /// Relay detection keeps every k-gram instead of a keyed sample, so a
    /// test row always checks the fingerprints its text holds, under any
    /// hash key. Call it on a firewall just built.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn keeping_every_kgram(mut self) -> Self {
        self.relay.keep_every_kgram();
        self
    }

    /// Create a new firewall from config.
    ///
    /// Compiles all rules, initialises scanners, and opens the audit log if
    /// configured. Falls back to stderr logging when the log file cannot be
    /// opened.
    pub fn from_config(
        config: FirewallConfig,
        transition_tracker: Option<Arc<TransitionTracker>>,
    ) -> Self {
        let startup = Arc::new(FirewallPolicy::compile(&config));
        let response_scanner = ResponseScanner::new();
        let input_scanner = input_scanner::InputScanner::new();
        let memory_scanner = memory_scanner::MemoryScanner::new(config.memory_poisoning.clone());
        let redactor = redactor::Redactor::new();
        let anomaly = if config.anomaly_detection {
            transition_tracker.map(|tt| {
                anomaly::AnomalyDetector::new(tt, config.anomaly_threshold)
                    .with_min_observations(config.anomaly_min_observations)
            })
        } else {
            None
        };
        let tenant_guard = tenant_guard::TenantGuard::new(config.tenant_guard.clone());
        let audit = config.audit_log.as_ref().map(|path| {
            audit::AuditLogger::new(path).unwrap_or_else(|e| {
                tracing::warn!("Cannot open audit log {}: {e}", path.display());
                audit::AuditLogger::stderr()
            })
        });
        let budget = config
            .budget
            .enabled
            .then(|| budget_guard::BudgetGuard::new(config.budget.clone()));
        let relay = collusion_gate::RelayGate::from_config(&config.collusion);

        Self {
            config,
            startup,
            response_scanner,
            input_scanner,
            memory_scanner,
            redactor,
            continuations: None,
            anomaly,
            tenant_guard,
            reads: tenant_reads::ReadHistory::shared(),
            budget,
            relay,
            audit,
            #[cfg(test)]
            response_observer: response_observer::ResponseObserver::default(),
            registries: allowed_root::Registries::default(),
            #[cfg(test)]
            seams: allowed_root::Seams::default(),
        }
    }
}
