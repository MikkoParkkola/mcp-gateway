// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MCP Security Firewall — unified request/response inspection layer.
//!
//! Composes existing security modules (`sanitize`, `response_scanner`, `policy`,
//! `ssrf`, `data_flow`, `tool_integrity`) into a single enforcement point with
//! configurable actions and structured audit logging.
//!
//! # Pipeline
//!
//! ```text
//! Pre-invocation:  InputScanner → AnomalyDetector → TenantGuard → resolve_action → AuditLogger
//! Post-invocation: Redactor → ResponseScanner → per-target policy reduction → AuditLogger
//! ```
//!
//! # Feature gate
//!
//! All items in this module are gated behind `#[cfg(feature = "firewall")]`.

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::security::ResponseScanner;
use crate::transition::TransitionTracker;

pub mod anomaly;
pub(crate) mod anomaly_config;
mod anomaly_gate;
use anomaly_config::{default_anomaly_min_observations, default_anomaly_threshold};
pub mod audit;
pub mod budget_guard;
// The direct route calls the detector through `collusion_gate` (increment
// 2a-i). Its counters and `RelayFinding::tool` have no reader until the
// metrics increment, which is when this `expect` must be removed.
#[cfg_attr(not(test), expect(dead_code))]
mod collusion;
mod collusion_digest;
mod collusion_gate;
pub use collusion_gate::{AllowedFlow, CollusionAction, CollusionConfig};
pub(crate) use collusion_gate::{DeliveryDigest, RelayCaller};
mod config;
pub use config::{FirewallAction, FirewallConfig, FirewallRule, ScanType};
pub mod input_scanner;
pub mod memory_scanner;
pub mod principal_window;
pub mod redactor;
mod response;
pub mod tenant_guard;
/// Re-exported here, where the guard that attributes reads lives.
pub(crate) use crate::security::tenant_reads;

#[cfg(test)]
mod anomaly_learning_tests;
#[cfg(test)]
mod anomaly_posture_tests;
#[cfg(test)]
mod response_observer;
#[cfg(test)]
pub(crate) mod response_tests;

// ─── Runtime types ───────────────────────────────────────────────────────────

/// Compiled firewall engine — the runtime enforcement point.
///
/// Created once at gateway startup from `FirewallConfig`. Thread-safe via
/// interior immutability; all mutable state lives in sub-modules behind locks.
pub struct Firewall {
    config: FirewallConfig,
    /// Compiled tool-match rules (glob → action).
    rules: Vec<CompiledRule>,
    /// Reuse existing response scanner for prompt injection.
    response_scanner: ResponseScanner,
    /// Input pattern scanner for request arguments.
    input_scanner: input_scanner::InputScanner,
    /// Memory-poisoning scanner for memory-write tool arguments (OWASP ASI06).
    memory_scanner: memory_scanner::MemoryScanner,
    /// Credential/PII redactor for response content.
    redactor: redactor::Redactor,
    /// The continuation state whose envelopes response inspection leaves
    /// unredacted (#2210). `None` exempts nothing.
    continuations: Option<Arc<crate::protocol::continuation::ContinuationState>>,
    /// Anomaly detector using transition data.
    anomaly: Option<anomaly::AnomalyDetector>,
    /// Cross-tenant data-minimisation guard, keyed on the authenticated
    /// principal (MIK-7116.TENANT.1).
    tenant_guard: tenant_guard::TenantGuard,
    /// The process's cross-tenant read history (MIK-7116.MIN.2), shared by
    /// every firewall the gateway builds; see [`Self::with_reads`].
    reads: Arc<tenant_reads::ReadHistory>,
    /// Principal-keyed call budget (MIK-7215.CONTROL.2).
    budget: Option<budget_guard::BudgetGuard>,
    /// Relay detection state (OWASP ASI10, COLLUDE.1).
    relay: collusion_gate::RelayGate,
    /// Structured audit logger.
    audit: Option<audit::AuditLogger>,
    #[cfg(test)]
    response_observer: response_observer::ResponseObserver,
}

/// A compiled firewall rule with a pre-processed glob pattern.
struct CompiledRule {
    pattern: glob::Pattern,
    action: FirewallAction,
    #[allow(dead_code)]
    scans: Vec<ScanType>,
    #[allow(dead_code)]
    reason: Option<String>,
}

/// Verdict from the firewall for a single tool invocation.
#[derive(Debug, Clone)]
pub struct FirewallVerdict {
    /// Whether the request is allowed to proceed.
    pub allowed: bool,
    /// Action taken (for logging/response annotation).
    pub action: FirewallAction,
    /// Findings from all scans.
    pub findings: Vec<Finding>,
    /// Anomaly score if anomaly detection is enabled.
    pub anomaly_score: Option<f64>,
}

/// A single finding from a scan.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Which scan produced this finding.
    pub scan_type: ScanType,
    /// Severity: high (block), medium (warn), low (log).
    pub severity: Severity,
    /// Human-readable description of the finding.
    pub description: String,
    /// The matched pattern or fragment (truncated for logging).
    pub matched: String,
    /// Where the finding was detected.
    pub location: FindingLocation,
}

/// Finding severity, which drives the default action when no rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Deterministic pattern — block by default.
    High,
    /// Heuristic pattern — warn by default.
    Medium,
    /// Statistical anomaly — log only by default.
    Low,
}

/// Where a finding was detected in the invocation flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingLocation {
    /// Found in tool invocation arguments.
    RequestArgs,
    /// Found in tool response content.
    ResponseContent,
    /// Derived from tool call sequence patterns.
    SequenceAnomaly,
}

// ─── Firewall impl ───────────────────────────────────────────────────────────

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

    /// Relay detection keeps every k-gram instead of a keyed sample, so a
    /// test row always checks the fingerprints its text holds, under any
    /// hash key (MIK-8083). Call it on a firewall just built.
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
        let rules = config.rules.iter().map(compile_rule).collect();
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
            rules,
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
        }
    }

    /// The stateless content scan of a request's arguments, shared by
    /// admission (`check_request`) and the dispatch chokepoint (`rescan`) so
    /// the two cannot diverge as scanners change. Records nothing.
    ///
    /// `scan_requests` names one control — argument content scanning — and
    /// switching it off must cost exactly that. The anomaly, tenant and
    /// budget guards carry their own enable flags, and an operator who
    /// turned those on did not ask for them to be silently switched off by a
    /// neighbouring one.
    fn content_findings(&self, tool: &str, args: &Value) -> Vec<Finding> {
        let mut findings = Vec::new();
        if self.config.scan_requests {
            // Input pattern scan (shell injection, path traversal, SQL).
            if let Value::Object(map) = args {
                findings.extend(self.input_scanner.scan_args(map));
            }
            // Memory-poisoning scan (OWASP ASI06) — applied only when the
            // tool name is a recognised memory-write operation.
            if self.memory_scanner.is_memory_write_tool(tool)
                && let Value::Object(map) = args
            {
                findings.extend(self.memory_scanner.scan_args(map));
            }
        }
        findings
    }

    /// The dispatch chokepoint's re-check (MIK-8137 P1-route-b1): the content
    /// scan and rule resolution against the running config, on the bytes a
    /// send actually carries. It records nothing and re-runs none of the
    /// stateful guards (anomaly, tenant, budget, learning): those judged the
    /// logical call once, at its route scan, and a second pass would count it
    /// twice. Design note `design-b1-rescan.md` r2.
    pub(crate) fn rescan(&self, tool: &str, args: &Value) -> FirewallVerdict {
        if !self.config.enabled {
            return FirewallVerdict::allow();
        }
        let findings = self.content_findings(tool, args);
        let action = self.resolve_action(tool, &findings);
        FirewallVerdict {
            allowed: action != FirewallAction::Block,
            action,
            findings,
            anomaly_score: None,
        }
    }

    /// One audit row for a chokepoint decision that is not a plain allow
    /// (a Warn or a Block), naming where the send came from. Arguments are
    /// hashed, never written.
    pub(crate) fn audit_dispatch(
        &self,
        correlation: &crate::security::response_policy::ResponseCorrelation<'_>,
        args: &Value,
        verdict: &FirewallVerdict,
        source: &'static str,
    ) {
        if let Some(ref audit) = self.audit {
            audit.log_dispatch(correlation, args, verdict, source);
        }
    }

    /// Pre-invocation check: scan request arguments for threats.
    ///
    /// Returns a verdict. If `allowed` is `false`, the caller **must not**
    /// forward the request to the backend.
    pub fn check_request(
        &self,
        session_id: &str,
        server: &str,
        tool: &str,
        args: &Value,
        caller: &str,
        control_identity: &str,
    ) -> FirewallVerdict {
        if !self.config.enabled {
            return FirewallVerdict::allow();
        }

        // 1. Content scan (input patterns, memory poisoning), shared with the
        //    dispatch chokepoint's `rescan`.
        let mut findings = self.content_findings(tool, args);

        // 2. Anomaly detection (`anomaly_gate.rs`). Empty is not an identity:
        // it must never key the detector, tenant or budget guards.
        let anomaly_identity = (!control_identity.is_empty()).then_some(control_identity);
        let gate = self.score_anomaly(session_id, anomaly_identity, server, tool, &mut findings);

        // 2b. Cross-tenant data-minimisation guard (MIK-7116.TENANT.1). Reuses
        // `anomaly_identity` — the authenticated principal, never a session —
        // for exactly the reason given at its computation above.
        let tenant_blind =
            self.check_tenant_guard(anomaly_identity, args, server, tool, &mut findings);

        // 3. Determine action from rules + finding severity.
        // A rule may downgrade an ordinary finding to Allow or Warn. It may not
        // downgrade this one: an unscoreable call was never examined, so there
        // is no judgement for a rule to soften. Forced after `resolve_action`
        // precisely so no rule can reach it.

        // 2c. Budget check - a per-session budget under statelessness is an
        // unlimited budget (MIK-7215.CONTROL.2), so this keys on the same
        // principal as the anomaly detector, over an explicit window.
        let budget_refuse = self.check_budget(anomaly_identity, server, tool, &mut findings);

        let action = if gate.blind || gate.forced_block || tenant_blind || budget_refuse {
            FirewallAction::Block
        } else {
            self.resolve_action(tool, &findings)
        };
        let allowed = action != FirewallAction::Block;
        let anomaly_score = gate.score;
        self.learn(gate, allowed);

        let verdict = FirewallVerdict {
            allowed,
            action,
            findings,
            anomaly_score,
        };

        // 4. Audit log every request (including clean ones).
        if let Some(ref audit) = self.audit {
            let labels = crate::security::response_policy::ResponseCorrelation {
                session_id,
                caller,
                external_server: server,
                external_tool: tool,
                subject: None,
            };
            let tenants = self.tenant_guard.request_tenants(args);
            audit.log_request_attributed(&labels, args, &verdict, &tenants);
        }

        verdict
    }

    /// MIK-7116.MIN.1: the tenants a request's `args` name under
    /// `tenant_guard.arg_keys`, whether or not the guard may refuse.
    pub(crate) fn request_tenants(&self, args: &Value) -> std::collections::BTreeSet<String> {
        self.tenant_guard.request_tenants(args)
    }

    /// MIK-7116.MIN.1: the tenants a tool result names (text-JSON included).
    pub(crate) fn response_tenants(&self, result: &Value) -> std::collections::BTreeSet<String> {
        self.tenant_guard.response_tenants(result)
    }

    /// Share `reads` with every other firewall of this process, so one
    /// caller's reads on `/mcp` and `/mcp/{name}` meet in one history.
    #[must_use]
    pub(crate) fn with_reads(mut self, reads: Arc<tenant_reads::ReadHistory>) -> Self {
        self.reads = reads;
        self
    }

    /// The process's cross-tenant read history.
    pub(crate) const fn reads(&self) -> &Arc<tenant_reads::ReadHistory> {
        &self.reads
    }

    /// The tenant guard, for attribution reads that record nothing (MIN.1).
    pub(crate) const fn tenant_guard(&self) -> &tenant_guard::TenantGuard {
        &self.tenant_guard
    }

    /// Cross-tenant data-minimisation guard (MIK-7116.TENANT.1). Pushes a
    /// finding into `findings` for a refused or unattributable call and
    /// returns whether the caller must be force-blocked (unattributable —
    /// no rule may soften an unmeasured call), mirroring `anomaly_blind`.
    fn check_tenant_guard(
        &self,
        principal: Option<&str>,
        args: &Value,
        server: &str,
        tool: &str,
        findings: &mut Vec<Finding>,
    ) -> bool {
        match self.tenant_guard.check(principal, args) {
            tenant_guard::TenantVerdict::Allowed => false,
            tenant_guard::TenantVerdict::Refused { distinct, limit } => {
                findings.push(Finding {
                    scan_type: ScanType::CrossTenantReach,
                    severity: Severity::High,
                    description: format!(
                        "Cross-tenant reach exceeded: principal touched {distinct} distinct \
                         tenants (limit {limit})"
                    ),
                    matched: format!("{server}:{tool}"),
                    location: FindingLocation::RequestArgs,
                });
                false
            }
            tenant_guard::TenantVerdict::Unattributable => {
                tracing::warn!(
                    server = server,
                    tool = tool,
                    "MIK-7116.TENANT.1: tenant guard has no principal to key on; \
                     refusing rather than passing the call unmeasured"
                );
                findings.push(Finding {
                    scan_type: ScanType::CrossTenantReach,
                    severity: Severity::High,
                    description:
                        "Tenant-scoped call has no authenticated principal to key breadth on; \
                         call refused unmeasured"
                            .to_string(),
                    matched: format!("{server}:{tool}"),
                    location: FindingLocation::RequestArgs,
                });
                true
            }
        }
    }

    /// Judge one request against the principal-keyed call budget
    /// (MIK-7215.CONTROL.2), pushing a [`Finding`] and returning `true` when
    /// the call must be refused.
    ///
    /// Split out of [`Self::check_request`] to keep that function under the
    /// line-count lint; the two `Refused`/`Unattributable` arms are the whole
    /// control and have no reason to live inline.
    fn check_budget(
        &self,
        identity: Option<&str>,
        server: &str,
        tool: &str,
        findings: &mut Vec<Finding>,
    ) -> bool {
        let Some(budget) = self.budget.as_ref() else {
            return false;
        };
        match budget.check(identity, server, tool) {
            budget_guard::BudgetVerdict::Allowed => false,
            budget_guard::BudgetVerdict::Refused { total, limit } => {
                findings.push(Finding {
                    scan_type: ScanType::BudgetExceeded,
                    severity: Severity::High,
                    description: format!(
                        "Call budget exceeded: {total} calls in the window (limit {limit})"
                    ),
                    matched: format!("{server}:{tool}"),
                    location: FindingLocation::SequenceAnomaly,
                });
                true
            }
            budget_guard::BudgetVerdict::Unattributable => {
                // Same failure shape as an unobservable anomaly check: a
                // budget with nothing to key on cannot protect, so it must
                // say so rather than count it under a key nobody chose. The
                // one deliberate shared key is the keyless session-less
                // caller (MIK-7971), which arrives here as an identity.
                findings.push(Finding {
                    scan_type: ScanType::BudgetExceeded,
                    severity: Severity::High,
                    description:
                        "Call budget has no caller identity to key on; call refused unattributed"
                            .to_string(),
                    matched: format!("{server}:{tool}"),
                    location: FindingLocation::SequenceAnomaly,
                });
                true
            }
        }
    }

    /// Post-invocation check: scan response content for credentials/injection.
    ///
    /// May redact credentials/PII from the response value in place (returns
    /// the potentially-modified value).
    pub fn check_response(
        &self,
        session_id: &str,
        server: &str,
        tool: &str,
        response: &mut Value,
        caller: &str,
    ) -> FirewallVerdict {
        use crate::security::response_policy::{
            ResponseArtifactKind, ResponseCorrelation, ResponseMutationPolicy, ResponsePolicyTarget,
        };
        let targets = [ResponsePolicyTarget {
            server: server.into(),
            tool: tool.into(),
        }];
        let correlation = ResponseCorrelation {
            session_id,
            caller,
            external_server: server,
            external_tool: tool,
            subject: None,
        };
        // The compatibility API always supplies one target. Keep the defensive
        // error branch fail-closed rather than panicking at an inspection boundary.
        self.check_response_artifact(
            response,
            &targets,
            &correlation,
            ResponseArtifactKind::FinalResponse,
            ResponseMutationPolicy::Redact,
        )
        .unwrap_or_else(|_| FirewallVerdict {
            allowed: false,
            action: FirewallAction::Block,
            findings: Vec::new(),
            anomaly_score: None,
        })
    }

    /// Match tool name against rules; fall back to severity-based default action.
    ///
    /// First matching rule wins. When no rule matches, the highest-severity
    /// finding determines the action: High→Block, Medium→Warn, Low→Allow.
    fn resolve_action(&self, tool: &str, findings: &[Finding]) -> FirewallAction {
        let highest_severity = strongest_finding_severity(findings);
        let matching_rule_action =
            highest_severity.and_then(|_| first_matching_rule_action(&self.rules, tool));

        decide_firewall_action(matching_rule_action, highest_severity)
    }

    /// Clean up per-session state in the anomaly detector.
    ///
    /// Must be called (via the `SessionLifecycle` hook) when a session
    /// disconnects to prevent unbounded memory growth.
    pub fn on_session_end(&self, session_id: &str) {
        if let Some(ref a) = self.anomaly {
            a.remove_session(session_id);
        }
    }
}

#[cfg(test)]
impl Firewall {
    pub(crate) fn response_inspection_counts(&self) -> response_observer::ResponseInspectionCounts {
        self.response_observer.snapshot()
    }
}

/// Generic refusal text served in place of a blocked response.
///
/// Deliberately says nothing about what matched: the finding detail belongs in
/// the audit log, not in a payload handed to the caller that triggered it.
pub const BLOCKED_RESPONSE_MESSAGE: &str =
    "Security firewall blocked this response: backend content failed a content scan";

impl FirewallVerdict {
    /// Construct an unconditional allow verdict (used when scanning is disabled).
    fn allow() -> Self {
        Self {
            allowed: true,
            action: FirewallAction::Allow,
            findings: Vec::new(),
            anomaly_score: None,
        }
    }

    /// Returns `true` when the block was triggered solely by anomaly detection
    /// (OWASP ASI10 — Rogue Agents), i.e. every blocking finding is a
    /// `SequenceAnomaly` at `Severity::High`.
    ///
    /// Callers should use JSON-RPC error code `-32002` for anomaly blocks to
    /// distinguish them from generic security blocks (`-32600`).
    pub fn is_anomaly_block(&self) -> bool {
        self.blocked_only_by(|_| false)
    }

    /// [`Self::is_anomaly_block`] widened to relay findings (OWASP ASI10,
    /// COLLUDE.1): every finding is a high `SequenceAnomaly` or a
    /// `CollusionRelay`. Crate-internal so the public meaning stays put.
    pub(crate) fn is_asi10_block(&self) -> bool {
        self.blocked_only_by(|f| f.scan_type == ScanType::CollusionRelay)
    }

    fn blocked_only_by(&self, also: impl Fn(&Finding) -> bool) -> bool {
        !self.allowed
            && !self.findings.is_empty()
            && self.findings.iter().all(|f| {
                (f.scan_type == ScanType::SequenceAnomaly && f.severity == Severity::High)
                    || also(f)
            })
    }

    /// Returns `true` when a blocking verdict must stop the response payload
    /// from being served (MIK/GH517 RESPONSE.1).
    ///
    /// A blocked verdict whose findings are *all* `ScanType::Credentials` does
    /// not stop the response: [`redactor::Redactor`] already rewrote those
    /// matches in place, so the payload handed onward is the neutralised one
    /// and the shipped redact-and-serve contract stands. Anything else — prompt
    /// injection above all — is still hostile in the payload, so the response
    /// is refused rather than forwarded.
    ///
    /// This infers remediation from the scan type because [`Finding`] carries
    /// no remediation flag; adding one is the cleaner fix if a future scanner
    /// also rewrites in place.
    pub fn blocks_response(&self) -> bool {
        !self.allowed
            && self
                .findings
                .iter()
                .any(|f| f.scan_type != ScanType::Credentials)
    }
}

// ─── Rule helpers ─────────────────────────────────────────────────────────────

fn compile_rule(rule: &FirewallRule) -> CompiledRule {
    let pattern = glob::Pattern::new(&rule.tool_match)
        .unwrap_or_else(|_| glob::Pattern::new("*").expect("fallback pattern compiles"));
    CompiledRule {
        pattern,
        action: rule.action,
        scans: rule.scan.clone(),
        reason: rule.reason.clone(),
    }
}

fn rule_matches(rule: &CompiledRule, tool: &str) -> bool {
    rule.pattern.matches(tool)
}

fn first_matching_rule_action(rules: &[CompiledRule], tool: &str) -> Option<FirewallAction> {
    rules
        .iter()
        .find(|rule| rule_matches(rule, tool))
        .map(|rule| rule.action)
}

fn strongest_finding_severity(findings: &[Finding]) -> Option<Severity> {
    findings
        .iter()
        .map(|finding| finding.severity)
        .min_by_key(|severity| severity_rank(*severity))
}

const fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::High => 0,
        Severity::Medium => 1,
        Severity::Low => 2,
    }
}

const fn default_action_for_severity(severity: Severity) -> FirewallAction {
    match severity {
        Severity::High => FirewallAction::Block,
        Severity::Medium => FirewallAction::Warn,
        Severity::Low => FirewallAction::Allow,
    }
}

const fn decide_firewall_action(
    matching_rule_action: Option<FirewallAction>,
    highest_severity: Option<Severity>,
) -> FirewallAction {
    match highest_severity {
        None => FirewallAction::Allow,
        Some(severity) => match matching_rule_action {
            Some(action) => action,
            None => default_action_for_severity(severity),
        },
    }
}

#[cfg(kani)]
mod verification;

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "tenant_audit_tests.rs"]
mod tenant_audit_tests;
#[cfg(test)]
#[path = "firewall_tests.rs"]
mod tests;
