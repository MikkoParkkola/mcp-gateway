// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Relay detection (OWASP ASI10) wired into the firewall: the operator config,
//! its load checks, and the egress check and delivery recording the direct
//! route calls (design `2026-09-28-asi10-verbatim-relay.md` §13.1).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::collusion::egress_parts;
#[cfg(test)]
pub(super) use super::collusion::egress_text;
use super::collusion::replay::ReplayReceipts;
use super::collusion::{
    CAPACITY_METRIC, CollusionDetector, MAX_COMMON_PRINCIPALS, RelayAction, RelayParams,
    RelayReason, SeamForms,
};
#[cfg(test)]
pub(super) use super::collusion_digest::delivery_leaves;
pub(super) use super::collusion_digest::delivery_parts;
use super::collusion_digest::{DELIVERED_SET_CAP, key_path_joins, key_path_runs};
pub(crate) use super::collusion_digest::{Delivered, DeliveryDigest};
use super::collusion_digest::{Mode, UnreadReceipt, view};
use super::{Finding, FindingLocation, Firewall, FirewallAction, FirewallVerdict, ScanType};
use crate::security::Severity;

/// What one delivery may stage for its plan steps in all (MIK-7992): past it
/// a step's receipt is dropped and counted, as an over-bound answer's are
/// (under-receipt, never a false excuse).
const PLAN_STAGED_CAP: usize = 4 * DELIVERED_SET_CAP;

/// What relay detection does with a finding.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollusionAction {
    /// No state is kept and nothing is checked.
    #[default]
    Off,
    /// Findings are logged and audited; calls proceed.
    Observe,
    /// A relaying call is refused with `-32002`.
    Block,
}

/// One reported relay, by action (`observe` or `block`).
const RELAY_METRIC: &str = "mcp_gateway_collusion_relay_total";
/// One egress checked without an authenticated caller, by action.
const UNKEYED_METRIC: &str = "mcp_gateway_collusion_unkeyed_egress_total";
/// One plan whose step receipts were dropped: its answer was over the bound.
const PLAN_DROP_METRIC: &str = "mcp_gateway_collusion_plan_receipts_dropped_total";

/// `allowed_flows` entries one detector tracks: one bit each in a `u64`.
const MAX_ALLOWED_FLOWS: usize = 64;

/// One `allowed_flows` entry: content delivered by a `source` tool may leave
/// through an `egress` tool without being a relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowedFlow {
    /// `server:tool` glob of the tool that delivered the content.
    pub source: String,
    /// `server:tool` glob of the tool the content leaves through.
    pub egress: String,
}

/// `security.firewall.collusion`: verbatim cross-principal relay detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CollusionConfig {
    /// `off` (default), `observe` or `block`.
    pub action: CollusionAction,
    /// How long a delivery is remembered, in seconds.
    #[serde(deserialize_with = "crate::duration_bound::secs")]
    pub window_secs: u64,
    /// Matching fingerprints one egress needs before it is a relay.
    pub min_matches: usize,
    /// Principals holding one fingerprint before it counts as common text.
    pub common_principals: usize,
    /// `server:tool` globs whose results are always sensitive.
    pub sources: Vec<String>,
    /// `server:tool` globs whose arguments are never checked.
    pub non_egress: Vec<String>,
    /// `{source, egress}` glob pairs whose flow is expected collaboration.
    pub allowed_flows: Vec<AllowedFlow>,
}

impl Default for CollusionConfig {
    fn default() -> Self {
        let params = RelayParams::default();
        Self {
            action: CollusionAction::Off,
            window_secs: params.window.as_secs(),
            min_matches: params.min_matches,
            common_principals: params.common_principals,
            sources: Vec::new(),
            non_egress: Vec::new(),
            allowed_flows: Vec::new(),
        }
    }
}

impl CollusionConfig {
    /// Refuse settings that cannot mean what they say. `off` loads whatever
    /// the other fields hold.
    pub(super) fn validate(&self, firewall_enabled: bool) -> Result<(), String> {
        if self.action == CollusionAction::Off {
            return Ok(());
        }
        let field =
            |name: &str, why: &str| Err(format!("security.firewall.collusion.{name} {why}"));
        if !firewall_enabled {
            return field("action", "needs security.firewall.enabled: true");
        }
        if self.min_matches == 0 {
            return field("min_matches", "must be at least 1");
        }
        if !(2..=MAX_COMMON_PRINCIPALS).contains(&self.common_principals) {
            return field(
                "common_principals",
                &format!("must be between 2 and {MAX_COMMON_PRINCIPALS}"),
            );
        }
        if self.window_secs == 0 {
            return field("window_secs", "must be at least 1");
        }
        if self.allowed_flows.len() > MAX_ALLOWED_FLOWS {
            return field(
                "allowed_flows",
                &format!("holds at most {MAX_ALLOWED_FLOWS} entries"),
            );
        }
        // A bad glob is named by its key path and index, never its text: a
        // pattern can hold a tool name the operator would not have logged.
        for (i, flow) in self.allowed_flows.iter().enumerate() {
            for (side, pattern) in [("source", &flow.source), ("egress", &flow.egress)] {
                if glob::Pattern::new(pattern).is_err() {
                    return field(&format!("allowed_flows[{i}].{side}"), "is not a valid glob");
                }
            }
        }
        for (name, patterns) in [("sources", &self.sources), ("non_egress", &self.non_egress)] {
            for (i, pattern) in patterns.iter().enumerate() {
                if glob::Pattern::new(pattern).is_err() {
                    return field(&format!("{name}[{i}]"), "is not a valid glob");
                }
            }
        }
        Ok(())
    }
}

/// The principal a relay is keyed on, decided before any anonymous fallback.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RelayCaller<'a> {
    /// An authenticated caller's key.
    Keyed(&'a str),
    /// No identity: the route's shared fallback bucket.
    Unkeyed(&'a str),
}

impl<'a> RelayCaller<'a> {
    pub(crate) fn new(key: &'a str, keyed: bool) -> Self {
        if keyed {
            Self::Keyed(key)
        } else {
            Self::Unkeyed(key)
        }
    }

    fn key(self) -> &'a str {
        match self {
            Self::Keyed(key) | Self::Unkeyed(key) => key,
        }
    }
}

/// Per-firewall relay state: the detector (shared across firewalls through
/// [`Firewall::with_collusion`]) and the compiled globs.
pub(super) struct RelayGate {
    detector: Option<Arc<CollusionDetector>>,
    /// The replay receipt store (`MIK-8408` E1): one beside the detector,
    /// shared wherever the detector is shared.
    replay: Arc<ReplayReceipts>,
    sources: Vec<glob::Pattern>,
    non_egress: Vec<glob::Pattern>,
    /// The compiled `allowed_flows`, as (source, egress), bit `i` for entry `i`.
    flows: Vec<(glob::Pattern, glob::Pattern)>,
    /// Delivered results whose text was cut to the recording cap.
    text_cut: AtomicU64,
    /// Plans whose answer was over the bound their receipts are kept against.
    plan_drop: AtomicU64,
    /// A test's frozen reading of this gate's receipt clock (MIK-8354).
    #[cfg(test)]
    pub(super) frozen: parking_lot::Mutex<Option<Instant>>,
}

impl RelayGate {
    /// See [`super::Firewall::keeping_every_kgram`].
    #[cfg(test)]
    pub(super) fn keep_every_kgram(&mut self) {
        if let Some(detector) = self.detector.as_mut() {
            Arc::get_mut(detector)
                .expect("a gate just built shares its detector with no one")
                .keep_every_kgram();
        }
    }

    pub(super) fn from_config(config: &CollusionConfig) -> Self {
        Self {
            detector: detector_for(config),
            replay: Arc::new(ReplayReceipts::new()),
            sources: compile_globs(&config.sources),
            non_egress: compile_globs(&config.non_egress),
            flows: compile_flows(&config.allowed_flows),
            text_cut: AtomicU64::new(0),
            plan_drop: AtomicU64::new(0),
            #[cfg(test)]
            frozen: parking_lot::Mutex::new(None),
        }
    }

    /// The receipt window's clock: wall time, or a test's frozen instant.
    /// Only a test build reads `self` (the frozen field exists there only).
    #[cfg_attr(not(test), allow(clippy::unused_self))]
    pub(super) fn now(&self) -> Instant {
        #[cfg(test)]
        if let Some(frozen) = *self.frozen.lock() {
            return frozen;
        }
        Instant::now()
    }

    /// The `allowed_flows` entries (bit each) whose source matches `target`.
    fn source_flows(&self, target: &str) -> u64 {
        Self::mask(self.flows.iter().map(|(source, _)| source), target)
    }

    /// The `allowed_flows` entries (bit each) whose egress matches `target`.
    fn egress_flows(&self, target: &str) -> u64 {
        Self::mask(self.flows.iter().map(|(_, egress)| egress), target)
    }

    fn mask<'a>(patterns: impl Iterator<Item = &'a glob::Pattern>, target: &str) -> u64 {
        patterns
            .enumerate()
            .filter(|(_, pattern)| pattern.matches(target))
            .fold(0, |mask, (bit, _)| mask | (1 << bit))
    }
}

/// `server:tool` globs, compiled; one that does not parse is dropped (the
/// config load has already refused it by key path).
pub(super) fn compile_globs(patterns: &[String]) -> Vec<glob::Pattern> {
    patterns
        .iter()
        .filter_map(|p| glob::Pattern::new(p).ok())
        .collect()
}

/// `allowed_flows`, compiled as (source, egress), at most
/// [`MAX_ALLOWED_FLOWS`] entries.
pub(super) fn compile_flows(flows: &[AllowedFlow]) -> Vec<(glob::Pattern, glob::Pattern)> {
    flows
        .iter()
        .take(MAX_ALLOWED_FLOWS)
        .filter_map(|f| {
            Some((
                glob::Pattern::new(&f.source).ok()?,
                glob::Pattern::new(&f.egress).ok()?,
            ))
        })
        .collect()
}

/// The detector `config` asks for; `None` when relay detection is off.
fn detector_for(config: &CollusionConfig) -> Option<Arc<CollusionDetector>> {
    let action = match config.action {
        CollusionAction::Off => return None,
        CollusionAction::Observe => RelayAction::Observe,
        CollusionAction::Block => RelayAction::Block,
    };
    Some(Arc::new(CollusionDetector::new(RelayParams {
        action,
        window: Duration::from_secs(config.window_secs),
        min_matches: config.min_matches,
        common_principals: config.common_principals,
        ..RelayParams::default()
    })))
}

/// Result text kept per delivery: the first and last half of this, so an
/// excerpt from either end still matches. Sized under the detector's
/// per-delivery keep limit (about one fingerprint per 4 chars and form, kept
/// in text order): a larger cap would silently drop the tail's fingerprints.
pub(super) const RECORD_CAP: usize = 6 * 1024;

/// A context-integrity data class that makes a delivery sensitive.
const SENSITIVE_CLASSES: [&str; 3] = ["personal_data", "financial_data", "guarded_material"];

impl Firewall {
    /// Record into and check against `other`'s relay detector, when there is
    /// an `other`: every firewall of one gateway shares one detector, so what
    /// one route records the other checks against (§13.1 "One detector").
    #[must_use]
    pub(crate) fn sharing_relay_with(mut self, other: Option<&Firewall>) -> Self {
        if let Some(other) = other {
            self.relay.detector.clone_from(&other.relay.detector);
            // `MIK-8408` F6: the replay store is shared exactly as the
            // detector it sits beside.
            self.relay.replay.clone_from(&other.relay.replay);
        }
        self
    }

    /// The replay receipt store beside this firewall's detector
    /// (`MIK-8408` E1; stage 1 reads it in tests only, route wiring is a
    /// later stage).
    #[cfg(test)]
    pub(super) fn replay_receipts(&self) -> &Arc<ReplayReceipts> {
        &self.relay.replay
    }

    /// The relay detector this firewall records into and checks against.
    #[cfg(test)]
    pub(crate) fn collusion_detector(&self) -> Option<&Arc<CollusionDetector>> {
        self.relay.detector.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn relay_text_cuts(&self) -> u64 {
        self.relay.text_cut.load(Ordering::Relaxed)
    }

    /// Plans whose receipts were dropped because their answer was over the
    /// bound they are kept against (MIK-7887.RECEIPT.2).
    #[cfg(test)]
    pub(crate) fn relay_plan_drops(&self) -> u64 {
        self.relay.plan_drop.load(Ordering::Relaxed)
    }

    /// Relay detection is on: callers skip staging and the receipt
    /// collector otherwise.
    pub(crate) fn relay_active(&self) -> bool {
        self.relay_detector().is_some()
    }

    fn relay_detector(&self) -> Option<&CollusionDetector> {
        self.relay
            .detector
            .as_deref()
            .filter(|_| self.config.enabled)
    }

    /// Egress check: does `params`, sent by `caller` through `server:tool`,
    /// carry content another principal was delivered? Every string of the
    /// forwarded params counts, `_meta` included. Findings are audited.
    pub(crate) fn check_relay(
        &self,
        caller: RelayCaller<'_>,
        server: &str,
        tool: &str,
        params: &Value,
        audit: (&str, &str),
    ) -> FirewallVerdict {
        let Some(detector) = self.relay_detector() else {
            return FirewallVerdict::allow();
        };
        let target = format!("{server}:{tool}");
        if self.relay.non_egress.iter().any(|p| p.matches(&target)) {
            return FirewallVerdict::allow();
        }
        let block = self.config.collusion.action == CollusionAction::Block;
        let label = if block { "block" } else { "observe" };
        if matches!(caller, RelayCaller::Unkeyed(_)) {
            telemetry_metrics::counter!(UNKEYED_METRIC, "action" => label).increment(1);
        }
        let finding = match caller {
            RelayCaller::Unkeyed(_) if block => Some((
                "unkeyed",
                relay_finding(
                    "relay check needs an authenticated caller".to_string(),
                    String::new(),
                ),
            )),
            _ => detector
                .check_egress_fingerprints_at(
                    caller.key(),
                    (&target, self.relay.egress_flows(&target)),
                    detector.egress_fingerprints(&egress_parts(params)),
                    self.relay.now(),
                )
                .map(|f| {
                    let finding = relay_finding(
                        relay_description(f.reason).to_string(),
                        format!(
                            "source={:016x} receiver={:016x} sender={:016x} matches={}",
                            f.source, f.receiver, f.sender, f.matches
                        ),
                    );
                    (f.reason.label(), finding)
                }),
        };
        let Some((reason, finding)) = finding else {
            return FirewallVerdict::allow();
        };
        // Every reported relay counts, the unkeyed block included (MIK-7873),
        // under the reason it was reported for (MIK-8201).
        telemetry_metrics::counter!(RELAY_METRIC, "action" => label, "reason" => reason)
            .increment(1);
        // The configured action alone decides: no rule may soften a relay.
        let action = if block {
            FirewallAction::Block
        } else {
            FirewallAction::Warn
        };
        let verdict = FirewallVerdict {
            allowed: !block,
            action,
            findings: vec![finding],
            anomaly_score: None,
        };
        if let Some(ref logger) = self.audit {
            logger.log_request(audit.0, server, tool, audit.1, params, &verdict);
        }
        verdict
    }

    /// [`Self::check_relay`] reduced to what every route answers with: `None`
    /// when the call may go, else the message of the `-32002` refusal. An
    /// observed relay (`Warn`) is logged here and the call goes.
    pub(crate) fn relay_block_message(
        &self,
        caller: RelayCaller<'_>,
        (server, tool): (&str, &str),
        params: &Value,
        audit: (&str, &str),
    ) -> Option<String> {
        let verdict = self.check_relay(caller, server, tool, params, audit);
        if verdict.action == FirewallAction::Warn {
            tracing::warn!(server, tool, "Firewall: relay observed");
        }
        if verdict.allowed {
            return None;
        }
        let desc = verdict
            .findings
            .first()
            .map_or("", |f| f.description.as_str());
        Some(format!("Relay detection blocked: {desc}"))
    }
}

impl Firewall {
    /// The seam fingerprints of a plan answer's value leaves (`MIK-8113`),
    /// each leaf with the plan step that produced it; empty with relay
    /// detection off.
    pub(crate) fn seam_fingerprints(
        &self,
        parts: &[(&str, Option<u32>)],
    ) -> Vec<super::collusion::SeamFingerprint> {
        self.relay_detector()
            .map(|detector| detector.seam_fingerprints(parts))
            .unwrap_or_default()
    }

    /// `MIK-8209` K6: the seam fingerprints of each key-path join of a
    /// plan's `answer` whose pieces belong to two or more steps, read run
    /// together as the join was delivered. `step_of` names the step that owns
    /// a piece, by the piece's identity in `answer`: owned only while that
    /// step's receipt keeps it whole, as the leaf pass decides.
    pub(crate) fn join_seam_fingerprints(
        &self,
        answer: &Value,
        step_of: &dyn Fn(&str) -> Option<u32>,
    ) -> Vec<super::collusion::SeamFingerprint> {
        let Some(detector) = self.relay_detector() else {
            return Vec::new();
        };
        let mut seams = Vec::new();
        for run in key_path_runs(answer) {
            let parts: Vec<(&str, Option<u32>)> = run.iter().map(|p| (*p, step_of(p))).collect();
            let owners: std::collections::BTreeSet<u32> =
                parts.iter().filter_map(|p| p.1).collect();
            if owners.len() >= 2 {
                seams.extend(detector.seam_fingerprints_in(&parts, SeamForms::RunTogether));
            }
        }
        seams
    }

    /// The `allowed_flows` mask of each of `sources`, in order: a seam's flow
    /// policy beside its sensitivity (`MIK-8113`).
    pub(crate) fn source_masks(&self, sources: &[String]) -> Vec<u64> {
        sources.iter().map(|s| self.relay.source_flows(s)).collect()
    }
}

/// What a refusal tells its caller, by reason (`MIK-8201`, `MIK-8206`). None
/// claims more than the detector recorded: the capacity texts never say this
/// text's own copy was dropped.
fn relay_description(reason: RelayReason) -> &'static str {
    match reason {
        RelayReason::Relay => "content delivered to another caller is leaving through this call",
        RelayReason::OtherSource => {
            "this text matches what the detector recorded as reaching you from a different tool, \
             and that does not excuse this relay"
        }
        RelayReason::OverflowWitness => {
            "another caller's copy of this text was kept past the relay detector's capacity, so no \
             copy of yours can excuse it"
        }
        RelayReason::ExcuseLost => {
            "the relay detector ran out of room for text you received, so it could not tell \
             whether your own copy covers this"
        }
    }
}

fn relay_finding(description: String, matched: String) -> Finding {
    Finding {
        scan_type: ScanType::CollusionRelay,
        severity: Severity::Medium,
        description,
        matched,
        location: FindingLocation::RequestArgs,
    }
}

/// The gateway-attached context-integrity verdict names a sensitive class.
fn context_integrity_sensitive(result: &Value) -> bool {
    result
        .pointer("/_context_integrity/classification/data_classes")
        .and_then(Value::as_array)
        .is_some_and(|classes| {
            classes
                .iter()
                .any(|c| c.as_str().is_some_and(|c| SENSITIVE_CLASSES.contains(&c)))
        })
}

#[path = "collusion_gate_answer.rs"]
mod answer;
#[path = "collusion_gate_receipts.rs"]
mod receipts;
#[path = "collusion_gate_replay.rs"]
mod replay_gate;
pub(crate) use replay_gate::{ReplaySource, ReplayedDigest};
#[path = "collusion_gate_seams.rs"]
mod seams;
#[path = "collusion_staging.rs"]
mod staging;
pub(crate) use staging::PlanStaging;
#[cfg(test)]
#[path = "collusion_gate_tests.rs"]
mod tests;
