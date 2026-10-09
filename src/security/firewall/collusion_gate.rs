// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Relay detection (OWASP ASI10) wired into the firewall: the operator config,
//! its load checks, and the egress check and delivery recording the direct
//! route calls (design `2026-09-28-asi10-verbatim-relay.md` §13.1).

use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::collusion::{
    CAPACITY_METRIC, CollusionDetector, MAX_COMMON_PRINCIPALS, RelayAction, RelayParams,
    RelayReason,
};
#[cfg(test)]
pub(super) use super::collusion_digest::delivery_leaves;
pub(super) use super::collusion_digest::delivery_parts;
use super::collusion_digest::{DELIVERED_SET_CAP, key_path_joins, key_path_run_indices};
pub(crate) use super::collusion_digest::{Delivered, DeliveryDigest};
use super::{
    Finding, FindingLocation, Firewall, FirewallAction, FirewallVerdict, ScanType, Severity,
};

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
        for flow in &self.allowed_flows {
            for pattern in [&flow.source, &flow.egress] {
                if let Err(e) = glob::Pattern::new(pattern) {
                    return field(
                        "allowed_flows",
                        &format!("has an invalid pattern {pattern:?}: {e}"),
                    );
                }
            }
        }
        for (name, patterns) in [("sources", &self.sources), ("non_egress", &self.non_egress)] {
            for pattern in patterns {
                if let Err(e) = glob::Pattern::new(pattern) {
                    return field(name, &format!("has an invalid pattern {pattern:?}: {e}"));
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
    sources: Vec<glob::Pattern>,
    non_egress: Vec<glob::Pattern>,
    /// The compiled `allowed_flows`, as (source, egress), bit `i` for entry `i`.
    flows: Vec<(glob::Pattern, glob::Pattern)>,
    /// Delivered results whose text was cut to the recording cap.
    text_cut: AtomicU64,
    /// Plans whose answer was over the bound their receipts are kept against.
    plan_drop: AtomicU64,
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
        let compile = |patterns: &[String]| {
            patterns
                .iter()
                .filter_map(|p| glob::Pattern::new(p).ok())
                .collect()
        };
        Self {
            detector: detector_for(config),
            sources: compile(&config.sources),
            non_egress: compile(&config.non_egress),
            flows: config
                .allowed_flows
                .iter()
                .take(MAX_ALLOWED_FLOWS)
                .filter_map(|f| {
                    Some((
                        glob::Pattern::new(&f.source).ok()?,
                        glob::Pattern::new(&f.egress).ok()?,
                    ))
                })
                .collect(),
            text_cut: AtomicU64::new(0),
            plan_drop: AtomicU64::new(0),
        }
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
        }
        self
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
                .check_egress_flows_at(
                    caller.key(),
                    (&target, self.relay.egress_flows(&target)),
                    &egress_text(params),
                    Instant::now(),
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

    /// Record `result` as delivered to `caller` from `server:tool`. Call it
    /// only with what the caller actually receives. Production records go
    /// through a staged or committed [`DeliveryDigest`]; this one-step form
    /// is the tests' shorthand.
    #[cfg(test)]
    pub(crate) fn record_delivery(
        &self,
        caller: RelayCaller<'_>,
        server: &str,
        tool: &str,
        result: &Value,
    ) {
        if let Some(digest) = self.delivery_digest(server, tool, result) {
            self.record_digest(caller, server, tool, &digest);
        }
    }

    /// What recording `result` from `server:tool` needs, taken now: its
    /// capped text and sensitivity. `None` when relay detection is off.
    pub(crate) fn delivery_digest(
        &self,
        server: &str,
        tool: &str,
        result: &Value,
    ) -> Option<DeliveryDigest> {
        let (digest, cut) = self.digest_with(server, tool, result, DeliveryDigest::of_parts)?;
        // `MIK-8209`: the key-path joins, on a budget of their own.
        let joins = key_path_joins(result);
        let (mut digest, joins_cut) = digest.with_joins(joins.clone());
        self.count_cut(joins_cut && !cut);
        if cut || joins_cut {
            // `MIK-8066.EXCUSE.1`: the whole delivered value, as received.
            let (leaves, values) = delivery_parts(result);
            digest.cut_fps = self.fps_of_leaves(&leaves, values, &joins);
        }
        Some(digest)
    }

    /// [`Self::delivery_digest`], or for a plan step (`plan`: what its
    /// delivery has staged so far, as [`DeliveryDigest::staged_len`] counts)
    /// staged whole, capped once it is kept to what the plan delivers or when
    /// recorded (MIK-7992). From [`DELIVERED_SET_CAP`] staged on, a step is
    /// capped now; from [`PLAN_STAGED_CAP`] on, its receipt is dropped and
    /// counted, so a plan of many steps stages a bounded total.
    pub(crate) fn receipt_digest(
        &self,
        server: &str,
        tool: &str,
        result: &Value,
        plan: Option<&Cell<usize>>,
    ) -> Option<DeliveryDigest> {
        let Some(staged) = plan else {
            return self.delivery_digest(server, tool, result);
        };
        let total = staged.get();
        if total >= PLAN_STAGED_CAP {
            self.relay_detector()?;
            self.count_plan_drop_once(staged);
            return None;
        }
        let digest = if total < DELIVERED_SET_CAP {
            let digest = self
                .digest_with(server, tool, result, DeliveryDigest::of_plan_step_parts)?
                .0;
            // `MIK-8209` K2a: the key-path runs, staged as leaf indices.
            let (leaves, values) = delivery_parts(result);
            digest.with_join_runs(key_path_run_indices(result, &leaves, values))
        } else {
            // A plan step is sketched only once kept to the plan's answer
            // (`MIK-8066` E1''): capped here, its cut text gets no sketch.
            let digest = self
                .digest_with(server, tool, result, DeliveryDigest::of_parts)?
                .0;
            let (digest, joins_cut) = digest.with_joins(key_path_joins(result));
            self.count_cut(joins_cut);
            digest
        };
        staged.set(total + digest.staged_len());
        Some(digest)
    }

    fn digest_with(
        &self,
        server: &str,
        tool: &str,
        result: &Value,
        of_parts: fn(&[&str], usize, bool) -> (DeliveryDigest, bool),
    ) -> Option<(DeliveryDigest, bool)> {
        self.relay_detector()?;
        let source = format!("{server}:{tool}");
        let sensitive = self.relay.sources.iter().any(|p| p.matches(&source))
            || context_integrity_sensitive(result);
        let (leaves, values) = delivery_parts(result);
        let (digest, cut) = of_parts(&leaves, values, sensitive);
        self.count_cut(cut);
        Some((digest, cut))
    }

    /// A copy of `digest` with its deferred cap applied, a cut counted;
    /// `None` when it was capped at staging.
    fn capped(&self, digest: &DeliveryDigest) -> Option<DeliveryDigest> {
        let (mut capped, cut) = digest.capped()?;
        self.count_cut(cut);
        if cut {
            capped.cut_fps = self.fps_of(digest);
        }
        Some(capped)
    }

    /// `MIK-8066.EXCUSE.1`: every fingerprint of a delivered value's leaves,
    /// values joined as a delivery walk reads them (both forms) and each key,
    /// all of it text the caller received; sketched when recorded
    /// (`MIK-8200`).
    fn fps_of_leaves(
        &self,
        leaves: &[&str],
        values: usize,
        joins: &[String],
    ) -> Option<Arc<[u64]>> {
        let detector = self.relay_detector()?;
        let (vals, keys) = leaves.split_at(values.min(leaves.len()));
        let mut fps = detector.fingerprints(&vals.join("\n"));
        if vals.len() > 1 {
            fps.extend(detector.fingerprints(&vals.concat()));
        }
        for key in keys {
            fps.extend(detector.fingerprints(key));
        }
        // Each key-path join alone, never run into a neighbour (`MIK-8209`).
        for join in joins {
            fps.extend(detector.fingerprints(join));
        }
        Some(fps.into())
    }

    /// `MIK-8066.EXCUSE.1`: every fingerprint of `whole`, the receipt kept
    /// to the plan's answer before its cut: what the holder received.
    fn fps_of(&self, whole: &DeliveryDigest) -> Option<Arc<[u64]>> {
        let detector = self.relay_detector()?;
        Some(whole.fingerprints(detector).into())
    }

    fn count_cut(&self, cut: bool) {
        if cut {
            self.relay.text_cut.fetch_add(1, Ordering::Relaxed);
            telemetry_metrics::counter!(CAPACITY_METRIC, "bound" => "record_text_cut").increment(1);
        }
    }

    /// The leaves of a plan's final answer that its step receipts are kept
    /// against (MIK-7887.RECEIPT.2). `None` with relay detection off, or over
    /// the bound, where the plan's receipts are dropped and counted.
    pub(crate) fn delivered_for_plan<'v>(
        &self,
        answer: &'v Value,
        staged: Option<&Cell<usize>>,
    ) -> Option<Delivered<'v>> {
        self.relay_detector()?;
        let (leaves, values) = delivery_parts(answer);
        let delivered = Delivered::of_parts(leaves, values);
        if delivered.is_none() {
            match staged {
                Some(staged) => self.count_plan_drop_once(staged),
                None => self.count_plan_drop(),
            }
        }
        delivered
    }

    /// What `answer` delivers, read as `delivered_for_plan` reads it; when it is
    /// over the bound, what `fallback` (the same text read as one leaf)
    /// delivers instead, so a fuller reading never loses a receipt the plainer
    /// one keeps (`MIK-8043.JOIN.4`). A drop is counted only when both fail.
    pub(crate) fn delivered_preferring<'v>(
        &self,
        answer: &'v Value,
        fallback: &'v Value,
        staged: Option<&Cell<usize>>,
    ) -> Option<Delivered<'v>> {
        self.relay_detector()?;
        let (leaves, values) = delivery_parts(answer);
        Delivered::of_parts(leaves, values).or_else(|| self.delivered_for_plan(fallback, staged))
    }

    /// [`Self::count_plan_drop`] unless this delivery already counted one:
    /// `staged` then holds `usize::MAX`, past every bound (`MIK-8094`).
    fn count_plan_drop_once(&self, staged: &Cell<usize>) {
        if staged.get() != usize::MAX {
            self.count_plan_drop();
            staged.set(usize::MAX);
        }
    }

    fn count_plan_drop(&self) {
        self.relay.plan_drop.fetch_add(1, Ordering::Relaxed);
        telemetry_metrics::counter!(PLAN_DROP_METRIC).increment(1);
    }

    /// `digest` kept to what `delivered` carries, its deferred cap still to
    /// apply: the seam pass reads which leaves it keeps whole before
    /// [`Self::cap_kept`] cuts any (`MIK-8113`); unchanged with relay
    /// detection off.
    pub(crate) fn retain_delivered(
        &self,
        digest: DeliveryDigest,
        delivered: &Delivered<'_>,
    ) -> DeliveryDigest {
        match self.relay_detector() {
            Some(detector) => digest.retaining(detector, delivered),
            None => digest,
        }
    }

    /// `digest` with its deferred cap applied, a cut counted.
    pub(crate) fn cap_kept(&self, digest: DeliveryDigest) -> DeliveryDigest {
        self.capped(&digest).unwrap_or(digest)
    }

    /// Record `digest` as delivered to `caller` from `server:tool`.
    pub(crate) fn record_digest(
        &self,
        caller: RelayCaller<'_>,
        server: &str,
        tool: &str,
        digest: &DeliveryDigest,
    ) {
        let Some(detector) = self.relay_detector() else {
            return;
        };
        let source = format!("{server}:{tool}");
        // MIK-8113: a seam of several sources leaves only by a flow every
        // contributing source allows.
        if let Some(sources) = digest.seam_sources.as_deref() {
            let masks = sources.iter().map(|s| self.relay.source_flows(s)).collect();
            detector.record_seam_at(
                &source,
                caller.key(),
                (digest.sensitive, masks),
                digest.fingerprints(detector),
                Instant::now(),
            );
            return;
        }
        let flows = self.relay.source_flows(&source);
        // MIK-7992: the one sink every record passes, so a plan step's
        // receipt never kept to its plan's answer is recorded capped too.
        let capped = self.capped(digest);
        let digest = capped.as_ref().unwrap_or(digest);
        let now = Instant::now();
        detector.record_cut_fingerprints_at(
            &source,
            caller.key(),
            (digest.sensitive, flows),
            (digest.fingerprints(detector), digest.cut_fps.clone()),
            now,
        );
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

/// The text a backend receives in `value`: every string leaf, newline-joined
/// (content split over short fields at word boundaries still matches), the
/// leaves once more run together, since a copy split mid-word over fields
/// shorter than a fingerprint is still one the backend can join, then every
/// object key, since a key reaches the backend like a value. What a caller
/// is delivered is read by [`delivery_parts`].
pub(super) fn egress_text(value: &Value) -> String {
    fn visit<'v>(value: &'v Value, leaves: &mut Vec<&'v str>, keys: &mut Vec<&'v str>) {
        match value {
            Value::String(s) => leaves.push(s),
            Value::Array(items) => items.iter().for_each(|v| visit(v, leaves, keys)),
            Value::Object(map) => map.iter().for_each(|(k, v)| {
                keys.push(k);
                visit(v, leaves, keys);
            }),
            _ => {}
        }
    }
    let (mut leaves, mut keys): (Vec<&str>, Vec<&str>) = (Vec::new(), Vec::new());
    visit(value, &mut leaves, &mut keys);
    let joined = (leaves.len() > 1).then(|| leaves.concat());
    let mut parts = leaves;
    parts.extend(joined.as_deref());
    parts.extend(keys);
    parts.join("\n")
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

#[cfg(test)]
#[path = "collusion_gate_tests.rs"]
mod tests;
