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

use super::collusion::{CollusionDetector, MAX_COMMON_PRINCIPALS, RelayAction, RelayParams};
use super::{
    Finding, FindingLocation, Firewall, FirewallAction, FirewallVerdict, ScanType, Severity,
};

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

/// `security.firewall.collusion`: verbatim cross-principal relay detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CollusionConfig {
    /// `off` (default), `observe` or `block`.
    pub action: CollusionAction,
    /// How long a delivery is remembered, in seconds.
    pub window_secs: u64,
    /// Matching fingerprints one egress needs before it is a relay.
    pub min_matches: usize,
    /// Principals holding one fingerprint before it counts as common text.
    pub common_principals: usize,
    /// `server:tool` globs whose results are always sensitive.
    pub sources: Vec<String>,
    /// `server:tool` globs whose arguments are never checked.
    pub non_egress: Vec<String>,
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
    /// Delivered results whose text was cut to the recording cap.
    text_cut: AtomicU64,
}

impl RelayGate {
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
            text_cut: AtomicU64::new(0),
        }
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
/// 1,024-fingerprint keep limit (one fingerprint per ~8.5 chars, kept in
/// text order): a larger cap would silently drop the tail's fingerprints.
const RECORD_CAP: usize = 6 * 1024;

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

    /// Whether relay detection is on, so a delivery is worth staging.
    pub(crate) fn relay_detection_on(&self) -> bool {
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
        let finding = match caller {
            RelayCaller::Unkeyed(_) if block => Some(relay_finding(
                "relay check needs an authenticated caller".to_string(),
                String::new(),
            )),
            _ => detector
                .check_egress_at(
                    caller.key(),
                    &target,
                    &text_of(params, Walk::Egress),
                    Instant::now(),
                )
                .map(|f| {
                    relay_finding(
                        "content delivered to another caller is leaving through this call"
                            .to_string(),
                        format!(
                            "source={:016x} receiver={:016x} sender={:016x} matches={}",
                            f.source, f.receiver, f.sender, f.matches
                        ),
                    )
                }),
        };
        let Some(finding) = finding else {
            return FirewallVerdict::allow();
        };
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

    /// Record `result` as delivered to `caller` from `server:tool`. Call it
    /// only with what the caller actually receives.
    pub(crate) fn record_delivery(
        &self,
        caller: RelayCaller<'_>,
        server: &str,
        tool: &str,
        result: &Value,
    ) {
        let Some(detector) = self.relay_detector() else {
            return;
        };
        let source = format!("{server}:{tool}");
        let sensitive = self.relay.sources.iter().any(|p| p.matches(&source))
            || context_integrity_sensitive(result);
        let (text, cut) = capped(text_of(result, Walk::Delivery));
        if cut {
            self.relay.text_cut.fetch_add(1, Ordering::Relaxed);
        }
        detector.record_delivery_at(&source, caller.key(), sensitive, &text, Instant::now());
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

/// Which side of a call [`text_of`] reads.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Walk {
    /// What a backend receives: every object key too, since a key reaches
    /// the backend like a value, and the leaves once more run together.
    Egress,
    /// What a caller is delivered: only keys long enough to fingerprint
    /// alone, so short schema keys never make unrelated payloads alike.
    Delivery,
}

/// The text of `value` read as `walk`: every string leaf, newline-joined
/// (content split over short fields at word boundaries still matches); on
/// egress the leaves once more run together, since a copy split mid-word
/// over fields shorter than a fingerprint is still one the backend can
/// join; then the keys `walk` reads. A delivery leaves out the top-level
/// `_context_integrity`: that slot is the gateway's verdict about the
/// result, whose fixed wording would make unrelated results look alike; a
/// backend writing its own content there is backend collusion (§9). A
/// nested one, and any one on egress, is content.
pub(super) fn text_of(value: &Value, walk: Walk) -> String {
    fn push(out: &mut String, s: &str) {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(s);
    }
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
    match value {
        Value::Object(map) if walk == Walk::Delivery => map
            .iter()
            .filter(|(k, _)| k.as_str() != "_context_integrity")
            .for_each(|(k, v)| {
                keys.push(k);
                visit(v, &mut leaves, &mut keys);
            }),
        _ => visit(value, &mut leaves, &mut keys),
    }
    let mut out = leaves.join("\n");
    if walk == Walk::Egress && leaves.len() > 1 {
        push(&mut out, &leaves.concat());
    }
    for key in keys {
        if walk == Walk::Egress || key.chars().count() >= super::collusion::K {
            push(&mut out, key);
        }
    }
    out
}

/// `text` within [`RECORD_CAP`]: head and tail halves, each cut on a char
/// boundary, and whether anything was cut.
// ponytail: the full text is built before the cut; bound the walk itself if
// huge results show up in memory profiles.
pub(super) fn capped(text: String) -> (String, bool) {
    if text.len() <= RECORD_CAP {
        return (text, false);
    }
    let half = RECORD_CAP / 2;
    let head = text.floor_char_boundary(half);
    let tail = text.ceil_char_boundary(text.len() - half);
    (format!("{}\n{}", &text[..head], &text[tail..]), true)
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
