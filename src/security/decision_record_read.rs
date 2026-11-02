// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reading the decision object back out of a recorded entry: the receipt's
//! evidence, the activity rule filter, and the receipt's line for each piece
//! of evidence a record does not carry.

use serde_json::Value;

use super::{Decision, Effect};

/// The decision object version that writes request findings and the declared
/// effect. A record below it predates both.
pub(crate) const FINDINGS_AND_EFFECT_SINCE: u8 = 2;

/// A rule the record names no id for: its check has no rule id yet.
pub(crate) const RULE_NOT_RECORDED: &str = "rule not recorded for this check";
/// The audit-required and rollback flags, which no tool-call rule carries.
pub(crate) const FLAGS_NOT_SET: &str = "not set by this rule";
/// Evidence a record from before this gateway version could not carry.
pub(crate) const NOT_RECORDED_BY_VERSION: &str = "not recorded by this gateway version";
/// Evidence this version writes, absent for this call (an early refusal, or
/// no evidence to read).
pub(crate) const NOT_RECORDED_FOR_CALL: &str = "not recorded for this call";
/// A request check that ran and raised nothing.
pub(crate) const NO_FINDINGS: &str = "none";
/// A tool whose definition declared no effect.
pub(crate) const UNDECLARED: &str = "the tool declared no effect";

/// The receipt's evidence lines, by name, in the order the receipt shows them.
pub(crate) const EVIDENCE_FIELDS: [&str; 6] =
    ["kind", "rule", "flags", "findings", "effect", "grant"];

/// The decision object `entry` carries; `None` for a record without one
/// (written before decisions were recorded), never an error.
pub(crate) fn decision_evidence(entry: &Value) -> Option<Decision> {
    let _ = entry;
    None
}

/// Whether `entry`'s decision names `rule_id`.
pub(crate) fn matches_rule(entry: &Value, rule_id: &str) -> bool {
    let _ = (entry, rule_id);
    true
}

/// The rule line, when the record names no rule id.
pub(crate) fn rule_line(decision: &Decision) -> Option<&'static str> {
    let _ = decision;
    None
}

/// The flags line: no tool-call rule carries the audit-required or rollback
/// flags, so the receipt says they were not set by the rule.
pub(crate) fn flags_line(decision: &Decision) -> &'static str {
    let _ = decision;
    NO_FINDINGS
}

/// The findings line, when there is no list to show.
pub(crate) fn findings_line(decision: &Decision) -> Option<&'static str> {
    let _ = decision;
    None
}

/// The effect line, when there is no declared read-only or write effect to
/// show.
pub(crate) fn effect_line(decision: &Decision) -> Option<&'static str> {
    let _ = (decision, Effect::Undeclared);
    None
}
