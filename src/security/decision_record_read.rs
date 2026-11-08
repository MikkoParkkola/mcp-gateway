// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reading the decision object back out of a recorded entry: the receipt's
//! evidence, the activity rule filter, and the receipt's line for each piece
//! of evidence a record does not carry.

use serde::Deserialize as _;
use serde_json::Value;

use super::{Decided, Decision, Effect};

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

/// A call decided for itself.
pub(crate) const DECIDED_FRESH: &str = "decided for this call";
/// A cache hit carrying the decision it was stored with.
pub(crate) const DECIDED_CACHE_COPIED: &str =
    "served from cache with the decision it was stored with";
/// A cache hit that was not decided again: only a read-only call may be one.
pub(crate) const DECIDED_CACHE_NOT_REDECIDED: &str =
    "served from cache, not re-decided; read-only calls only";
/// An idempotent replay of a stored result.
pub(crate) const DECIDED_REPLAYED: &str = "replayed from a stored result";

/// The receipt's evidence lines, by name, in the order the receipt shows them.
pub(crate) const EVIDENCE_FIELDS: [&str; 6] =
    ["kind", "rule", "grant", "flags", "findings", "effect"];

/// The decision object `entry` carries; `None` for a record without one
/// (written before decisions were recorded) and for one that does not read
/// as a decision, never an error.
pub(crate) fn decision_evidence(entry: &Value) -> Option<Decision> {
    let raw = entry.get("decision").filter(|d| object_shaped(d))?;
    Decision::deserialize(raw).ok()
}

/// Whether `decision` has the shape the writer gives it: an object, and each
/// request finding an object. serde would read a positional array as either
/// struct, which no writer produces.
fn object_shaped(decision: &Value) -> bool {
    decision.is_object()
        && decision
            .get("request_findings")
            .and_then(Value::as_array)
            .is_none_or(|found| found.iter().all(Value::is_object))
}

/// Whether `entry`'s decision names `rule_id`. A record with no decision, or
/// one that does not read, names no rule. The borrowed `rule_id` field is
/// compared exactly first, so a line that cannot match costs a pointer walk
/// and no allocation; a candidate is still fully read and compared.
pub(crate) fn matches_rule(entry: &Value, rule_id: &str) -> bool {
    entry.pointer("/decision/rule_id").and_then(Value::as_str) == Some(rule_id)
        && decision_evidence(entry).is_some_and(|d| d.rule_id.as_deref() == Some(rule_id))
}

/// The line for evidence `decision` does not carry: its version could not
/// write it, or this call has none.
fn not_recorded(decision: &Decision) -> &'static str {
    if decision.v < FINDINGS_AND_EFFECT_SINCE {
        NOT_RECORDED_BY_VERSION
    } else {
        NOT_RECORDED_FOR_CALL
    }
}

/// The rule line, when the record names no rule id.
pub(crate) fn rule_line(decision: &Decision) -> Option<&'static str> {
    decision.rule_id.is_none().then_some(RULE_NOT_RECORDED)
}

/// The flags line: no tool-call rule carries the audit-required or rollback
/// flags, so the receipt says they were not set by the rule.
pub(crate) fn flags_line(_decision: &Decision) -> &'static str {
    FLAGS_NOT_SET
}

/// The findings line, when there is no list to show.
pub(crate) fn findings_line(decision: &Decision) -> Option<&'static str> {
    match &decision.request_findings {
        None => Some(not_recorded(decision)),
        Some(found) if found.is_empty() => Some(NO_FINDINGS),
        Some(_) => None,
    }
}

/// The effect line, when there is no declared read-only or write effect to
/// show.
pub(crate) fn effect_line(decision: &Decision) -> Option<&'static str> {
    match decision.declared_effect {
        None => Some(not_recorded(decision)),
        Some(Effect::Undeclared) => Some(UNDECLARED),
        Some(Effect::ReadOnly | Effect::MayWrite) => None,
    }
}

/// How the call was decided, in the receipt's words.
pub(crate) fn decided_line(decision: &Decision) -> &'static str {
    match decision.decided {
        Decided::Fresh => DECIDED_FRESH,
        Decided::CacheHitCopied => DECIDED_CACHE_COPIED,
        Decided::CacheHitNotRedecided => DECIDED_CACHE_NOT_REDECIDED,
        Decided::Replayed => DECIDED_REPLAYED,
    }
}
