// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The join of delivery records to calls, held for one read (a page, or all
//! the passes of one export).
//!
//! A delivery sits newer than its call, so a newest-first scan meets it first
//! and holds it in a bounded map until the call arrives. Nothing the map
//! forgets is ever restored: an evicted trace keeps a tombstone with the
//! reason, and a read that outgrows the tombstones says so for every call
//! after it.

use std::collections::{HashMap, VecDeque};

use serde_json::{Map, Value};

use super::answer::{
    DELIVERY_WINDOW, Delivery, Effect, Findings, Joined, MAX_EVICTED, MAX_PENDING, Searched, Why,
};
use super::reader::{Line, Which};
use super::rows::{Check, kind_of};
use crate::security::transparency_log::signature::SignatureState;

pub(super) use super::reader::Seen;

/// What is held for one trace.
enum Held {
    One(Delivery),
    Bad(Why),
}

/// The join state of one read.
pub(super) struct Joiner<'a, 's> {
    check: &'a Check<'s>,
    pending: HashMap<String, Held>,
    /// Insertion order of `pending`, oldest first.
    order: VecDeque<String>,
    evicted: HashMap<String, Why>,
    overflowed: bool,
    /// Admitted calls joined incomplete, or unfinished with no record.
    pub(super) join_incomplete: usize,
    /// Calls whose record failed the trust rule or was duplicated.
    pub(super) answer_integrity_failed: usize,
}

fn str_of<'a>(entry: &'a Value, key: &str) -> Option<&'a str> {
    entry.get(key).and_then(Value::as_str)
}

/// The longest a finding's text field is kept: the writer's kinds and parts
/// are short closed sets, so a longer value is not one of them.
const FINDING_FIELD_MAX: usize = 128;

/// One finding as the writer shapes it, and no more: `kind`, `severity` and
/// `where`, each only when it is a string, so a record carrying anything else
/// (a payload, a nested object) never reaches a row or a manifest.
fn project_finding(finding: &Value) -> Option<Value> {
    let object = finding.as_object()?;
    let kept: Map<String, Value> = ["kind", "severity", "where"]
        .into_iter()
        .filter_map(|key| {
            let text = object.get(key)?.as_str()?;
            let capped: String = text.chars().take(FINDING_FIELD_MAX).collect();
            Some((key.to_string(), Value::String(capped)))
        })
        .collect();
    Some(Value::Object(kept))
}

/// The bounded projection of a delivery record.
fn project(entry: &Value, unverifiable: bool) -> Delivery {
    let effect = match str_of(entry, "response_effect").and_then(Effect::parse) {
        Some(e @ (Effect::Delivered | Effect::Annotated | Effect::Rewritten | Effect::Refused)) => {
            e
        }
        _ => Effect::Unknown,
    };
    let findings = match entry.get("response_findings") {
        Some(Value::Array(list)) => Findings::Scanned {
            list: list.iter().take(32).filter_map(project_finding).collect(),
            total: entry.get("response_findings_total").and_then(Value::as_u64),
        },
        Some(Value::Null) => Findings::NotScanned,
        _ => Findings::NotRecorded,
    };
    Delivery {
        effect,
        findings,
        unverifiable,
    }
}

impl<'a, 's> Joiner<'a, 's> {
    pub(super) fn new(check: &'a Check<'s>) -> Self {
        Self {
            check,
            pending: HashMap::new(),
            order: VecDeque::new(),
            evicted: HashMap::new(),
            overflowed: false,
            join_incomplete: 0,
            answer_integrity_failed: 0,
        }
    }

    /// The trust rule: `Err` is why the record cannot be believed; `Ok(true)`
    /// is a record whose signature cannot be verified by this gateway.
    fn trust(&self, line: &Line) -> Result<bool, Why> {
        let judged = self.check.judge(line);
        match judged.state {
            SignatureState::Invalid if judged.integrity == Some("sig_missing") => {
                Err(Why::Unsigned)
            }
            SignatureState::Invalid => Err(Why::Invalid),
            SignatureState::Valid => Ok(false),
            SignatureState::Unsigned | SignatureState::SignedUnverifiable => Ok(true),
        }
    }

    /// Fold a scanned invocation-log line that is not a listed row. `true`
    /// when the line carried a trace and was routed here: the caller drops it.
    pub(super) fn observe(&mut self, line: &Line) -> bool {
        if line.log != Which::Invocation || kind_of(line).is_some() {
            return false;
        }
        let Some(trace) = str_of(&line.entry, "trace_id") else {
            return false;
        };
        match self.trust(line) {
            Err(why) => self.hold_bad(trace, why),
            Ok(unverifiable) => {
                let is_delivery = str_of(&line.entry, "event") == Some("response_delivery_attempt")
                    && str_of(&line.entry, "response_stage") == Some("transport_finalized");
                if is_delivery {
                    self.hold_record(trace, project(&line.entry, unverifiable));
                }
            }
        }
        true
    }
}

impl Joiner<'_, '_> {
    /// A record that cannot be believed poisons its trace.
    fn hold_bad(&mut self, trace: &str, why: Why) {
        if let Some(reason) = self.evicted.get_mut(trace) {
            // The first integrity reason stays; an evicted record is upgraded.
            if reason.integrity().is_none() {
                *reason = why;
            }
            return;
        }
        match self.pending.get_mut(trace) {
            Some(held @ Held::One(_)) => *held = Held::Bad(why),
            Some(Held::Bad(_)) => {}
            None => self.insert(trace, Held::Bad(why)),
        }
    }

    /// A believed `transport_finalized` record: a second one for a trace is
    /// tamper, whether the first is held or was evicted.
    fn hold_record(&mut self, trace: &str, delivery: Delivery) {
        if let Some(reason) = self.evicted.get_mut(trace) {
            if *reason == Why::Evicted {
                *reason = Why::Duplicate;
            }
            return;
        }
        match self.pending.get_mut(trace) {
            Some(held @ Held::One(_)) => *held = Held::Bad(Why::Duplicate),
            Some(Held::Bad(_)) => {}
            None => self.insert(trace, Held::One(delivery)),
        }
    }

    fn insert(&mut self, trace: &str, held: Held) {
        if self.pending.len() >= MAX_PENDING {
            self.evict_oldest();
        }
        self.order.push_back(trace.to_string());
        self.pending.insert(trace.to_string(), held);
    }

    /// The oldest-inserted entry leaves; its tombstone keeps the reason.
    fn evict_oldest(&mut self) {
        let Some(oldest) = self.order.pop_front() else {
            return;
        };
        let reason = match self.pending.remove(&oldest) {
            Some(Held::Bad(why)) => why,
            _ => Why::Evicted,
        };
        if self.evicted.len() < MAX_EVICTED {
            self.evicted.insert(oldest, reason);
        } else {
            self.overflowed = true;
        }
    }

    /// The join for a call line. Does not count: see [`Self::count`].
    pub(super) fn join(&mut self, line: &Line, seen: Seen) -> Joined {
        let Some(trace) = str_of(&line.entry, "trace_id") else {
            return Joined::NoRecord(Searched::NoTrace);
        };
        if self.overflowed {
            return Joined::Incomplete(Why::Overflow);
        }
        if let Some(why) = self.evicted.get(trace) {
            return Joined::Incomplete(*why);
        }
        match self.pending.get(trace) {
            Some(Held::One(d)) => Joined::Found(d.clone()),
            Some(Held::Bad(why)) => Joined::Incomplete(*why),
            None if seen.head_covered || seen.above >= DELIVERY_WINDOW => {
                Joined::NoRecord(Searched::Finished)
            }
            None => Joined::NoRecord(Searched::Unfinished),
        }
    }

    /// Count an admitted call's join.
    pub(super) fn count(&mut self, joined: &Joined) {
        match joined {
            Joined::Incomplete(why) => {
                self.join_incomplete += 1;
                if why.integrity().is_some() {
                    self.answer_integrity_failed += 1;
                }
            }
            Joined::NoRecord(Searched::Unfinished) => self.join_incomplete += 1,
            Joined::Found(_) | Joined::NoRecord(_) => {}
        }
    }
}
