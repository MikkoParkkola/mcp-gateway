// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `audit verify` pairs settle records: each intent with
//! its terminal record, by token and role, over the records the chain check
//! already verified. Findings name a token, a role, a rule and counters,
//! never a payload value; tokens stay raw here, and the CLI escapes them.

use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::super::settle::{self, FieldProblem, KIND_PREFIX, Role};

/// What pairing found over one verified stream.
#[derive(Debug, Default)]
pub(super) struct Findings {
    /// The first pairing failure: the deciding record's counter, and a
    /// message naming the rule and the token.
    pub(super) failure: Option<(u64, String)>,
    /// Findings that do not fail the verdict.
    pub(super) warnings: Vec<String>,
    /// Information lines: expired intents, legacy intents.
    pub(super) notes: Vec<String>,
}

/// A dependent record, kept for the end-of-stream rules.
#[derive(Debug)]
struct Dependent {
    counter: u64,
    token: String,
    role: Role,
    intent_counter: Option<u64>,
    settled_by: Option<(String, u64)>,
}

/// Pairing state over the records of one stream, fed in order.
// ponytail: O(settle records) memory in a retry-heavy log, since every
// repeat's counter is kept for exact membership; spill the counter sets to
// a sorted temp file past a budget if a log ever needs it.
#[derive(Debug, Default)]
pub(super) struct Pairing {
    /// (token, role) -> the caller-view digest and every repeat's counter.
    /// Outcome and abandoned share one slot: a token has one terminal.
    groups: HashMap<(String, Role), (String, BTreeSet<u64>)>,
    dependents: Vec<Dependent>,
    /// Tokens with an outcome record.
    outcomes: BTreeSet<String>,
    failure: Option<(u64, String)>,
    legacy: usize,
    /// Intent counters by token (writer and recovery intents alike): one
    /// lookup answers whether a token has an intent at a counter.
    intents: HashMap<String, BTreeSet<u64>>,
    /// Files holding a mismatched record, by position in the stream
    /// (oldest first, from 1): the first counter and the count.
    mismatched: BTreeMap<usize, (u64, usize)>,
}

/// A failure message: the rule, the counter and the token.
fn failed(rule: &str, counter: u64, token: &str) -> (u64, String) {
    (
        counter,
        format!("{rule} at counter {counter} (token {token})"),
    )
}

impl Pairing {
    /// Take one verified record at `counter`, read from the stream's
    /// `file`-th file (oldest first, from 0).
    pub(super) fn observe(&mut self, entry: &Value, counter: u64, file: usize) {
        let Some(fields) = entry.as_object() else {
            return;
        };
        let event = fields.get("event").and_then(Value::as_str).unwrap_or("");
        let prefixed = fields
            .get("kind")
            .and_then(Value::as_str)
            .is_some_and(|k| k.starts_with(KIND_PREFIX));
        match (Role::from_event(event), prefixed) {
            (Some(role), true) => self.settle_record(role, fields, counter),
            (Some(Role::Intent(_) | Role::RecoveryIntent), false) => self.legacy += 1,
            (Some(_), false) | (None, true) => {
                let seen = self.mismatched.entry(file + 1).or_insert((counter, 0));
                seen.1 += 1;
            }
            (None, false) => {}
        }
    }

    /// One settle record. A record that breaks a rule is skipped, and the
    /// first such break is the failure; later records are still taken, so
    /// an intent whose outcome follows a broken record is not warned.
    fn settle_record(&mut self, role: Role, fields: &Map<String, Value>, counter: u64) {
        let token = fields.get("token").and_then(Value::as_str).unwrap_or("-");
        if let Err(f) = settle::role_fields(role, fields) {
            let problem = match f.problem {
                FieldProblem::Missing => "missing",
                FieldProblem::Mistyped => "mistyped",
                FieldProblem::Forbidden => "forbidden",
            };
            let why = format!("field {} {problem} for {}", f.field, role.event());
            self.failure
                .get_or_insert_with(|| failed(&why, counter, token));
            return;
        }
        let view = Value::Object(settle::caller_view(fields));
        let digest = crate::hashing::canonical_json_sha256(&view);
        let slot = if role == Role::Abandoned {
            Role::Outcome
        } else {
            role
        };
        let (kept, counters) = self
            .groups
            .entry((token.to_string(), slot))
            .or_insert_with(|| (digest.clone(), BTreeSet::new()));
        if *kept != digest {
            let why = "two different records for one token and role";
            self.failure
                .get_or_insert_with(|| failed(why, counter, token));
            return;
        }
        counters.insert(counter);
        if matches!(role, Role::Intent(_) | Role::RecoveryIntent) {
            let at = self.intents.entry(token.to_string()).or_default();
            at.insert(counter);
        }
        if role == Role::Outcome {
            self.outcomes.insert(token.to_string());
        }
        if !matches!(role, Role::Intent(_) | Role::RecoveryIntent) {
            let by = fields.get("settled_by").and_then(|b| {
                let t = b.get("token")?.as_str()?.to_string();
                Some((t, b.get("intent_counter")?.as_u64()?))
            });
            self.dependents.push(Dependent {
                counter,
                token: token.to_string(),
                role,
                intent_counter: fields.get("intent_counter").and_then(Value::as_u64),
                settled_by: by,
            });
        }
    }
}

impl Pairing {
    /// The findings, given the retention `boundary`: the counter of the
    /// first record of the oldest file streamed.
    pub(super) fn finish(mut self, boundary: Option<u64>) -> Findings {
        let below = |n: u64| boundary.is_some_and(|b| n < b);
        let mut notes = Vec::new();
        if self.failure.is_none() {
            self.failure = self
                .dependents
                .iter()
                .find_map(|d| self.check(d, &below, &mut notes));
        }
        if self.legacy > 0 {
            notes.push(format!(
                "{} config intents written before outcome records existed; not paired",
                self.legacy
            ));
        }
        let mut warnings = self.unsettled_intents();
        for (file, (at, n)) in &self.mismatched {
            warnings.push(format!(
                "not a settle record at counter {at} in file {file} ({n} in this file)"
            ));
        }
        Findings {
            failure: self.failure,
            warnings,
            notes,
        }
    }

    /// Rules 4-6 for one dependent: a failure, or info lines for what
    /// retention expired.
    fn check(
        &self,
        d: &Dependent,
        below: &impl Fn(u64) -> bool,
        notes: &mut Vec<String>,
    ) -> Option<(u64, String)> {
        let (event, at, token) = (d.role.event(), d.counter, d.token.as_str());
        if let Some(n) = d.intent_counter {
            if below(n) {
                notes.push(format!(
                    "intent expired: {event} at counter {at} names counter {n} (token {token})"
                ));
            } else if !self.is_intent(token, n) {
                let rule = "names no intent of its token at that counter";
                return Some(failed(rule, at, token));
            }
        }
        if let Some((by, n)) = &d.settled_by {
            if below(*n) {
                notes.push(format!(
                    "settled_by names an intent expired by retention at counter {at} (token {token})"
                ));
            } else if !self.is_intent(by, *n) {
                return Some(failed("settled_by names no intent", at, token));
            }
        }
        if d.role == Role::DeliveryStopped && !self.outcomes.contains(token) {
            return Some(failed("delivery stopped with no outcome", at, token));
        }
        None
    }

    /// Whether `token` has an intent (writer or recovery) at counter `n`.
    fn is_intent(&self, token: &str, n: u64) -> bool {
        self.intents.get(token).is_some_and(|at| {
            // One candidate set examined: the rows count it.
            #[cfg(test)]
            probe();
            at.contains(&n)
        })
    }

    /// Rule 3: an intent with no terminal record warns, "left to recovery"
    /// after a deferral, "interrupted" otherwise; a terminal takes
    /// precedence over a deferral.
    fn unsettled_intents(&self) -> Vec<String> {
        let mut intents: Vec<(u64, &str)> = self
            .groups
            .iter()
            .filter(|((_, role), _)| matches!(role, Role::Intent(_) | Role::RecoveryIntent))
            .filter_map(|((t, _), (_, c))| Some((*c.first()?, t.as_str())))
            .collect();
        intents.sort_unstable();
        let has = |token: &str, role| self.groups.contains_key(&(token.to_string(), role));
        intents
            .into_iter()
            .filter(|(_, token)| !has(token, Role::Outcome))
            .map(|(at, token)| {
                let what = if has(token, Role::Deferred) {
                    "left to recovery"
                } else {
                    "interrupted"
                };
                format!("intent {what} at counter {at} (token {token})")
            })
            .collect()
    }
}

#[cfg(test)]
thread_local! {
    /// Work the intent lookup did on this thread: the rows count it rather
    /// than time it, since a timing bound flakes on a loaded runner.
    pub(crate) static PROBES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Count one unit of intent-lookup work.
#[cfg(test)]
fn probe() {
    PROBES.with(|p| p.set(p.get() + 1));
}
