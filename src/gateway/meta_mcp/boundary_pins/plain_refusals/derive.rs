// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The tables and sets derived from one walk: the effect and refused-step
//! writers, the plain-refusal helpers and the raise helpers (each to a fixed
//! point), and the two tables' rows.

use std::collections::{BTreeMap, BTreeSet};

use super::super::delivery_framing::is_refusal_name;
use super::{ASSOCIATED, Collect, Event, FACTS, FACTS_FILE, Kind, module_of, monitored_tokens};

/// Effect writers that are not call needles: `step` scopes one composite
/// step and notes its outcome; the step's own raise is the row.
const NOT_A_NEEDLE: [&str; 1] = ["step"];

/// The tables and sets derived from one walk.
pub(in super::super) struct Derived {
    /// `delivery_facts.rs` functions that write the effect, closed under
    /// calls between them.
    pub(in super::super) effect_writers: BTreeSet<String>,
    /// `delivery_facts.rs` functions that store `LastStep::Refused`.
    pub(in super::super) step_writers: BTreeSet<String>,
    /// Error-valued `src/gateway` functions that build one of the twelve,
    /// to a fixed point.
    pub(in super::super) helpers: BTreeSet<String>,
    /// (file, fn, needle) -> count.
    pub(in super::super) raises: BTreeMap<String, usize>,
    /// Raise helpers outside `delivery_facts.rs`, as `file::fn`.
    pub(in super::super) raise_helpers: BTreeSet<String>,
    /// (file, fn, needle, ordinal), in walk order.
    pub(in super::super) plain: Vec<String>,
}

fn fns_with(events: &[Event], file: &str, hit: impl Fn(&Kind) -> bool) -> BTreeSet<String> {
    events
        .iter()
        .filter(|e| e.file == file && hit(&e.kind))
        .map(|e| e.func.clone())
        .collect()
}

impl Collect {
    /// The effect writers (closed under calls in `delivery_facts.rs`) and
    /// the `LastStep::Refused` writers.
    fn writers(&self) -> (BTreeSet<String>, BTreeSet<String>) {
        let events = &self.events;
        let mut effect_writers =
            fns_with(events, FACTS_FILE, |k| *k == Kind::Writes("facts.effect ="));
        loop {
            let more = fns_with(
                events,
                FACTS_FILE,
                |k| matches!(k, Kind::Call { name, method: false, value: false, .. } if effect_writers.contains(name)),
            );
            let before = effect_writers.len();
            effect_writers.extend(more);
            if effect_writers.len() == before {
                break;
            }
        }
        let step_writers = fns_with(events, FACTS_FILE, |k| {
            *k == Kind::Writes("facts.last_step = Refused")
        });
        (effect_writers, step_writers)
    }

    /// Error-valued `src/gateway` functions that build one of the twelve or
    /// call such a function, to a fixed point.
    fn helper_set(&self) -> BTreeSet<(String, String)> {
        let mut helpers: BTreeSet<(String, String)> = BTreeSet::new();
        loop {
            let builds = |e: &Event| match &e.kind {
                Kind::Construct { .. } => true,
                Kind::Call {
                    owner,
                    name,
                    method,
                    ..
                } => {
                    (owner.as_deref() == Some("Error") && ASSOCIATED.contains(&name.as_str()))
                        || self.calls_helper(e, &helpers)
                        || (*method && helpers.iter().any(|h| h.1 == *name))
                }
                _ => false,
            };
            let more: BTreeSet<(String, String)> = self
                .events
                .iter()
                .filter(|e| {
                    e.file.starts_with("src/gateway/")
                        && self
                            .error_valued
                            .contains(&(e.file.clone(), e.func.clone()))
                        && builds(e)
                })
                .map(|e| (e.file.clone(), e.func.clone()))
                .collect();
            let before = helpers.len();
            helpers.extend(more);
            if helpers.len() == before {
                return helpers;
            }
        }
    }

    /// Whether `event` names one of `helpers`: a non-method call or value by
    /// [`Self::names_fn`], a method call by its name (a method's owner type
    /// is not resolved).
    fn calls_helper(&self, event: &Event, helpers: &BTreeSet<(String, String)>) -> bool {
        match &event.kind {
            Kind::Call {
                name, method: true, ..
            } => helpers.iter().any(|h| h.1 == *name),
            _ => helpers
                .iter()
                .any(|h| self.names_fn(event, (h.0.as_str(), h.1.as_str()))),
        }
    }

    /// Whether `event` (a non-method call or value use) names the function
    /// `name` defined in `file`: a bare name in that file or in a file that
    /// imports it through its module, or a path whose segment before the
    /// name is that module.
    fn names_fn(&self, event: &Event, (file, name): (&str, &str)) -> bool {
        let Kind::Call {
            owner,
            name: called,
            method: false,
            ..
        } = &event.kind
        else {
            return false;
        };
        if called != name {
            return false;
        }
        let module = module_of(file);
        match owner {
            Some(owner) => *owner == module,
            None => {
                event.file == file
                    || self.uses.iter().any(|(f, path)| {
                        *f == event.file && path.ends_with(&[module.clone(), name.to_string()])
                    })
            }
        }
    }

    /// Raise helpers: functions outside `delivery_facts.rs` returning `()`
    /// that hold a raise or call another raise helper, to a fixed point.
    /// Deleting a call of one drops a record as surely as deleting a raise.
    fn raise_helpers(&self, needles: &BTreeSet<&String>) -> BTreeSet<(String, String)> {
        let raises_in = |func: &(String, String), helpers: &BTreeSet<(String, String)>| {
            self.events.iter().any(|e| {
                e.file == func.0
                    && e.func == func.1
                    && match &e.kind {
                        Kind::Call {
                            owner: Some(owner),
                            name,
                            method: false,
                            ..
                        } if owner == FACTS => needles.contains(name),
                        _ => helpers
                            .iter()
                            .any(|h| self.names_fn(e, (h.0.as_str(), h.1.as_str()))),
                    }
            })
        };
        let mut helpers = BTreeSet::new();
        loop {
            let more: BTreeSet<(String, String)> = self
                .unit_fns
                .iter()
                .filter(|f| raises_in(f, &helpers))
                .cloned()
                .collect();
            let before = helpers.len();
            helpers.extend(more);
            if helpers.len() == before {
                return helpers;
            }
        }
    }

    pub(in super::super) fn derive(&self) -> Derived {
        let events = &self.events;
        let (effect_writers, step_writers) = self.writers();
        let needles: BTreeSet<&String> = effect_writers
            .iter()
            .chain(&step_writers)
            .filter(|n| !NOT_A_NEEDLE.contains(&n.as_str()))
            .collect();
        let helper_fns = self.helper_set();
        let helpers: BTreeSet<String> = helper_fns.iter().map(|h| h.1.clone()).collect();
        let raise_helpers = self.raise_helpers(&needles);

        let mut raises = BTreeMap::new();
        let mut plain = Vec::new();
        let mut ordinals: BTreeMap<String, usize> = BTreeMap::new();
        for event in events {
            let key = format!("{}\t{}", event.file, event.func);
            let gateway = event.file.starts_with("src/gateway/");
            let mut plain_needle = None;
            match &event.kind {
                Kind::Writes(needle) => {
                    *raises.entry(format!("{key}\t{needle}")).or_insert(0) += 1;
                }
                Kind::Call {
                    owner,
                    name,
                    value,
                    method: false,
                    combinator,
                } => {
                    // Inside delivery_facts.rs a bare name is a raise only when
                    // called: a local such as `refused` in `step` is not one.
                    let through = owner.as_deref() == Some(FACTS)
                        || (event.file == FACTS_FILE && owner.is_none() && !*value);
                    let suffix = if *value { " (as value)" } else { "" };
                    if through && needles.contains(name) {
                        *raises.entry(format!("{key}\t{name}{suffix}")).or_insert(0) += 1;
                    }
                    if raise_helpers
                        .iter()
                        .any(|h| self.names_fn(event, (h.0.as_str(), h.1.as_str())))
                    {
                        *raises
                            .entry(format!("{key}\tvia {name}{suffix}"))
                            .or_insert(0) += 1;
                    }
                    let associated =
                        owner.as_deref() == Some("Error") && ASSOCIATED.contains(&name.as_str());
                    // A refusal-named helper called, or handed to a combinator,
                    // is rowed by the refusal scan; any other value use is not.
                    let rowed_there = is_refusal_name(name) && (!*value || *combinator);
                    let helper = self.calls_helper(event, &helper_fns) && !rowed_there;
                    if gateway && (associated || helper) {
                        plain_needle = Some(format!("via {name}{suffix}"));
                    }
                }
                Kind::Call {
                    name, method: true, ..
                } => {
                    if gateway && self.calls_helper(event, &helper_fns) && !is_refusal_name(name) {
                        plain_needle = Some(format!("via {name}"));
                    }
                }
                Kind::Construct {
                    variant,
                    form,
                    wrapped,
                } => {
                    let shape = match *form {
                        "call" => format!("Error::{variant}(..)"),
                        "{}" => format!("Error::{variant}{{}}"),
                        _ => format!("Error::{variant} (as value)"),
                    };
                    let wrap = if *wrapped { " wrapped" } else { "" };
                    plain_needle = Some(format!("{shape}{wrap}"));
                }
                Kind::Closure(name) if gateway => {
                    plain_needle = Some(format!("via {name} (closure)"));
                }
                Kind::InMacro(tokens) => {
                    let names = monitored_tokens(tokens, &helpers);
                    let is_facts = |n: &String| n == FACTS || n.starts_with(&format!("{FACTS}*"));
                    if let Some(facts) = names.iter().find(|n| is_facts(n)) {
                        *raises
                            .entry(format!("{key}\t{facts} (in macro)"))
                            .or_insert(0) += 1;
                    }
                    let plain_names: Vec<&str> = names
                        .iter()
                        .filter(|n| !is_facts(n))
                        .map(String::as_str)
                        .collect();
                    if gateway && !plain_names.is_empty() {
                        plain_needle = Some(format!("{} (in macro)", plain_names.join(",")));
                    }
                }
                _ => {}
            }
            if let Some(needle) = plain_needle {
                let row = format!("{key}\t{needle}");
                let n = ordinals.entry(row.clone()).or_insert(0);
                *n += 1;
                plain.push(format!("{row}\t{n}"));
            }
        }
        plain.sort();
        Derived {
            raise_helpers: raise_helpers
                .iter()
                .map(|(file, name)| format!("{file}::{name}"))
                .collect(),
            effect_writers,
            step_writers,
            helpers,
            raises,
            plain,
        }
    }

    /// Imports through `delivery_facts` that hide a raise: a glob, a renamed
    /// module, or a raise imported by name.
    pub(in super::super) fn raise_imports(&self, derived: &Derived) -> Vec<String> {
        self.facts_uses
            .iter()
            .filter(|(_, key, _)| {
                key == "*"
                    || derived.effect_writers.contains(key)
                    || derived.step_writers.contains(key)
            })
            .map(|(_, _, text)| text.clone())
            .collect()
    }

    /// Imports that rename a discovered helper (`use x::helper as other`).
    pub(in super::super) fn helper_renames(&self, helpers: &BTreeSet<String>) -> Vec<String> {
        self.renames
            .iter()
            .filter(|(_, from, _)| helpers.contains(from))
            .map(|(file, from, to)| format!("{file}: use {from} as {to}"))
            .collect()
    }
}
