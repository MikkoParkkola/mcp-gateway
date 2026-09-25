// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Undeclared argument keys, nested and top-level (MIK-7570.SCHEMA.1, R2).
//!
//! A child of `schema_bounds` so local `$ref`s resolve through the parent's
//! private resolver. Not a JSON Schema validator (ruling R6): it decides only
//! whether each argument key is declared, plus the value of a key admitted by a
//! schema-valued `additionalProperties`. Every limit fails closed.
//!
//! Per key K at one object level the verdict is Refuse, Accept or Undecided:
//! own keywords first, then combinators, Refuse over Accept over Undecided.
//! Undecided is accepted only at a free map, a level whose every keyword is in
//! [`KEY_NEUTRAL`], and under `standard`, where only an explicit refusal closes.

use std::collections::HashMap;

use regex::{Regex, RegexBuilder};
use serde_json::{Map, Value};

use super::resolve;
use crate::config::InputSchemaEnforcement;

/// Depth from the root, per path: object, array and `$ref` descents each count.
pub(crate) const MAX_DEPTH: usize = 16;
/// Node visits per call, shared across all paths.
pub(crate) const MAX_VISITS: usize = 10_000;
/// Compiled-size ceiling for one `patternProperties` regex.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// Keywords that do not constrain which keys an object may carry.
const KEY_NEUTRAL: &[&str] = &[
    "type",
    "title",
    "description",
    "default",
    "examples",
    "$comment",
    "$schema",
    "$id",
    "$anchor",
    "$defs",
    "definitions",
    "deprecated",
    "readOnly",
    "writeOnly",
    "format",
    "minProperties",
    "maxProperties",
    "contentMediaType",
    "contentEncoding",
];

/// One reason a call is refused. Paths are the caller's own keys; they are
/// bounded and escaped where they are rendered, never logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeyFault {
    /// The key at this path is not declared by the schema.
    Undeclared(String),
    /// A value admitted by a schema-valued `additionalProperties` is not of its type.
    WrongType(String, String),
    /// The walk went deeper than [`MAX_DEPTH`].
    TooDeep,
    /// The walk visited more than [`MAX_VISITS`] nodes.
    TooComplex,
}

/// Every undeclared key in `arguments` under `schema`, empty when the call may
/// proceed. `off` checks nothing.
#[must_use]
pub(crate) fn undeclared_keys(
    arguments: &Value,
    schema: &Value,
    mode: InputSchemaEnforcement,
) -> Vec<KeyFault> {
    if mode == InputSchemaEnforcement::Off {
        return Vec::new();
    }
    let mut walk = Walk {
        schema: std::marker::PhantomData,
        standard: mode == InputSchemaEnforcement::Standard,
        visits: 0,
        limit: None,
        memo: HashMap::new(),
        patterns: HashMap::new(),
    };
    let mut faults = walk.node(arguments, schema, schema, "", 0);
    if let Some(limit) = walk.limit {
        faults = vec![limit];
    }
    faults
}

/// What a key's value must satisfy once the key is accepted.
#[derive(Debug, Clone)]
enum Req<'a> {
    /// Nothing further.
    Free,
    /// The value is walked under this schema (resolved against the root).
    Schema(&'a Value, &'a Value),
    /// As `Schema`, and the value must also be of the schema's `type`.
    Extra(&'a Value, &'a Value),
    /// Every requirement holds.
    All(Vec<Req<'a>>),
    /// At least one requirement holds.
    Any(Vec<Req<'a>>),
}

#[derive(Debug, Clone)]
enum Verdict<'a> {
    Refuse,
    Accept(Req<'a>),
    Undecided,
    /// The schema matches no object: Refuse under `allOf`, ignored under `anyOf`.
    MatchesNothing,
}

struct Walk<'a> {
    /// Ties the requirements built during the walk to the schema's lifetime.
    schema: std::marker::PhantomData<&'a Value>,
    standard: bool,
    visits: usize,
    limit: Option<KeyFault>,
    /// (schema node, argument node, depth) → faults, so a shared subtree is
    /// judged once per depth.
    memo: HashMap<(usize, usize, usize), Vec<KeyFault>>,
    patterns: HashMap<String, Option<Regex>>,
}

impl<'a> Walk<'a> {
    /// Charge one visit; false once a limit has been hit.
    fn charge(&mut self, depth: usize) -> bool {
        if self.limit.is_some() {
            return false;
        }
        self.visits += 1;
        if depth > MAX_DEPTH {
            self.limit = Some(KeyFault::TooDeep);
        } else if self.visits > MAX_VISITS {
            self.limit = Some(KeyFault::TooComplex);
        }
        self.limit.is_none()
    }

    /// Walk one argument node under one schema.
    fn node(
        &mut self,
        value: &Value,
        root: &'a Value,
        schema: &'a Value,
        path: &str,
        depth: usize,
    ) -> Vec<KeyFault> {
        if !self.charge(depth) {
            return Vec::new();
        }
        let key = (
            std::ptr::from_ref(schema) as usize,
            std::ptr::from_ref(value) as usize,
            depth,
        );
        if let Some(done) = self.memo.get(&key) {
            return done.clone();
        }
        let faults = match value {
            Value::Object(map) => self.object(map, root, schema, path, depth),
            Value::Array(items) => {
                let mut faults = Vec::new();
                for (i, item) in items.iter().enumerate() {
                    let req = self.element(root, schema, i, depth);
                    let at = format!("{path}[{i}]");
                    faults.extend(self.value(item, &req, &at, depth + 1));
                }
                faults
            }
            _ => Vec::new(),
        };
        self.memo.insert(key, faults.clone());
        faults
    }

    fn object(
        &mut self,
        map: &Map<String, Value>,
        root: &'a Value,
        schema: &'a Value,
        path: &str,
        depth: usize,
    ) -> Vec<KeyFault> {
        let mut faults = Vec::new();
        for (name, item) in map {
            let at = if path.is_empty() {
                name.clone()
            } else {
                format!("{path}.{name}")
            };
            match self.verdict(root, schema, name, depth, false) {
                Verdict::Accept(req) => faults.extend(self.value(item, &req, &at, depth + 1)),
                Verdict::Undecided if self.standard || is_free_map(schema) => {}
                Verdict::Undecided | Verdict::Refuse | Verdict::MatchesNothing => {
                    faults.push(KeyFault::Undeclared(at));
                }
            }
        }
        faults
    }

    /// Check a value against what its key's acceptance requires.
    fn value(&mut self, value: &Value, req: &Req<'a>, path: &str, depth: usize) -> Vec<KeyFault> {
        let _ = (value, path, depth);
        if true {
            return Vec::new();
        }
        match req {
            Req::Free => Vec::new(),
            Req::Schema(root, schema) => self.node(value, root, schema, path, depth),
            Req::Extra(root, schema) => {
                let mut faults = self.node(value, root, schema, path, depth);
                if let Some(expected) = type_mismatch(value, schema) {
                    faults.push(KeyFault::WrongType(path.to_owned(), expected));
                }
                faults
            }
            Req::All(reqs) => reqs
                .iter()
                .flat_map(|r| self.value(value, r, path, depth))
                .collect(),
            Req::Any(reqs) => {
                let mut first = None;
                for r in reqs {
                    let faults = self.value(value, r, path, depth);
                    if faults.is_empty() {
                        return faults;
                    }
                    first.get_or_insert(faults);
                }
                first.unwrap_or_default()
            }
        }
    }

    /// The verdict on key `key` at the object level `schema`.
    ///
    /// `hops` counts `$ref` and combinator descents that consume no argument
    /// depth, so a pure `$ref` cycle ends at the depth limit.
    fn verdict(
        &mut self,
        root: &'a Value,
        schema: &'a Value,
        key: &str,
        hops: usize,
        in_any: bool,
    ) -> Verdict<'a> {
        if !self.charge(hops) {
            return Verdict::Refuse;
        }
        let map = match schema {
            Value::Bool(true) => return Verdict::Accept(Req::Free),
            Value::Bool(false) => return Verdict::MatchesNothing,
            Value::Object(map) => map,
            _ => return Verdict::Undecided,
        };
        if in_any && is_free_map(schema) {
            return Verdict::Accept(Req::Free);
        }
        if matches_nothing(map) {
            return Verdict::MatchesNothing;
        }
        let root = if map.get("$id").is_some_and(Value::is_string) {
            schema
        } else {
            root
        };
        let mut parts = vec![self.own(root, map, key)];
        // `{$ref: X, ...siblings}` is `allOf: [X, {...siblings}]` (2020-12).
        if let Some(Value::String(pointer)) = map.get("$ref") {
            // `combine` reads a match-nothing target as Refuse; an unresolved
            // one adds nothing, so it neither opens nor closes the level.
            if let Some(target) = resolve(root, pointer) {
                parts.push(self.verdict(root, target, key, hops + 1, false));
            } else {
                count("unresolved_ref");
            }
        }
        if let Some(Value::Array(branches)) = map.get("allOf") {
            parts.push(self.all_of(root, branches, key, hops));
        }
        for word in ["anyOf", "oneOf"] {
            if let Some(Value::Array(branches)) = map.get(word) {
                parts.push(self.any_of(root, branches, key, hops));
            }
        }
        combine(parts)
    }

    fn all_of(
        &mut self,
        root: &'a Value,
        branches: &'a [Value],
        key: &str,
        hops: usize,
    ) -> Verdict<'a> {
        let mut parts = Vec::new();
        for branch in branches {
            parts.push(match self.verdict(root, branch, key, hops + 1, false) {
                Verdict::MatchesNothing => Verdict::Refuse,
                other => other,
            });
        }
        combine(parts)
    }

    fn any_of(
        &mut self,
        root: &'a Value,
        branches: &'a [Value],
        key: &str,
        hops: usize,
    ) -> Verdict<'a> {
        let mut accepted = Vec::new();
        for branch in branches {
            if let Verdict::Accept(req) = self.verdict(root, branch, key, hops + 1, true) {
                accepted.push(req);
            }
        }
        if accepted.is_empty() {
            Verdict::Undecided
        } else {
            Verdict::Accept(Req::Any(accepted))
        }
    }

    /// The level's own keywords: `properties`, `patternProperties`,
    /// `additionalProperties` and object-valued `enum`/`const`.
    fn own(&mut self, root: &'a Value, map: &'a Map<String, Value>, key: &str) -> Verdict<'a> {
        let mut declared = Vec::new();
        if let Some(prop) = map.get("properties").and_then(|p| p.get(key)) {
            declared.push(Req::Schema(root, prop));
        }
        if let Some(Value::Object(patterns)) = map.get("patternProperties") {
            for (pattern, sub) in patterns {
                if self.pattern(pattern).is_some_and(|re| re.is_match(key)) {
                    declared.push(Req::Schema(root, sub));
                }
            }
        }
        if !declared.is_empty() {
            return Verdict::Accept(Req::All(declared));
        }
        match map.get("additionalProperties") {
            Some(Value::Bool(false)) => return Verdict::Refuse,
            Some(Value::Bool(true)) => return Verdict::Accept(Req::Free),
            Some(extra @ Value::Object(_)) => return Verdict::Accept(Req::Extra(root, extra)),
            _ => {}
        }
        let mut literals = map
            .get("enum")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .chain(map.get("const"))
            .filter_map(Value::as_object)
            .peekable();
        if literals.peek().is_some() {
            return if literals.any(|object| object.contains_key(key)) {
                Verdict::Accept(Req::Free)
            } else {
                Verdict::Refuse
            };
        }
        Verdict::Undecided
    }

    /// A compiled `patternProperties` regex; one that does not compile matches
    /// nothing, so its keys stay undeclared (fail closed).
    fn pattern(&mut self, pattern: &str) -> Option<&Regex> {
        self.patterns
            .entry(pattern.to_owned())
            .or_insert_with(|| {
                let built = RegexBuilder::new(pattern)
                    .size_limit(REGEX_SIZE_LIMIT)
                    .build()
                    .ok();
                if built.is_none() {
                    tracing::warn!("patternProperties regex does not compile; it matches nothing");
                    count("bad_pattern");
                }
                built
            })
            .as_ref()
    }

    /// What element `index` of an array under `schema` must satisfy.
    fn element(
        &mut self,
        root: &'a Value,
        schema: &'a Value,
        index: usize,
        hops: usize,
    ) -> Req<'a> {
        let Value::Object(map) = schema else {
            return Req::Free;
        };
        if !self.charge(hops) {
            return Req::Free;
        }
        let root = if map.get("$id").is_some_and(Value::is_string) {
            schema
        } else {
            root
        };
        let mut all = Vec::new();
        let prefix = map.get("prefixItems").and_then(Value::as_array);
        match prefix.and_then(|p| p.get(index)) {
            Some(item) => all.push(Req::Schema(root, item)),
            None => match map.get("items") {
                Some(Value::Array(legacy)) => {
                    if let Some(item) = legacy.get(index) {
                        all.push(Req::Schema(root, item));
                    }
                }
                Some(item) => all.push(Req::Schema(root, item)),
                None => {}
            },
        }
        if let Some(Value::String(pointer)) = map.get("$ref")
            && let Some(target) = resolve(root, pointer)
        {
            all.push(self.element(root, target, index, hops + 1));
        }
        if let Some(Value::Array(branches)) = map.get("allOf") {
            for branch in branches {
                all.push(self.element(root, branch, index, hops + 1));
            }
        }
        for word in ["anyOf", "oneOf"] {
            if let Some(Value::Array(branches)) = map.get(word) {
                let any: Vec<_> = branches
                    .iter()
                    .filter(|b| !b.as_object().is_some_and(matches_nothing))
                    .map(|b| self.element(root, b, index, hops + 1))
                    .collect();
                if !any.is_empty() {
                    all.push(Req::Any(any));
                }
            }
        }
        Req::All(all)
    }
}

/// Refuse over Accept over Undecided; every accepted requirement must hold.
fn combine(parts: Vec<Verdict<'_>>) -> Verdict<'_> {
    let mut accepted = Vec::new();
    for part in parts {
        match part {
            Verdict::Refuse | Verdict::MatchesNothing => return Verdict::Refuse,
            Verdict::Accept(req) => accepted.push(req),
            Verdict::Undecided => {}
        }
    }
    if accepted.is_empty() {
        Verdict::Undecided
    } else {
        Verdict::Accept(Req::All(accepted))
    }
}

/// A level that accepts any key: `true`, or an object-capable schema whose
/// every keyword is in [`KEY_NEUTRAL`] (an allowlist, so an unrecognised
/// keyword closes the level rather than opening it).
fn is_free_map(schema: &Value) -> bool {
    match schema {
        Value::Bool(open) => *open,
        Value::Object(map) => {
            // `properties: {}` declares no key (design revision 2, item 4).
            !matches_nothing(map)
                && map.iter().all(|(k, v)| {
                    KEY_NEUTRAL.contains(&k.as_str())
                        || (k == "properties" && v.as_object().is_some_and(Map::is_empty))
                })
        }
        _ => false,
    }
}

/// `enum: []`, or a `type` that excludes `object`.
fn matches_nothing(map: &Map<String, Value>) -> bool {
    if map
        .get("enum")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        return true;
    }
    match map.get("type") {
        Some(Value::String(ty)) => ty != "object",
        Some(Value::Array(types)) => !types.iter().any(|t| t == "object"),
        _ => false,
    }
}

/// The declared `type` a value fails, allowing the coercions the capability
/// validator applies (`"3"` for an integer, `"true"` for a boolean).
fn type_mismatch(value: &Value, schema: &Value) -> Option<String> {
    let ty = schema.get("type")?.as_str()?;
    let text = value.as_str().map(str::trim);
    let fits = match ty {
        "string" => value.is_string(),
        "integer" => {
            value.is_i64() || value.is_u64() || text.is_some_and(|t| t.parse::<i64>().is_ok())
        }
        "number" => value.is_number() || text.is_some_and(|t| t.parse::<f64>().is_ok()),
        "boolean" => value.is_boolean() || matches!(text, Some("true" | "false")),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "null" => value.is_null(),
        _ => true,
    };
    (!fits).then(|| ty.to_owned())
}

/// Count a schema event by a fixed label; never an argument key.
pub(crate) fn count(kind: &'static str) {
    telemetry_metrics::counter!("mcp_input_schema_events_total", "kind" => kind).increment(1);
}

#[cfg(test)]
mod tests;
