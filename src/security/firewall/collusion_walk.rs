// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The delivered text of a result: the string leaves a delivery walk reads, and
//! the forms a run of segments is fingerprinted in.

use serde_json::Value;

use super::super::collusion::K;
use super::Segment;

/// A run's text newline-joined, as a delivery walk joins leaves, and, for a
/// run of several value segments, those values run together too, as egress
/// reads forwarded values (keys stay out, as egress keeps them): a copy
/// delivered split mid-word over short fields then matches its holder's own
/// forwarding of the pieces (MIK-7773). A run never crosses a seam, so
/// neither form joins text across a cut.
pub(super) fn run_forms(run: &[&Segment]) -> Vec<String> {
    let joined = run
        .iter()
        .map(|s| s.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let values: Vec<&str> = run
        .iter()
        .filter(|s| !s.key)
        .map(|s| s.text.as_str())
        .collect();
    let mut forms = vec![joined];
    if values.len() > 1 {
        forms.push(values.concat());
    }
    forms
}

/// The leaves of [`delivery_parts`] (tests only).
#[cfg(test)]
pub(in super::super) fn delivery_leaves(value: &Value) -> Vec<&str> {
    delivery_parts(value).0
}

/// The string leaves of `value` a delivery walk reads, in walk order: every
/// string, leaving out a top-level `_context_integrity`, then each object key
/// of at least `K` chars; and how many of them, from the front, are values
/// (the rest are keys).
pub(in super::super) fn delivery_parts(value: &Value) -> (Vec<&str>, usize) {
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
    let (mut leaves, mut keys) = (Vec::new(), Vec::new());
    match value {
        Value::Object(map) => map
            .iter()
            .filter(|(k, _)| k.as_str() != "_context_integrity")
            .for_each(|(k, v)| {
                keys.push(k.as_str());
                visit(v, &mut leaves, &mut keys);
            }),
        _ => visit(value, &mut leaves, &mut keys),
    }
    let values = leaves.len();
    leaves.extend(keys.into_iter().filter(|k| k.chars().count() >= K));
    (leaves, values)
}
