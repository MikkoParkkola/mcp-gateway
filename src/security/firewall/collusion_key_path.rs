// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8209` (design §14.1 K1): the per-key-path joins of a delivery. A copy
//! split over one key path of consecutive array elements (content items,
//! labelled parts) is text its caller received as one run, though the walk
//! interleaves the elements' other fields between the pieces. No list of
//! metadata keys: the rule is structural.

use std::collections::{BTreeSet, HashMap};

use serde_json::Value;

/// The pieces of each per-key-path run of `value`, borrowed from it. For
/// every array in `value`, in the order a delivery walk reaches it (skipping
/// a top-level `_context_integrity`), and every object-only key path under
/// its elements (sorted on the key sequence), a run is at least two
/// consecutive elements whose value at that path is a string; its join is
/// the pieces run together. A missing or non-string value ends a run. The
/// empty path (an array of strings) is left to the all-values form, and a
/// nested array is its own array, never joined across instances.
pub(in super::super) fn key_path_runs(value: &Value) -> Vec<Vec<&str>> {
    let mut arrays = Vec::new();
    match value {
        Value::Object(map) => map
            .iter()
            .filter(|(k, _)| k.as_str() != "_context_integrity")
            .for_each(|(_, v)| collect_arrays(v, &mut arrays)),
        _ => collect_arrays(value, &mut arrays),
    }
    let mut runs = Vec::new();
    for items in arrays {
        let mut paths = BTreeSet::new();
        for item in items {
            object_paths(item, &mut Vec::new(), &mut paths);
        }
        for path in &paths {
            let mut run: Vec<&str> = Vec::new();
            for item in items.iter().map(Some).chain([None]) {
                if let Some(piece) = item.and_then(|i| string_at(i, path)) {
                    run.push(piece);
                    continue;
                }
                if run.len() >= 2 {
                    runs.push(std::mem::take(&mut run));
                }
                run.clear();
            }
        }
    }
    runs
}

/// Each run's join: its pieces run together, in run order.
pub(in super::super) fn key_path_joins(value: &Value) -> Vec<String> {
    key_path_runs(value)
        .iter()
        .map(|run| run.concat())
        .collect()
}

/// Each run of `value` as indices into `leaves`, the value leaves
/// [`super::delivery_parts`] read from the same `value` (its first `values`).
/// A piece is found by identity, not by text, so two equal strings are never
/// confused; a run with a piece the walk did not read is left out. Empty
/// strings may share an address; an empty piece adds no text either way.
pub(in super::super) fn key_path_run_indices(
    value: &Value,
    leaves: &[&str],
    values: usize,
) -> Vec<Box<[u32]>> {
    let at: HashMap<*const u8, u32> = leaves[..values.min(leaves.len())]
        .iter()
        .enumerate()
        .filter_map(|(i, leaf)| Some((leaf.as_ptr(), u32::try_from(i).ok()?)))
        .collect();
    key_path_runs(value)
        .iter()
        .filter_map(|run| {
            run.iter()
                .map(|piece| at.get(&piece.as_ptr()).copied())
                .collect()
        })
        .collect()
}

/// Every array in `value`, a parent before the arrays inside it.
fn collect_arrays<'v>(value: &'v Value, out: &mut Vec<&'v [Value]>) {
    match value {
        Value::Array(items) => {
            out.push(items);
            for v in items {
                collect_arrays(v, out);
            }
        }
        Value::Object(map) => map.values().for_each(|v| collect_arrays(v, out)),
        _ => {}
    }
}

/// The key paths from `value` to its string leaves through objects only.
fn object_paths<'v>(value: &'v Value, at: &mut Vec<&'v str>, out: &mut BTreeSet<Vec<&'v str>>) {
    let Value::Object(map) = value else { return };
    for (key, child) in map {
        at.push(key);
        match child {
            Value::String(_) => {
                out.insert(at.clone());
            }
            Value::Object(_) => object_paths(child, at, out),
            _ => {}
        }
        at.pop();
    }
}

/// The string at `path` under `value`, through objects only.
fn string_at<'v>(value: &'v Value, path: &[&str]) -> Option<&'v str> {
    path.iter()
        .try_fold(value, |v, key| v.as_object()?.get(*key))
        .and_then(Value::as_str)
}

#[cfg(test)]
#[path = "collusion_key_path_tests.rs"]
mod tests;
