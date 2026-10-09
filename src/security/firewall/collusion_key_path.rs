// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8209` (design §14.1 K1): the per-key-path joins of a delivery. A copy
//! split over one key path of consecutive array elements (content items,
//! labelled parts) is text its caller received as one run, though the walk
//! interleaves the elements' other fields between the pieces. No list of
//! metadata keys: the rule is structural.

use std::collections::{BTreeMap, HashMap};

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
        // One pass over the elements: each path's pieces with their element
        // index, so a sparse array costs its leaves, not paths x elements.
        let mut by_path: BTreeMap<Vec<&str>, Vec<(usize, &str)>> = BTreeMap::new();
        for (i, item) in items.iter().enumerate() {
            object_strings(item, &mut Vec::new(), &mut |path, piece| {
                by_path.entry(path.to_vec()).or_default().push((i, piece));
            });
        }
        for pieces in by_path.values() {
            // A run ends where the next element lacks a string at this path.
            let mut run: Vec<&str> = Vec::new();
            let mut last: Option<usize> = None;
            for &(i, piece) in pieces {
                if last.is_some_and(|l| l + 1 != i) {
                    if run.len() >= 2 {
                        runs.push(std::mem::take(&mut run));
                    }
                    run.clear();
                }
                run.push(piece);
                last = Some(i);
            }
            if run.len() >= 2 {
                runs.push(run);
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

/// Object entries the walk has visited on this thread (tests only): the work
/// a row bounds by the leaf count, so a quadratic walk fails it.
#[cfg(test)]
thread_local! {
    pub(super) static VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Count one object entry visited (tests only; nothing in production).
fn visit() {
    #[cfg(test)]
    VISITS.with(|v| v.set(v.get() + 1));
}

/// Each string leaf of `value` reached through objects only, with its key
/// path; a leaf inside a nested array is that array's, not this element's.
fn object_strings<'v>(
    value: &'v Value,
    at: &mut Vec<&'v str>,
    out: &mut dyn FnMut(&[&'v str], &'v str),
) {
    let Value::Object(map) = value else { return };
    for (key, child) in map {
        visit();
        at.push(key);
        match child {
            Value::String(piece) => out(at, piece),
            Value::Object(_) => object_strings(child, at, out),
            _ => {}
        }
        at.pop();
    }
}

#[cfg(test)]
#[path = "collusion_key_path_tests.rs"]
mod tests;
