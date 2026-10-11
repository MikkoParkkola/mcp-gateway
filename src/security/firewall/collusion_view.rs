// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8066` 2b D1/D2: the bounded sampled view of a plan answer. It holds
//! the answer's sampled k-gram hashes (every leaf, the values newline-joined,
//! the values run together, each key-path join), deduplicated and sorted,
//! and nothing else: no leaf set, no text. Every byte it stores is reserved
//! from `VIEW_BYTES` before it is allocated (D8).

use std::sync::atomic::Ordering;

use serde_json::Value;

use super::super::collusion::CollusionDetector;
use super::super::collusion::budget::{MAX_ANSWER_DEPTH, ViewCharge};
use super::key_path::key_path_runs;
use super::walk::delivery_parts;

/// Bytes reserved per answer node for the walks' reference lists.
const REF_BYTES_PER_NODE: usize = 64;

/// Why an answer could not be read as a view (D6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unreadable {
    /// Past the answer text cap, the node cap or the depth cap.
    Shape,
    /// The view would pass the entry cap A.
    EntryCap,
    /// `VIEW_BYTES` had no room.
    NoRoom,
}

/// A built view: sorted distinct sampled hashes, and the charge for them.
pub(crate) struct AnswerView {
    entries: Box<[u64]>,
    charge: ViewCharge,
}

impl AnswerView {
    /// Whether `hash` is in the view.
    pub(crate) fn contains(&self, hash: u64) -> bool {
        self.entries.binary_search(&hash).is_ok()
    }

    /// The view's sorted entries.
    pub(crate) fn entries(&self) -> &[u64] {
        &self.entries
    }

    /// Bytes this view holds against `VIEW_BYTES`.
    pub(crate) fn charge_bytes(&self) -> usize {
        self.charge.bytes()
    }
}

/// The allocation-free preflight (D2): text plus a segment per leaf, nodes
/// (every key and every value) and depth, each against its cap. Iterative,
/// with a stack bounded by the depth cap, so deep input cannot overflow.
fn preflight(detector: &CollusionDetector, answer: &Value) -> Result<usize, Unreadable> {
    let text_cap = detector.views.answer_text_cap.load(Ordering::Relaxed);
    let per_leaf = std::mem::size_of::<super::Segment>();
    let node_cap = text_cap / 16;
    let (mut text, mut nodes) = (0usize, 0usize);
    let mut stack: Vec<(&Value, usize)> = Vec::with_capacity(MAX_ANSWER_DEPTH + 1);
    stack.push((answer, 0));
    while let Some((value, depth)) = stack.pop() {
        nodes += 1;
        if depth > MAX_ANSWER_DEPTH || nodes > node_cap {
            return Err(Unreadable::Shape);
        }
        match value {
            Value::String(s) => text += s.len() + per_leaf,
            Value::Array(items) => stack.extend(items.iter().map(|v| (v, depth + 1))),
            Value::Object(map) => {
                for (k, v) in map {
                    nodes += 1;
                    text += k.len() + per_leaf;
                    stack.push((v, depth + 1));
                }
            }
            _ => {}
        }
        if text > text_cap {
            return Err(Unreadable::Shape);
        }
    }
    Ok(nodes)
}

/// The growing entry buffer, every capacity change reserved first.
struct Entries<'p> {
    vec: Vec<u64>,
    charge: ViewCharge,
    refs: usize,
    probe: Option<&'p mut Vec<(usize, usize)>>,
}

impl Entries<'_> {
    fn note(&mut self, live: usize) {
        if let Some(p) = self.probe.as_deref_mut() {
            p.push((self.charge.bytes(), live));
        }
    }

    fn push(&mut self, hash: u64) -> Result<(), Unreadable> {
        if self.vec.len() == self.vec.capacity() {
            let old = self.vec.capacity();
            let new = (old * 2).max(1024);
            // Both buffers live during the reallocation.
            if !self.charge.resize(self.refs + (old + new) * 8) {
                return Err(Unreadable::NoRoom);
            }
            self.vec
                .try_reserve_exact(new - self.vec.len())
                .map_err(|_| Unreadable::NoRoom)?;
            self.note((old + self.vec.capacity()) * 8 + self.refs);
            let held = self.refs + self.vec.capacity() * 8;
            if !self.charge.resize(held) {
                return Err(Unreadable::NoRoom);
            }
        }
        self.vec.push(hash);
        Ok(())
    }
}

/// Build `answer`'s view (D1/D2), or say why it cannot be read (D6).
/// `probe` records (reserved, live) bytes at every growth and at compaction.
pub(crate) fn build(
    detector: &CollusionDetector,
    answer: &Value,
    probe: Option<&mut Vec<(usize, usize)>>,
) -> Result<AnswerView, Unreadable> {
    let nodes = preflight(detector, answer)?;
    let refs = nodes * REF_BYTES_PER_NODE;
    let charge = detector
        .views
        .budget
        .reserve(refs)
        .ok_or(Unreadable::NoRoom)?;
    let mut entries = Entries {
        vec: Vec::new(),
        charge,
        refs,
        probe,
    };
    let entry_cap = detector.views.entry_cap.load(Ordering::Relaxed);
    let (all, values_len) = delivery_parts(answer);
    let values = &all[..values_len.min(all.len())];
    let runs = key_path_runs(answer);
    let mut form = |chars: &mut dyn Iterator<Item = char>| -> Result<(), Unreadable> {
        for hash in detector.sampled_kgram_stream(chars) {
            entries.push(hash)?;
        }
        entries.vec.sort_unstable();
        entries.vec.dedup();
        if entries.vec.len() > entry_cap {
            return Err(Unreadable::EntryCap);
        }
        Ok(())
    };
    for leaf in &all {
        form(&mut leaf.chars())?;
    }
    let mut joined = values
        .iter()
        .enumerate()
        .flat_map(|(i, v)| (i > 0).then_some('\n').into_iter().chain(v.chars()));
    form(&mut joined)?;
    if values.len() > 1 {
        form(&mut values.iter().flat_map(|v| v.chars()))?;
    }
    for run in &runs {
        form(&mut run.iter().flat_map(|p| p.chars()))?;
    }
    drop(form);
    drop(runs);
    drop(all);
    // Compaction may reallocate: reserve the replacement while the old
    // buffer is still charged, then release down to the exact size.
    let (len, cap) = (entries.vec.len(), entries.vec.capacity());
    if !entries.charge.resize(entries.refs + (cap + len) * 8) {
        return Err(Unreadable::NoRoom);
    }
    let boxed = std::mem::take(&mut entries.vec).into_boxed_slice();
    entries.refs = 0;
    let _ = entries.charge.resize(boxed.len() * 8);
    entries.note(boxed.len() * 8);
    Ok(AnswerView {
        entries: boxed,
        charge: entries.charge,
    })
}
