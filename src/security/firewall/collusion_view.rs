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

/// Bytes reserved per char of the longest combining run: the NFC iterator
/// buffers one combining sequence (a char and its class) at a time.
const COMBINING_BYTES_PER_CHAR: usize = 8;

/// What the preflight measured of an answer it admits.
pub(crate) struct Measured {
    /// Every key and every value.
    pub(crate) nodes: usize,
    /// The longest run of chars with a nonzero canonical combining class.
    pub(crate) combining: usize,
}

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
    /// Held for its `Drop`: releases the view's `VIEW_BYTES` charge.
    #[cfg_attr(not(test), expect(dead_code, reason = "held for its Drop"))]
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
    #[cfg(test)]
    pub(crate) fn charge_bytes(&self) -> usize {
        self.charge.bytes()
    }
}

/// One container being walked by [`preflight`]: its remaining children.
enum Frame<'a> {
    Array(std::slice::Iter<'a, Value>),
    Object(serde_json::map::Iter<'a>),
}

/// The longest run of combining marks normalization can see (D2): within one
/// string, or across strings joined in any order (the run-together forms),
/// characters input sanitization strips neither counting nor breaking a run.
#[derive(Default)]
struct Combining {
    /// The longest run inside one string.
    inner: usize,
    /// Every string's leading plus trailing run: a run across strings is at
    /// most a sum of these.
    edges: usize,
}

impl Combining {
    fn add(
        &mut self,
        ccc: &icu_normalizer::properties::CanonicalCombiningClassMapBorrowed<'_>,
        s: &str,
    ) {
        let kept = |c: &char| !crate::security::sanitize::is_unsafe_control(*c);
        let mark = |c: char| ccc.get_u8(c) != 0;
        let leading = s.chars().filter(kept).take_while(|&c| mark(c)).count();
        let trailing = s
            .chars()
            .rev()
            .filter(kept)
            .take_while(|&c| mark(c))
            .count();
        let mut run = 0usize;
        for c in s.chars().filter(kept) {
            run = if mark(c) { run + 1 } else { 0 };
            self.inner = self.inner.max(run);
        }
        self.edges = self.edges.saturating_add(leading + trailing);
    }

    /// Chars the normalizer may buffer at once: the longest run, doubled (a
    /// mark can decompose into two), plus a starter's own decomposition.
    fn bound(&self) -> usize {
        self.inner
            .max(self.edges)
            .saturating_mul(2)
            .saturating_add(4)
    }
}

/// The preflight (D2): text plus a segment per leaf, nodes (every key and
/// every value) and depth, each against its cap. Iterative over one frame
/// per open container, so its stack is bounded by the depth cap whatever
/// the answer's width, and deep input cannot overflow.
fn preflight(detector: &CollusionDetector, answer: &Value) -> Result<Measured, Unreadable> {
    let text_cap = detector.views.answer_text_cap.load(Ordering::Relaxed);
    let per_leaf = std::mem::size_of::<super::Segment>();
    let node_cap = text_cap / 16;
    let (mut text, mut nodes) = (0usize, 0usize);
    let mut combining = Combining::default();
    let ccc = icu_normalizer::properties::CanonicalCombiningClassMapBorrowed::new();
    let mut stack: Vec<Frame<'_>> = Vec::with_capacity(MAX_ANSWER_DEPTH + 1);
    let mut next = Some(answer);
    loop {
        if let Some(value) = next.take() {
            nodes += 1;
            // A value's depth is the containers open above it.
            if stack.len() > MAX_ANSWER_DEPTH || nodes > node_cap {
                return Err(Unreadable::Shape);
            }
            match value {
                Value::String(s) => {
                    text += s.len() + per_leaf;
                    combining.add(&ccc, s);
                }
                Value::Array(items) => stack.push(Frame::Array(items.iter())),
                Value::Object(map) => stack.push(Frame::Object(map.iter())),
                _ => {}
            }
            if text > text_cap {
                return Err(Unreadable::Shape);
            }
        }
        let Some(frame) = stack.last_mut() else {
            break;
        };
        match frame {
            Frame::Array(items) => next = items.next(),
            Frame::Object(entries) => {
                if let Some((k, v)) = entries.next() {
                    nodes += 1;
                    text += k.len() + per_leaf;
                    combining.add(&ccc, k);
                    next = Some(v);
                }
            }
        }
        if next.is_none() {
            stack.pop();
        }
    }
    Ok(Measured {
        nodes,
        combining: combining.bound(),
    })
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

/// The preflight, then the walks' charge (D2/D8): the reference lists every
/// walk of `answer` builds (the gate's leaf reading, the view's forms, the
/// label walk and the seam pass) and the normalizer's combining buffer,
/// reserved from `VIEW_BYTES` before any walk allocates.
pub(crate) fn reserve_walk(
    detector: &CollusionDetector,
    answer: &Value,
) -> Result<WalkCharge, Unreadable> {
    let measured = preflight(detector, answer)?;
    let refs = measured.nodes * REF_BYTES_PER_NODE + measured.combining * COMBINING_BYTES_PER_CHAR;
    let charge = detector
        .views
        .budget
        .reserve(refs)
        .ok_or(Unreadable::NoRoom)?;
    Ok(WalkCharge { charge, refs })
}

/// The walks' reservation, carried into the view, which holds it for as
/// long as the answer is judged (retention, labels, seams).
pub(crate) struct WalkCharge {
    charge: ViewCharge,
    refs: usize,
}

/// Build `answer`'s view (D1/D2) within its reserved walk charge, or say
/// why it cannot be read (D6). `probe` records (reserved, live) bytes at the
/// first reservation, at every growth and at compaction.
pub(crate) fn build_with(
    detector: &CollusionDetector,
    answer: &Value,
    walk: WalkCharge,
    probe: Option<&mut Vec<(usize, usize)>>,
) -> Result<AnswerView, Unreadable> {
    let WalkCharge { charge, refs } = walk;
    let mut entries = Entries {
        vec: Vec::new(),
        charge,
        refs,
        probe,
    };
    entries.note(0);
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
    // The walk charge stays: the answer's later walks (labels, seams) run
    // while the view lives.
    let held = entries.refs + boxed.len() * 8;
    let _ = entries.charge.resize(held);
    entries.note(held);
    Ok(AnswerView {
        entries: boxed,
        charge: entries.charge,
    })
}

/// What a retention reads the answer through: the leaf path's k-gram set, or
/// a view (D1). Every lookup retention makes is a sampled fingerprint (D8).
#[derive(Clone, Copy)]
pub(crate) enum Found<'a> {
    Set(&'a std::collections::HashSet<u64>),
    View(&'a AnswerView),
}

impl Found<'_> {
    pub(crate) fn contains(&self, hash: u64) -> bool {
        match self {
            Found::Set(set) => set.contains(&hash),
            Found::View(view) => view.contains(hash),
        }
    }

    /// Every entry; for a view, already sampled.
    pub(crate) fn for_each(&self, mut f: impl FnMut(u64)) {
        match self {
            Found::Set(set) => set.iter().copied().for_each(&mut f),
            Found::View(view) => view.entries().iter().copied().for_each(&mut f),
        }
    }

    /// Whether every entry is already a sampled fingerprint.
    pub(crate) fn presampled(&self) -> bool {
        matches!(self, Found::View(_))
    }
}
