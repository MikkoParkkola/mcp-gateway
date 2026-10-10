// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8290`: egress windows that are glue, not evidence.
//!
//! A window made of one long leaf's text plus a few chars from outside it
//! (the separator the egress text puts between parts, or the edge char of
//! a neighbouring part) matches any copy where the same text sits beside any
//! other value. Such a window is dropped when the leaf is at least
//! [`DOMINANT`] normalised chars long. That leaf keeps all its own interior
//! windows (K + 1 or more), so a relay through it keeps its evidence, while
//! next to a shorter leaf nothing is dropped and the evidence is exactly
//! as before. The windows themselves are always those of the whole-text
//! normalisation; owners only decide which to drop, and when the per-owner
//! reconstruction differs from the whole text nothing is dropped. So the
//! kept windows are a subset of the old ones: no holder gains a new match.

use std::collections::HashMap;
use std::hash::BuildHasher;

use icu_normalizer::ComposingNormalizerBorrowed;

use super::{CollusionDetector, K, key, sample};

/// Normalised chars a window may take from outside its dominant leaf and
/// still be glue. Every observed case is one char (a separator, or a
/// neighbour's edge char); 4 covers coincidental runs such as ": " or "-- ".
/// It is a constant, never a setting.
const GLUE: usize = 4;

/// A leaf this many normalised chars long or longer keeps at least K + 1
/// interior windows, so dropping the glue around it never leaves a relay
/// through it without evidence.
const DOMINANT: usize = 2 * K;

impl CollusionDetector {
    /// The fingerprints of an egress text made of `parts`, each with its
    /// owner (a leaf or key index; `None` for the separator), less the glue
    /// windows around long leaves. Sampled as
    /// [`Self::fingerprints`] samples.
    pub(crate) fn egress_fingerprints(&self, parts: &[(&str, Option<u32>)]) -> Vec<u64> {
        let text: String = parts.iter().map(|(t, _)| *t).collect();
        let norm = self.normalized(&text);
        let bounds: Vec<usize> = norm
            .char_indices()
            .map(|(i, _)| i)
            .chain(std::iter::once(norm.len()))
            .collect();
        let chars = bounds.len() - 1;
        if chars < K {
            return Vec::new();
        }
        let glue = glue_windows(&norm, parts, |owner_text| {
            self.normalized(owner_text).chars().count()
        });
        let hashes: Vec<u64> = (0..=chars - K)
            .filter(|i| !glue.as_ref().is_some_and(|g| g[*i]))
            .map(|i| key().hash_one(&norm[bounds[i]..bounds[i + K]]))
            .collect();
        sample(&hashes, self.sample)
    }
}

/// For each window of `norm`, whether it is glue. `None` when the owners
/// cannot be lined up with `norm` (composition across an owner boundary):
/// then nothing is dropped.
fn glue_windows(
    norm: &str,
    parts: &[(&str, Option<u32>)],
    normalized_len: impl Fn(&str) -> usize,
) -> Option<Vec<bool>> {
    let tags = tagged(parts, norm)?;
    let mut long: HashMap<u32, bool> = HashMap::new();
    for (text, owner) in parts {
        if let Some(o) = owner {
            let is_long = normalized_len(text) >= DOMINANT;
            long.entry(*o)
                .and_modify(|l| *l |= is_long)
                .or_insert(is_long);
        }
    }
    let windows = tags.len().checked_sub(K)? + 1;
    let mut counts: HashMap<u32, usize> = HashMap::new();
    for t in tags.iter().take(K).flatten() {
        *counts.entry(*t).or_default() += 1;
    }
    let mut glue = Vec::with_capacity(windows);
    for i in 0..windows {
        if i > 0 {
            if let Some(o) = tags[i - 1] {
                *counts.entry(o).or_default() -= 1;
            }
            if let Some(o) = tags[i + K - 1] {
                *counts.entry(o).or_default() += 1;
            }
        }
        // A dominant owner holds at least K − GLUE of K chars, so it owns at
        // least one of any GLUE + 1 positions: checking those suffices.
        let dominant = (0..=GLUE)
            .filter_map(|d| tags[i + d * (K - 1) / GLUE])
            .find(|o| counts.get(o).is_some_and(|&c| c >= K - GLUE));
        glue.push(dominant.is_some_and(|o| {
            counts.get(&o).is_some_and(|&c| c < K) && long.get(&o).copied().unwrap_or(false)
        }));
    }
    Some(glue)
}

/// A whitespace run being collapsed: none yet, every char of one owner (the
/// separator's being `None`), or chars of several owners.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Run {
    Outside,
    Owned(Option<u32>),
    Mixed,
}

/// The owner of each char of `norm`, rebuilt by normalising each owner's run
/// of `parts` apart and collapsing whitespace as the whole text is: a
/// whitespace run is an owner's when every char in it, and the chars on
/// both sides of it, are that owner's; otherwise unowned. `None` when the rebuilt text differs from `norm`.
fn tagged(parts: &[(&str, Option<u32>)], norm: &str) -> Option<Vec<Option<u32>>> {
    let nfc = ComposingNormalizerBorrowed::new_nfc();
    let mut stream: Vec<(char, Option<u32>)> = Vec::new();
    for (text, owner) in parts {
        let visible: String = text
            .chars()
            .filter(|&c| !crate::security::sanitize::is_unsafe_control(c))
            .collect();
        stream.extend(nfc.normalize(&visible).chars().map(|c| (c, *owner)));
    }
    let mut rebuilt = String::with_capacity(norm.len());
    let mut tags = Vec::with_capacity(norm.len());
    let mut run = Run::Outside;
    for (c, owner) in stream {
        if c.is_whitespace() {
            run = match run {
                Run::Outside => Run::Owned(owner),
                Run::Owned(o) if o == owner => Run::Owned(o),
                Run::Owned(_) | Run::Mixed => Run::Mixed,
            };
            continue;
        }
        let space = std::mem::replace(&mut run, Run::Outside);
        if space != Run::Outside
            && let Some(&before) = tags.last()
        {
            // An owner's normalisation alone trims its edge whitespace, so a
            // space is its owner's only with that owner's text on both sides.
            let own = match space {
                Run::Owned(Some(o)) if before == Some(o) && owner == Some(o) => Some(o),
                _ => None,
            };
            rebuilt.push(' ');
            tags.push(own);
        }
        rebuilt.push(c);
        tags.push(owner);
    }
    (rebuilt == norm).then_some(tags)
}

/// The parts a backend receives in `value`, each with its owner: every
/// string leaf newline-joined (content split over short fields at word
/// boundaries still matches), the leaves once more run together, since a
/// copy split mid-word over fields shorter than a fingerprint is still one
/// the backend can join, then every object key, since a key reaches the
/// backend like a value. Separators are unowned parts; the run-together
/// leaves keep their own leaf's owner. Joined, the parts are [`egress_text`].
pub(crate) fn egress_parts(value: &serde_json::Value) -> Vec<(&str, Option<u32>)> {
    fn visit<'v>(value: &'v serde_json::Value, leaves: &mut Vec<&'v str>, keys: &mut Vec<&'v str>) {
        match value {
            serde_json::Value::String(s) => leaves.push(s),
            serde_json::Value::Array(items) => items.iter().for_each(|v| visit(v, leaves, keys)),
            serde_json::Value::Object(map) => map.iter().for_each(|(k, v)| {
                keys.push(k);
                visit(v, leaves, keys);
            }),
            _ => {}
        }
    }
    let (mut leaves, mut keys): (Vec<&str>, Vec<&str>) = (Vec::new(), Vec::new());
    visit(value, &mut leaves, &mut keys);
    let owner = |i: usize| u32::try_from(i).ok();
    let mut slots: Vec<Vec<(&str, Option<u32>)>> = leaves
        .iter()
        .enumerate()
        .map(|(i, l)| vec![(*l, owner(i))])
        .collect();
    if leaves.len() > 1 {
        slots.push(
            leaves
                .iter()
                .enumerate()
                .map(|(i, l)| (*l, owner(i)))
                .collect(),
        );
    }
    slots.extend(
        keys.iter()
            .enumerate()
            .map(|(j, k)| vec![(*k, owner(leaves.len() + j))]),
    );
    let mut parts = Vec::new();
    for (n, slot) in slots.into_iter().enumerate() {
        if n > 0 {
            parts.push(("\n", None));
        }
        parts.extend(slot);
    }
    parts
}

/// The text a backend receives in `value`: [`egress_parts`] joined. What a
/// caller is delivered is read by `delivery_parts` (tests only).
#[cfg(test)]
pub(crate) fn egress_text(value: &serde_json::Value) -> String {
    egress_parts(value).iter().map(|(t, _)| *t).collect()
}
