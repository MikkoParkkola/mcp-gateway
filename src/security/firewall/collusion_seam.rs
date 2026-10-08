// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8113`: the fingerprints of a plan answer that span text of two or
//! more plan steps, each with every step whose text it touches.
//!
//! One pass per form over the answer's value leaves in order: newline-joined
//! (as a delivery walk joins them) and run together (as egress reads
//! forwarded values). Each char carries the step that produced it, or none
//! (text the engine wrote, or no step's unchanged text). A k-gram whose chars
//! come from at least two steps is a seam k-gram; unowned chars inside it are
//! text the caller received in between and never contribute.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::hash::BuildHasher;

use icu_normalizer::ComposingNormalizerBorrowed;

use super::{CollusionDetector, K, key, winnow};

/// A seam fingerprint and the steps whose text it touches anywhere in the
/// answer, ascending.
pub(crate) type SeamFingerprint = (u64, Vec<u32>);

impl CollusionDetector {
    /// The seam fingerprints of `parts`, the answer's value leaves in order,
    /// each with the step that produced it. Every occurrence of a fingerprint
    /// adds its steps, so each occurrence's limits apply to it together.
    ///
    /// Cost: each form is normalized twice (once tagged, once as
    /// [`Self::kgram_hashes`] reads it, which the tagged result must equal),
    /// and each k-gram reads the at most `K` steps in its window: O(L * K)
    /// time, O(L) memory, for L chars of answer.
    pub(crate) fn seam_fingerprints(&self, parts: &[(&str, Option<u32>)]) -> Vec<SeamFingerprint> {
        let mut steps: HashMap<u64, BTreeSet<u32>> = HashMap::new();
        for separator in ["\n", ""] {
            if separator.is_empty() && parts.len() < 2 {
                continue;
            }
            for (fp, owners) in self.form_seams(parts, separator) {
                steps.entry(fp).or_default().extend(owners);
            }
        }
        let mut out: Vec<SeamFingerprint> = steps
            .into_iter()
            .map(|(fp, owners)| (fp, owners.into_iter().collect()))
            .collect();
        out.sort_unstable();
        out
    }

    /// One form's seam fingerprints, each with the steps of every occurrence.
    /// Two slides of the window: the first finds the seam k-grams and the
    /// winnowed fingerprints among them, the second collects steps only for
    /// those, so an answer with few seams allocates for few.
    fn form_seams(
        &self,
        parts: &[(&str, Option<u32>)],
        separator: &str,
    ) -> Vec<(u64, BTreeSet<u32>)> {
        let Some((norm, tags)) = self.tagged_form(parts, separator) else {
            return Vec::new();
        };
        let chars = tags.len();
        if chars < K {
            return Vec::new();
        }
        let bounds: Vec<usize> = norm
            .char_indices()
            .map(|(i, _)| i)
            .chain(std::iter::once(norm.len()))
            .collect();
        let mut hashes = Vec::with_capacity(chars - K + 1);
        let mut seam: HashSet<u64> = HashSet::new();
        slide(&tags, |i, window| {
            let hash = key().hash_one(&norm[bounds[i]..bounds[i + K]]);
            hashes.push(hash);
            if window.len() >= 2 {
                seam.insert(hash);
            }
        });
        let selected: HashSet<u64> = winnow(&hashes)
            .into_iter()
            .filter(|fp| seam.contains(fp))
            .collect();
        if selected.is_empty() {
            return Vec::new();
        }
        let mut union: HashMap<u64, BTreeSet<u32>> = HashMap::new();
        slide(&tags, |i, window| {
            if selected.contains(&hashes[i]) {
                union
                    .entry(hashes[i])
                    .or_default()
                    .extend(window.keys().copied());
            }
        });
        union.into_iter().collect()
    }

    /// The form's text normalized as [`Self::kgram_hashes`] normalizes it,
    /// with the step of each char. `None` when normalizing the parts one by
    /// one does not give the text normalized whole (a part that composes
    /// with its neighbour): that form then has no seam, a missed seam at
    /// most, never a fingerprint the egress side cannot compute.
    fn tagged_form(
        &self,
        parts: &[(&str, Option<u32>)],
        separator: &str,
    ) -> Option<(String, Vec<Option<u32>>)> {
        let nfc = ComposingNormalizerBorrowed::new_nfc();
        let mut stream: Vec<(char, Option<u32>)> = Vec::new();
        for (i, (text, owner)) in parts.iter().enumerate() {
            if i > 0 {
                stream.extend(separator.chars().map(|c| (c, None)));
            }
            let visible: String = text
                .chars()
                .filter(|&c| !crate::security::sanitize::is_unsafe_control(c))
                .collect();
            stream.extend(nfc.normalize(&visible).chars().map(|c| (c, *owner)));
        }
        // Whitespace collapsed as `split_whitespace().join(" ")`: trimmed, and
        // each inner run one unowned space.
        let mut norm = String::new();
        let mut tags = Vec::new();
        let mut pending_space = false;
        for (c, owner) in stream {
            if c.is_whitespace() {
                pending_space = !norm.is_empty();
                continue;
            }
            if pending_space {
                norm.push(' ');
                tags.push(None);
                pending_space = false;
            }
            norm.push(c);
            tags.push(owner);
        }
        let joined = parts
            .iter()
            .map(|(text, _)| *text)
            .collect::<Vec<_>>()
            .join(separator);
        (self.normalized(&joined) == norm).then_some((norm, tags))
    }
}

/// Slide a `K`-char window over `tags`, calling `at` with each start and the
/// count of each step's chars inside the window.
fn slide(tags: &[Option<u32>], mut at: impl FnMut(usize, &HashMap<u32, usize>)) {
    let mut window: HashMap<u32, usize> = HashMap::new();
    for owner in tags[..K].iter().flatten() {
        *window.entry(*owner).or_default() += 1;
    }
    for i in 0..=tags.len() - K {
        if i > 0 {
            if let Some(gone) = tags[i - 1]
                && let Some(n) = window.get_mut(&gone)
            {
                *n -= 1;
                if *n == 0 {
                    window.remove(&gone);
                }
            }
            if let Some(came) = tags[i + K - 1] {
                *window.entry(came).or_default() += 1;
            }
        }
        at(i, &window);
    }
}
