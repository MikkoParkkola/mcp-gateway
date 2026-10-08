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
use icu_normalizer::properties::{
    CanonicalCombiningClassMapBorrowed, CanonicalCompositionBorrowed,
    CanonicalDecompositionBorrowed, Decomposed,
};

use super::{CollusionDetector, K, key, winnow};

/// The longest piece of text normalized together, in bytes: past it the
/// stream is cut even inside a composing run.
const MAX_PIECE: usize = 256;

/// A seam fingerprint and the steps whose text it touches anywhere in the
/// answer, ascending.
pub(crate) type SeamFingerprint = (u64, Vec<u32>);

impl CollusionDetector {
    /// The seam fingerprints of `parts`, the answer's value leaves in order,
    /// each with the step that produced it. Every occurrence of a fingerprint
    /// adds its steps, so each occurrence's limits apply to it together.
    ///
    /// Cost: each form is normalized once, part by part, and the window is
    /// slid twice, collecting steps only for winnowed seam fingerprints:
    /// O(L) time and memory for L chars of answer.
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
        let (norm, tags) = self.tagged_form(parts, separator);
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

    /// The form's text normalized as [`Self::kgram_hashes`] normalizes the
    /// whole text, with the step of each char. The stream is cut only before
    /// a starter that cannot compose with the char before it, where NFC
    /// never reaches across, so normalizing each piece gives exactly the
    /// text normalized whole. A piece takes the step of the char it starts
    /// with: a mark of another step composed into it adds no step. A piece
    /// over [`MAX_PIECE`] bytes is cut anyway, costing at most the k-grams
    /// over that cut.
    #[expect(
        clippy::unused_self,
        reason = "normalized as every k-gram the detector reads"
    )]
    fn tagged_form(
        &self,
        parts: &[(&str, Option<u32>)],
        separator: &str,
    ) -> (String, Vec<Option<u32>>) {
        let nfc = ComposingNormalizerBorrowed::new_nfc();
        let ccc = CanonicalCombiningClassMapBorrowed::new();
        let comp = CanonicalCompositionBorrowed::new();
        let dec = CanonicalDecompositionBorrowed::new();
        let len = parts
            .iter()
            .map(|(text, _)| text.len() + separator.len())
            .sum();
        let mut stream: Vec<(char, Option<u32>)> = Vec::with_capacity(len);
        let mut piece = Piece::default();
        let chars = parts.iter().enumerate().flat_map(|(i, (text, step))| {
            let sep = if i > 0 { separator } else { "" };
            sep.chars().map(|c| (c, None)).chain(
                text.chars()
                    .filter(|&c| !crate::security::sanitize::is_unsafe_control(c))
                    .map(move |c| (c, *step)),
            )
        });
        for (c, step) in chars {
            // A piece is cut at its cap whatever comes next, so a run of
            // marks never reaches the normalizer longer than the cap.
            if piece.text.len() >= MAX_PIECE {
                piece.flush(&nfc, &mut stream);
            }
            // NFC never reaches back across a char whose full decomposition
            // opens with a starter that does not compose with the char
            // before it.
            if !piece.text.is_empty() && ccc.get_u8(leading(&dec, c)) == 0 {
                let joins = !c.is_ascii()
                    && piece
                        .last_normalized(&nfc)
                        .is_some_and(|last| comp.compose(last, c).is_some());
                if !joins {
                    piece.flush(&nfc, &mut stream);
                }
            }
            piece.push(c, step);
        }
        piece.flush(&nfc, &mut stream);
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
        (norm, tags)
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

/// The first char of `c`'s full canonical decomposition.
fn leading(dec: &CanonicalDecompositionBorrowed<'_>, mut c: char) -> char {
    loop {
        match dec.decompose(c) {
            Decomposed::Default => return c,
            Decomposed::Singleton(s) => c = s,
            Decomposed::Expansion(first, _) => c = first,
        }
    }
}

/// Text normalized together, with the step of each of its chars.
#[derive(Default)]
struct Piece {
    text: String,
    steps: Vec<(char, Option<u32>)>,
}

impl Piece {
    fn push(&mut self, c: char, step: Option<u32>) {
        self.text.push(c);
        self.steps.push((c, step));
    }

    /// The last char of the piece normalized.
    fn last_normalized(&self, nfc: &ComposingNormalizerBorrowed<'_>) -> Option<char> {
        if self.text.is_ascii() {
            self.text.chars().next_back()
        } else {
            nfc.normalize(&self.text).chars().next_back()
        }
    }

    /// Append the piece normalized to `stream` and empty it. A char that
    /// comes through normalization unchanged keeps its own step; a char
    /// composition made takes the step of the char the piece opens with.
    fn flush(
        &mut self,
        nfc: &ComposingNormalizerBorrowed<'_>,
        stream: &mut Vec<(char, Option<u32>)>,
    ) {
        let first = self.steps.first().and_then(|(_, step)| *step);
        if self.text.is_ascii() || self.steps.iter().all(|(_, s)| *s == first) {
            stream.extend(nfc.normalize(&self.text).chars().map(|n| (n, first)));
        } else {
            let mut left = std::mem::take(&mut self.steps);
            for n in nfc.normalize(&self.text).chars() {
                let step = left
                    .iter()
                    .position(|(c, _)| *c == n)
                    .map_or(first, |i| left.remove(i).1);
                stream.push((n, step));
            }
        }
        self.text.clear();
        self.steps.clear();
    }
}
