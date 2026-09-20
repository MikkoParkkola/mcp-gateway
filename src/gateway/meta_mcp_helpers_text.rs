// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use crate::ranking::{expand_abbreviations, expand_synonyms};

/// Return `true` if `word`, any of its synonyms, or any expansion of it as a
/// supported abbreviation appears as a substring of `text`.
///
/// Abbreviations are consulted last, so this only ever admits more than before:
/// nothing that matched already stops matching.
pub(super) fn word_matches_text(word: &str, text: &str) -> bool {
    if text.contains(word) {
        return true;
    }
    if expand_synonyms(word)
        .iter()
        .any(|syn| *syn != word && text.contains(*syn))
    {
        return true;
    }
    expand_abbreviations(word)
        .iter()
        .any(|full| *full != word && text.contains(*full))
}

/// The first `chars` characters of `word`, or `None` when `word` is shorter.
///
/// Byte slicing panics when the index falls inside a multi-byte character, so
/// a prefix rule stated in characters has to be cut on character boundaries.
/// For ASCII input the result is the same slice the byte cut produced.
pub(super) fn char_prefix(word: &str, chars: usize) -> Option<&str> {
    let end = word
        .char_indices()
        .nth(chars)
        .map_or(word.len(), |(at, _)| at);
    (word[..end].chars().count() == chars).then_some(&word[..end])
}
