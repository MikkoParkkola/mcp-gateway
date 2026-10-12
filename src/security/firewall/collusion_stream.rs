// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8066` 2b D2: the sampled k-gram hashes of a text, computed as a
//! stream. `normalized()` and `kgram_hashes()` build several answer-sized
//! copies (the visible text, its NFC form, a word vector, the joined string,
//! a char-boundary vector and a hash vector); this stream holds one 48-char
//! window and a small compacted buffer, so a view's cost is its own entries.
//! Its output equals `fingerprints(text)` as a set (pinned by a row at both
//! sampling rates).

use std::collections::VecDeque;
use std::hash::BuildHasher;

use icu_normalizer::ComposingNormalizerBorrowed;

use super::{CollusionDetector, K, key};

/// Bytes of consumed window text kept before the buffer is compacted.
const COMPACT_AT: usize = 4096;

impl CollusionDetector {
    /// The sampled k-gram hashes of the text `chars` spells, in position
    /// order (repeats included), exactly as `fingerprints` would sample the
    /// same text, without materializing it.
    pub(crate) fn sampled_kgram_stream<'a, I>(&'a self, chars: I) -> impl Iterator<Item = u64> + 'a
    where
        I: Iterator<Item = char> + 'a,
    {
        let visible = chars.filter(|&c| !crate::security::sanitize::is_unsafe_control(c));
        let nfc = ComposingNormalizerBorrowed::new_nfc().normalize_iter(visible);
        let mut collapsed = Collapse {
            inner: nfc,
            pending: false,
            started: false,
            held: None,
        };
        let mut window = Window::default();
        let rate = self.sample;
        std::iter::from_fn(move || {
            for c in collapsed.by_ref() {
                if let Some(hash) = window.push(c)
                    && hash.is_multiple_of(rate)
                {
                    return Some(hash);
                }
            }
            None
        })
    }
}

/// Whitespace collapsed as `split_whitespace().join(" ")` does: runs become
/// one space, emitted only before the next visible char, so leading and
/// trailing whitespace vanish.
struct Collapse<I> {
    inner: I,
    pending: bool,
    started: bool,
    held: Option<char>,
}

impl<I: Iterator<Item = char>> Iterator for Collapse<I> {
    type Item = char;

    fn next(&mut self) -> Option<char> {
        if let Some(c) = self.held.take() {
            return Some(c);
        }
        loop {
            let c = self.inner.next()?;
            if c.is_whitespace() {
                self.pending |= self.started;
                continue;
            }
            self.started = true;
            if self.pending {
                self.pending = false;
                self.held = Some(c);
                return Some(' ');
            }
            return Some(c);
        }
    }
}

/// The last K chars of the normalized stream, as contiguous text so each
/// window hashes the same bytes `kgram_hashes` hashes.
#[derive(Default)]
struct Window {
    buf: String,
    starts: VecDeque<usize>,
}

impl Window {
    /// Push `c`; once K chars are held, the hash of the current window.
    fn push(&mut self, c: char) -> Option<u64> {
        self.starts.push_back(self.buf.len());
        self.buf.push(c);
        if self.starts.len() > K {
            self.starts.pop_front();
        }
        if self.starts.len() < K {
            return None;
        }
        let start = self.starts[0];
        let hash = key().hash_one(&self.buf[start..]);
        if start > COMPACT_AT {
            self.buf.drain(..start);
            for s in &mut self.starts {
                *s -= start;
            }
        }
        Some(hash)
    }
}
