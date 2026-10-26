// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The writer every redaction insertion goes through (MIK-8794): the marker
//! and a renamed key's collision suffix, each behind the barrier space where
//! a second pass would otherwise run a connection string through it.

use super::REDACTED;

/// The suffix a colliding redacted key takes: ` #n` where `spaced` (the
/// barrier holds where the key ends), else `#n`. One helper forms both the
/// name a key reserves and the text written for it, so they cannot differ.
pub(super) fn collision_suffix(n: usize, spaced: bool) -> String {
    if spaced {
        format!(" #{n}")
    } else {
        format!("#{n}")
    }
}

/// The connection-string rule's schemes, each with its `://`, as
/// `connection_prefix!` spells them; the barrier tests pin the two together.
pub(super) const SCHEMES: [&[u8]; 4] = [b"postgres://", b"mysql://", b"mongodb://", b"redis://"];

/// The longest scheme with its `://`: how much of a run the matcher keeps.
pub(super) const LONGEST: usize = 11;

/// Redacted text being written, and what a second pass will read where it
/// ends (MIK-8794). Only the connection-string rule's class accepts the
/// marker's characters, so a marker or a collision suffix written straight
/// after a run of non-whitespace that holds an unreplaced connection-string
/// prefix would let that rule's run grow through it on a second pass, past
/// the floor the first pass did not reach. There, one space goes first.
///
/// The run is tracked by one forward pass over each written byte, with no
/// regex and no rescan: the last [`LONGEST`] characters of the run, folded
/// as the rule's `(?i)` folds them, are enough to see a scheme end.
pub(super) struct Spliced {
    pub(super) out: String,
    /// The current run's last characters, folded: a ring, `head` the next slot.
    tail: [u8; LONGEST],
    head: usize,
    /// How many of `tail` hold characters of the current run.
    len: usize,
    /// Whether the current run holds an unreplaced connection-string prefix.
    prefixed: bool,
}

impl Spliced {
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            out: String::with_capacity(capacity),
            tail: [0; LONGEST],
            head: 0,
            len: 0,
            prefixed: false,
        }
    }

    /// Append `text` as written, tracking the run it ends in.
    ///
    /// Only the run `text` ends in matters, so the last whitespace is found
    /// first and everything before it is skipped. A long run is not walked
    /// byte by byte: its head goes through [`Self::track`] for a scheme that
    /// began in earlier text, each `://` in it is checked on a short window,
    /// and the tail is rebuilt from its last characters. Short runs take
    /// [`Self::track`] whole; both ways reach the same state.
    pub(super) fn push(&mut self, text: &str) {
        self.out.push_str(text);
        let run = match last_white_end(text) {
            Some(end) => {
                self.len = 0;
                self.head = 0;
                self.prefixed = false;
                &text[end..]
            }
            None => text,
        };
        if self.prefixed {
            return;
        }
        if run.len() <= WALKED {
            self.track(run);
            return;
        }
        // A scheme ending here may have begun in earlier text.
        self.track(&run[..run.ceil_char_boundary(WINDOW)]);
        // A scheme wholly inside the run ends in a `://` found here.
        if !self.prefixed {
            self.prefixed = run.match_indices("://").any(|(at, _)| {
                let end = at + 3;
                scheme_ends(&run[run.floor_char_boundary(end.saturating_sub(WINDOW))..end])
            });
        }
        if !self.prefixed {
            self.len = 0;
            self.head = 0;
            self.track(&run[run.floor_char_boundary(run.len().saturating_sub(WINDOW))..]);
        }
    }

    /// Track `text` from the current state, one character at a time.
    fn track(&mut self, text: &str) {
        let bytes = text.as_bytes();
        let mut at = 0;
        while at < bytes.len() {
            let byte = bytes[at];
            let (folded, white, width) = if byte.is_ascii() {
                (
                    byte.to_ascii_lowercase(),
                    byte.is_ascii_whitespace() || byte == 0x0b,
                    1,
                )
            } else {
                let c = text[at..].chars().next().unwrap_or('\u{fffd}');
                // `(?i)` folds U+017F (long s) to `s`; no other non-ASCII
                // character folds to a letter of the four schemes.
                let folded = if c == '\u{17f}' { b's' } else { 0 };
                (folded, c.is_whitespace(), c.len_utf8())
            };
            at += width;
            if white {
                self.len = 0;
                self.prefixed = false;
                continue;
            }
            if self.prefixed {
                continue;
            }
            self.tail[self.head] = folded;
            self.head = (self.head + 1) % LONGEST;
            self.len = (self.len + 1).min(LONGEST);
            // Every scheme ends in `/`, so only a `/` can complete one.
            if folded == b'/' {
                self.prefixed = SCHEMES.iter().any(|scheme| self.ends_with(scheme));
            }
        }
    }

    /// Whether the run's last characters are `scheme`.
    fn ends_with(&self, scheme: &[u8]) -> bool {
        scheme.len() <= self.len
            && scheme
                .iter()
                .rev()
                .enumerate()
                .all(|(back, &want)| self.tail[(self.head + LONGEST - 1 - back) % LONGEST] == want)
    }

    /// Whether an insertion here needs the leading space: the output ends in
    /// a run of non-whitespace holding an unreplaced connection-string prefix.
    pub(super) fn barrier(&self) -> bool {
        self.prefixed
    }

    /// Append the marker, behind the barrier space where one is needed.
    pub(super) fn insert_marker(&mut self) {
        if self.barrier() {
            self.push(" ");
        }
        self.push(REDACTED);
    }
}

/// How many bytes each window the writer reads holds: [`LONGEST`] characters
/// of any width. No byte budget is derived from the schemes' spelling, since
/// a folded scheme can be wider than it looks (`postgres` with both `s` as
/// U+017F takes 13 bytes); a window holds no whitespace, so extra characters
/// in front of a scheme cannot hide it.
const WINDOW: usize = LONGEST * 4;

/// Runs up to this long go through [`Spliced::track`] whole.
const WALKED: usize = 64;

/// Whether `window`, read alone, ends a scheme.
fn scheme_ends(window: &str) -> bool {
    let mut probe = Spliced::with_capacity(0);
    probe.track(window);
    probe.prefixed
}

/// Where the run `text` ends in starts: just past its last whitespace, or
/// `None` when it holds none. Only these lead bytes start a non-ASCII
/// whitespace character, so the rest are skipped without decoding.
fn last_white_end(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut end = bytes.len();
    while let Some(at) = bytes[..end].iter().rposition(|&b| {
        b.is_ascii_whitespace() || b == 0x0b || matches!(b, 0xc2 | 0xe1 | 0xe2 | 0xe3)
    }) {
        if bytes[at].is_ascii() {
            return Some(at + 1);
        }
        let c = text[at..].chars().next().unwrap_or('\u{fffd}');
        if c.is_whitespace() {
            return Some(at + c.len_utf8());
        }
        end = at;
    }
    None
}

/// Whether an insertion after `text`, a whole document, needs the barrier.
pub(super) fn ends_open(text: &str) -> bool {
    let mut out = Spliced::with_capacity(0);
    out.push(text);
    out.barrier()
}
