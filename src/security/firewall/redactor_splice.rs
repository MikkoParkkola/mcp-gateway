// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The writer every redaction insertion goes through (MIK-8794): the marker
//! and a renamed key's collision suffix, each behind the barrier space where
//! a second pass would otherwise run a connection string through it.

use regex::Regex;

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

/// How far back from newly written text a connection-string prefix that
/// ends in it can start: `postgres://` is 11 characters, at most 4 bytes
/// each under case folding.
const PREFIX_REACH: usize = 44;

fn connection_prefix() -> &'static Regex {
    static PREFIX: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    PREFIX.get_or_init(|| {
        // invariant: a constant pattern the credential rule set also compiles at startup.
        Regex::new(connection_prefix!()).expect("prefix compiles")
    })
}

/// Redacted text being written, and what a second pass will read where it
/// ends (MIK-8794). Only the connection-string rule's class accepts the
/// marker's characters, so a marker or a collision suffix written straight
/// after a run of non-whitespace that holds an unreplaced connection-string
/// prefix would let that rule's run grow through it on a second pass, past
/// the floor the first pass did not reach. There, one space goes first. The
/// run is tracked as text is written, so a write costs its own length plus
/// [`PREFIX_REACH`], never a rescan of the output.
pub(super) struct Spliced {
    pub(super) out: String,
    /// Where the current run of non-whitespace starts in `out`.
    run: usize,
    /// Whether that run holds an unreplaced connection-string prefix.
    prefixed: bool,
}

impl Spliced {
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            out: String::with_capacity(capacity),
            run: 0,
            prefixed: false,
        }
    }

    /// Append `text` as written, tracking the run it ends in.
    pub(super) fn push(&mut self, text: &str) {
        let old = self.out.len();
        self.out.push_str(text);
        if let Some((at, c)) = text.char_indices().rev().find(|(_, c)| c.is_whitespace()) {
            self.run = old + at + c.len_utf8();
            self.prefixed = false;
        }
        if !self.prefixed {
            let mut from = old.saturating_sub(PREFIX_REACH).max(self.run);
            while !self.out.is_char_boundary(from) {
                from += 1;
            }
            self.prefixed = connection_prefix().is_match(&self.out[from..]);
        }
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

/// Whether an insertion after `text`, a whole document, needs the barrier.
pub(super) fn ends_open(text: &str) -> bool {
    let mut out = Spliced::with_capacity(0);
    out.push(text);
    out.barrier()
}
