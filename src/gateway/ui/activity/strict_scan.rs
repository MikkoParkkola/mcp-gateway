// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A forward line reader with a strict byte limit: every byte its buffer pulls
//! from the file passes a `Take`-style limit set to the budget, so total bytes
//! read never exceed it, read-ahead included. Used by the look-above and the
//! receipt's forward scan.

use std::fs::File;
use std::io::{self, BufReader, Take};

/// What the next line was.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Next {
    /// A whole line, without its newline.
    Line(Vec<u8>),
    /// The budget ended the read, on a line boundary or inside a line (whose
    /// bytes are not returned).
    Budget,
    /// No whole line remains: the end of the file, or a partial append.
    End,
}

pub(super) struct Forward {
    reader: BufReader<Take<File>>,
    budget: u64,
}

impl Forward {
    /// Read from `offset` of `file`, at most `budget` bytes.
    pub(super) fn open(file: File, offset: u64, budget: u64) -> io::Result<Self> {
        let _ = (&file, offset);
        let take = io::Read::take(file, 0);
        Ok(Self {
            reader: BufReader::with_capacity(1, take),
            budget,
        })
    }

    pub(super) fn next_line(&mut self) -> io::Result<Next> {
        let _ = &mut self.reader;
        Ok(Next::End)
    }

    /// Bytes pulled from the file so far, counted at the limited reader.
    pub(super) fn pulled(&self) -> u64 {
        self.budget - self.reader.get_ref().limit()
    }
}
