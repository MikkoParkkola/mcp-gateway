// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The composite event id: `b<boot>.s<gen>.r<gen>.q<gen>.i<N>-<hash>.g<M>-<hash>`.
//!
//! Every part is optional and printed in that fixed order. An id names what one
//! connection has delivered, so a frame changes only its own part.

/// One log's position: the counter and the 16-hex hash of its last row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LogPart {
    pub(super) counter: u64,
    pub(super) hash16: String,
}

/// Which log a row belongs to: the export source enum already names both.
pub(super) use crate::control_plane::export::ExportSource as LogName;

/// A position in both logs. Either half may be absent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct LogCursor {
    pub(super) inv: Option<LogPart>,
    pub(super) gov: Option<LogPart>,
}

/// The id could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct IdError;

/// What a connection has delivered, as one id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct StreamId {
    pub(super) boot: Option<u64>,
    pub(super) status: Option<u64>,
    pub(super) reload: Option<u64>,
    pub(super) queue: Option<u64>,
    pub(super) cursor: LogCursor,
}

impl StreamId {
    /// Read an id; any malformed or out-of-order part is an error.
    pub(super) fn parse(text: &str) -> Result<Self, IdError> {
        let mut id = Self::default();
        if text.is_empty() {
            return Ok(id);
        }
        let mut last = 0usize;
        for token in text.split('.') {
            let mut chars = token.chars();
            let tag = chars.next().ok_or(IdError)?;
            let rest = chars.as_str();
            let order = "bsrqig".find(tag).ok_or(IdError)? + 1;
            if order <= last {
                return Err(IdError);
            }
            last = order;
            match tag {
                'b' => id.boot = Some(parse_boot(rest)?),
                's' => id.status = Some(parse_num(rest)?),
                'r' => id.reload = Some(parse_num(rest)?),
                'q' => id.queue = Some(parse_num(rest)?),
                'i' => id.cursor.inv = Some(parse_log(rest)?),
                _ => id.cursor.gov = Some(parse_log(rest)?),
            }
        }
        Ok(id)
    }

    /// Print the id; `parse(render(x)) == x`.
    pub(super) fn render(&self) -> String {
        let mut parts = Vec::new();
        parts.extend(self.boot.map(|b| format!("b{b:016x}")));
        parts.extend(self.status.map(|n| format!("s{n}")));
        parts.extend(self.reload.map(|n| format!("r{n}")));
        parts.extend(self.queue.map(|n| format!("q{n}")));
        parts.extend(
            self.cursor
                .inv
                .as_ref()
                .map(|p| format!("i{}-{}", p.counter, p.hash16)),
        );
        parts.extend(
            self.cursor
                .gov
                .as_ref()
                .map(|p| format!("g{}-{}", p.counter, p.hash16)),
        );
        parts.join(".")
    }
}

fn parse_num(text: &str) -> Result<u64, IdError> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(IdError);
    }
    text.parse().map_err(|_| IdError)
}

fn is_hash(text: &str) -> bool {
    text.len() == 16 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn parse_boot(text: &str) -> Result<u64, IdError> {
    if !is_hash(text) {
        return Err(IdError);
    }
    u64::from_str_radix(text, 16).map_err(|_| IdError)
}

fn parse_log(text: &str) -> Result<LogPart, IdError> {
    let (n, hash) = text.split_once('-').ok_or(IdError)?;
    if !is_hash(hash) {
        return Err(IdError);
    }
    Ok(LogPart {
        counter: parse_num(n)?,
        hash16: hash.to_owned(),
    })
}
