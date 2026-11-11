// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The fetch's output (ADR-027 N4): drained to EOF so the pipe never blocks,
//! its last 64 KiB kept, and the last line, which a failing fetch refuses
//! with, stripped of the fetch credential and of any URL userinfo.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the Linux fetch step, a later part, calls these")
)]

use std::io::{self, Read};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::security::sanitize::redact_url_keep_path;
use crate::security::secret_redaction::redact_untruncated;

/// How much of the fetch's output is kept: its tail.
pub(crate) const TAIL_BYTES: usize = 64 * 1024;

/// Read `reader` to EOF, keeping its last [`TAIL_BYTES`]: the tool's final
/// line is the one a failing fetch is explained by. A final line longer than
/// the cap shows nothing: its cut fragment may start inside a credential.
pub(crate) fn read_tail(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut tail = Vec::with_capacity(2 * TAIL_BYTES);
    let mut buf = [0; 8 * 1024];
    let mut drained = false;
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        tail.extend_from_slice(&buf[..n]);
        if tail.len() > TAIL_BYTES {
            tail.drain(..tail.len() - TAIL_BYTES);
            drained = true;
        }
    }
    if drained {
        // Only a newline proves that the next bytes start a complete line.
        let end = tail.iter().position(|&b| b == b'\n');
        tail.drain(..end.map_or(tail.len(), |i| i + 1));
    }
    Ok(tail)
}

/// The last non-blank line of `tail`, redacted.
pub(crate) fn last_line(tail: &[u8], credential: &str) -> String {
    let text = String::from_utf8_lossy(tail);
    let line = text
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("");
    redact_line(line.trim(), credential)
}

/// `line` without `credential`, raw or in base64 (alone, or as the Basic
/// value `x:<credential>`), and without any URL's userinfo, query or
/// fragment: the fetch env holds no other secret.
pub(crate) fn redact_line(line: &str, credential: &str) -> String {
    let forms: Vec<String> = [
        credential.to_owned(),
        STANDARD.encode(format!("x:{credential}")),
        STANDARD.encode(credential),
    ]
    .into_iter()
    // Unpadded, so the needle matches whatever padding follows it.
    .map(|f| f.trim_end_matches('=').to_owned())
    .collect();
    let text = redact_untruncated(line, &forms, &[]);
    let text = text
        .split(' ')
        .map(|word| {
            if word.contains("://") || word.contains(['@', '?', '#']) {
                // Punctuation belongs to the input: cutting it off can keep secrets.
                redact_url_keep_path(word)
            } else {
                word.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    // URL normalization can recreate a literal by lowercasing the host, so
    // every form is also matched case-insensitively, per word (a credential
    // holds no space).
    let lowered_forms: Vec<String> = forms
        .iter()
        .filter(|form| !form.is_empty())
        .map(|form| form.to_ascii_lowercase())
        .collect();
    text.split(' ')
        .map(|word| {
            // Case variants in paths or free text can survive URL normalization.
            let lowered = word.to_ascii_lowercase();
            if lowered_forms.iter().any(|form| lowered.contains(form)) {
                "[redacted]"
            } else {
                word
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
#[path = "fetch_output_tests.rs"]
mod tests;
