// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway hash-key`: the offline digest helper for API keys (E4).
//!
//! The key comes from stdin, never an argument, so it stays out of shell
//! history and the process list. Exactly one trailing `\n` or `\r\n` is
//! stripped, so `echo "$KEY" |` and `printf %s "$KEY" |` agree; any further
//! whitespace is part of the key. Nothing secret is ever printed.

use std::io::{self, IsTerminal, Read};
use std::process::ExitCode;

use mcp_gateway::config::api_key_digest_spec;
use subtle::ConstantTimeEq;

/// Longest accepted input, line ending included.
const MAX_KEY_BYTES: u64 = 64 * 1024;

const USAGE: &str = "usage: printf %s \"$KEY\" | mcp-gateway hash-key [--verify sha256:<hex>]";

/// Run `hash-key`. Exit codes: 0 printed or matched, 1 mismatch, 2 usage error
/// (stdin is a terminal, empty key, unreadable input, or a malformed digest).
pub fn run_hash_key_command(verify: Option<&str>) -> ExitCode {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    let mut raw = Vec::new();
    // Bounded: a key is short, and a stray large pipe must fail fast.
    if stdin
        .lock()
        .take(MAX_KEY_BYTES + 1)
        .read_to_end(&mut raw)
        .is_err()
    {
        eprintln!("hash-key: could not read the key from stdin");
        return ExitCode::from(2);
    }
    if u64::try_from(raw.len()).unwrap_or(u64::MAX) > MAX_KEY_BYTES {
        eprintln!("hash-key: the input is longer than {MAX_KEY_BYTES} bytes");
        return ExitCode::from(2);
    }
    let key = strip_one_line_ending(&raw);
    if key.is_empty() {
        eprintln!("hash-key: the key is empty\n{USAGE}");
        return ExitCode::from(2);
    }
    let presented = api_key_digest_spec(key);
    match verify {
        None => {
            println!("{presented}");
            ExitCode::SUCCESS
        }
        Some(expected) => {
            if !same_shape(expected, &presented) {
                eprintln!(
                    "hash-key: --verify takes sha256: followed by 64 lowercase hex characters"
                );
                return ExitCode::from(2);
            }
            if bool::from(presented.as_bytes().ct_eq(expected.as_bytes())) {
                eprintln!("hash-key: the key matches");
                ExitCode::SUCCESS
            } else {
                eprintln!("hash-key: the key does not match");
                ExitCode::from(1)
            }
        }
    }
}

/// Whether `expected` has the canonical shape of `presented`, the library's
/// own output: the same prefix and length, then lowercase hex. Derived from
/// that output so the digest format is defined once, in the library.
fn same_shape(expected: &str, presented: &str) -> bool {
    let Some(split) = presented.find(':').map(|i| i + 1) else {
        return false;
    };
    expected.len() == presented.len()
        && expected.get(..split) == presented.get(..split)
        && expected[split..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Strip exactly one trailing `\r\n` or `\n`.
fn strip_one_line_ending(raw: &[u8]) -> &[u8] {
    raw.strip_suffix(b"\r\n")
        .or_else(|| raw.strip_suffix(b"\n"))
        .unwrap_or(raw)
}
