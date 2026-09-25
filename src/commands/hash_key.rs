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

use mcp_gateway::config::{api_key_digest_spec, parse_api_key_digest};
use subtle::ConstantTimeEq;

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
    if stdin.lock().read_to_end(&mut raw).is_err() {
        eprintln!("hash-key: could not read the key from stdin");
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
            let (Some(expected), Some(presented)) = (
                parse_api_key_digest(expected),
                parse_api_key_digest(&presented),
            ) else {
                eprintln!(
                    "hash-key: --verify takes sha256: followed by 64 lowercase hex characters"
                );
                return ExitCode::from(2);
            };
            if bool::from(presented.as_slice().ct_eq(expected.as_slice())) {
                eprintln!("hash-key: the key matches");
                ExitCode::SUCCESS
            } else {
                eprintln!("hash-key: the key does not match");
                ExitCode::from(1)
            }
        }
    }
}

/// Strip exactly one trailing `\r\n` or `\n`.
fn strip_one_line_ending(raw: &[u8]) -> &[u8] {
    raw.strip_suffix(b"\r\n")
        .or_else(|| raw.strip_suffix(b"\n"))
        .unwrap_or(raw)
}
