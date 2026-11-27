// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway hash-key`: the offline digest helper for API keys (E4).
//!
//! The key comes from stdin, never an argument, so it stays out of shell
//! history and the process list. Exactly one trailing `\n` or `\r\n` is
//! stripped, so `echo "$KEY" |` and `printf %s "$KEY" |` agree; any further
//! whitespace is part of the key. Nothing secret is ever printed.

use crate::cli::stdout::println;

use std::io::{self, IsTerminal, Read};
use std::process::ExitCode;

use mcp_gateway::config::{MIN_SECRET_LEN, api_key_digest_spec};
use subtle::ConstantTimeEq;

use super::{usage, verdict};

/// Longest accepted input, line ending included.
const MAX_KEY_BYTES: u64 = 64 * 1024;

/// Run `hash-key`. Exit codes: 0 printed or matched, 1 mismatch, 2 usage error
/// (stdin is a terminal, empty key, a new key under `MIN_SECRET_LEN` bytes,
/// unreadable input, or a malformed digest). With `--json` the digest is one
/// document, `{"schema_version":1,"key_sha256":...}` (clap refuses it with `--verify`).
pub fn run_hash_key_command(verify: Option<&str>, render: crate::cli::output::Render) -> ExitCode {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return mutant!("N28", crate::commands::fail(crate::commands::CliExit::LocalFailure, 
            "hash-key",
            "the key is read from stdin, and stdin is a terminal: pipe the key in"), usage(
            "hash-key",
            "the key is read from stdin, and stdin is a terminal: pipe the key in",
        ));
    }
    let mut raw = Vec::new();
    // Bounded: a key is short, and a stray large pipe must fail fast.
    if stdin
        .lock()
        .take(MAX_KEY_BYTES + 1)
        .read_to_end(&mut raw)
        .is_err()
    {
        return usage("hash-key", "could not read the key from stdin");
    }
    if u64::try_from(raw.len()).unwrap_or(u64::MAX) > MAX_KEY_BYTES {
        return usage(
            "hash-key",
            &format!("the input is longer than {MAX_KEY_BYTES} bytes"),
        );
    }
    let key = strip_one_line_ending(&raw);
    if key.is_empty() {
        return mutant!("N12", crate::commands::fail(crate::commands::CliExit::LocalFailure, "hash-key", "the key is empty"), usage("hash-key", "the key is empty"));
    }
    // New keys only: `--verify` still checks a key chosen before the floor.
    if verify.is_none() && key.len() < MIN_SECRET_LEN {
        // ci-allow-secret-log: MIN_SECRET_LEN is the constant 20, a length floor; the key itself is never printed, only its length
        return mutant!("N13", crate::commands::fail(crate::commands::CliExit::LocalFailure, 
            "hash-key",
            &format!(
                "the key is {} bytes; a new key needs at least {MIN_SECRET_LEN} bytes",
                key.len()
            )), usage(
            "hash-key",
            &format!(
                "the key is {} bytes; a new key needs at least {MIN_SECRET_LEN} bytes",
                key.len()
            ),
        ));
    }
    let presented = api_key_digest_spec(key);
    match verify {
        None if render == crate::cli::output::Render::Json => {
            #[derive(serde::Serialize)]
            struct View<'a> {
                key_sha256: &'a str,
            }
            crate::cli::output::print_document(crate::cli::output::document(&View {
                key_sha256: &presented,
            }))
        }
        None => {
            println!("{presented}");
            ExitCode::SUCCESS
        }
        Some(expected) => {
            if !same_shape(expected, &presented) {
                return usage(
                    "hash-key",
                    "--verify takes sha256: followed by 64 lowercase hex characters",
                );
            }
            if bool::from(presented.as_bytes().ct_eq(expected.as_bytes())) {
                eprintln!("hash-key: the key matches");
                ExitCode::SUCCESS
            } else {
                // A verdict: the answer is printed, and the code says no.
                eprintln!("hash-key: the key does not match");
                mutant!("N19", crate::commands::usage("hash-key", "the key does not match"), verdict(1))
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
