// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! E4 (APIKEY.1): `mcp-gateway hash-key` turns a key read from stdin into the
//! `sha256:<hex>` digest the config stores, and `--verify` checks one.

use std::io::Write;
use std::process::{Command, Output, Stdio};

use sha2::{Digest, Sha256};

fn digest_of(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn hash_key(args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-gateway"))
        .arg("hash-key")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary starts");
    // A binary that exits before reading closes the pipe; its exit status,
    // not this write, is what the cell asserts.
    let _ = child.stdin.take().expect("stdin is piped").write_all(stdin);
    child.wait_with_output().expect("binary exits")
}

fn printed(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .trim_end()
        .to_string()
}

// E4-T10
#[test]
fn hash_key_cli_prints_digest() {
    let expected = digest_of(b"k-abc");
    // `printf %s`, `echo`, and a CRLF line all name the same key.
    for input in [&b"k-abc"[..], b"k-abc\n", b"k-abc\r\n"] {
        let output = hash_key(&[], input);
        assert!(output.status.success(), "{input:?}: {output:?}");
        assert_eq!(printed(&output), expected, "{input:?}");
    }
    // Exactly one line ending is stripped: the rest is part of the key.
    let output = hash_key(&[], b"k-abc\n\n");
    assert!(output.status.success(), "{output:?}");
    assert_eq!(printed(&output), digest_of(b"k-abc\n"));

    let empty = hash_key(&[], b"\n");
    assert!(!empty.status.success(), "an empty key must be refused");
    assert!(empty.stdout.is_empty(), "{empty:?}");
}

// E4-T10b
#[test]
fn hash_key_verify_exit_codes() {
    let right = digest_of(b"k-abc");
    let wrong = digest_of(b"k-abd");
    for (digest, code) in [(right.as_str(), 0), (wrong.as_str(), 1), ("sha256:xyz", 2)] {
        let output = hash_key(&["--verify", digest], b"k-abc\n");
        assert_eq!(output.status.code(), Some(code), "{digest}: {output:?}");
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!all.contains("k-abc"), "the key was printed: {all}");
    }
}
