// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! E4 (APIKEY.1): `mcp-gateway hash-key` turns a key read from stdin into the
//! `sha256:<hex>` digest the config stores, and `--verify` checks one.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::io::Write;
use std::process::{Output, Stdio};

use sha2::{Digest, Sha256};

/// A 20-byte key: exactly the floor `hash-key` accepts for a new key (T2).
const KEY: &[u8] = b"k-abc-0123456789-xyz";

fn digest_of(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn hash_key(args: &[&str], stdin: &[u8]) -> Output {
    let home = tempfile::tempdir().expect("an isolated home");
    let mut child = gateway_bin::command(home.path(), gateway_bin::Inherit::Environment)
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
    let expected = digest_of(KEY);
    // `printf %s`, `echo`, and a CRLF line all name the same key.
    for input in [KEY.to_vec(), [KEY, b"\n"].concat(), [KEY, b"\r\n"].concat()] {
        let output = hash_key(&[], &input);
        assert!(output.status.success(), "{input:?}: {output:?}");
        assert_eq!(printed(&output), expected, "{input:?}");
    }
    // Exactly one line ending is stripped: the rest is part of the key.
    let output = hash_key(&[], &[KEY, b"\n\n"].concat());
    assert!(output.status.success(), "{output:?}");
    assert_eq!(printed(&output), digest_of(&[KEY, b"\n"].concat()));

    // The floor counts bytes: ten two-byte characters are a 20-byte key.
    let multibyte = "é".repeat(10);
    let output = hash_key(&[], multibyte.as_bytes());
    assert!(output.status.success(), "{output:?}");
    assert_eq!(printed(&output), digest_of(multibyte.as_bytes()));

    let empty = hash_key(&[], b"\n");
    assert!(!empty.status.success(), "an empty key must be refused");
    assert!(empty.stdout.is_empty(), "{empty:?}");
}

/// T1: a new key under 20 bytes is a usage error that
/// names the floor and prints neither a digest nor the key. The floor counts
/// the key, so a 19-byte key with its line ending (20 bytes read) is refused
/// too.
#[test]
fn hash_key_refuses_a_short_new_key() {
    let short = &KEY[..19];
    for input in [short.to_vec(), [short, b"\n"].concat()] {
        let output = hash_key(&[], &input);
        assert_eq!(output.status.code(), Some(2), "{input:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("20 bytes"), "the floor is named: {stderr}");
        assert!(
            !stderr.contains(std::str::from_utf8(short).expect("ascii")),
            "the key was printed: {stderr}"
        );
    }
}

// E4-T10b
#[test]
fn hash_key_verify_exit_codes() {
    let right = digest_of(b"k-abc");
    let wrong = digest_of(b"k-abd");
    for (digest, code) in [(right.as_str(), 0), (wrong.as_str(), 1), ("sha256:xyz", 2)] {
        let output = hash_key(&["--verify", digest], b"k-abc\n");
        assert_eq!(output.status.code(), Some(code), "{digest}: {output:?}");
        if code == 1 {
            // The mismatch verdict's text is pinned before hash_key.rs is converted to the shared exit helpers.
            assert_eq!(
                String::from_utf8_lossy(&output.stderr),
                "hash-key: the key does not match\n"
            );
        }
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!all.contains("k-abc"), "the key was printed: {all}");
    }
}
