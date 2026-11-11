// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the fetch's output: drained whole, its tail kept, and the line a
//! refusal shows stripped of the fetch credential.

use std::io::Read;

use base64::engine::general_purpose::STANDARD;

use super::*;

const CRED: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

fn assert_clean(text: &str) {
    assert!(!text.contains(CRED), "raw credential left: {text}");
    for encoded in [STANDARD.encode(format!("x:{CRED}")), STANDARD.encode(CRED)] {
        let stem = encoded.trim_end_matches('=');
        assert!(!text.contains(stem), "base64 credential left: {text}");
    }
    assert!(!text.contains("x:0f1e"), "userinfo left: {text}");
}

/// T6 (N4): the credential raw, in base64 (alone and as the Basic value) and
/// inside a proxy URL leaves the refusal line; the rest of the line stays.
#[test]
fn the_credential_never_leaves_in_a_refusal_line() {
    let basic = STANDARD.encode(format!("x:{CRED}"));
    let alone = STANDARD.encode(CRED);
    for line in [
        format!("npm error proxy auth {CRED} rejected"),
        format!("npm error Proxy-Authorization: Basic {basic}"),
        format!("error: token {alone}"),
        format!("npm error request to http://x:{CRED}@127.0.0.1:41234/ failed"),
        format!("uv: proxy 'http://x:{CRED}@127.0.0.1:9' unreachable"),
    ] {
        let out = redact_line(&line, CRED);
        assert_clean(&out);
        assert!(
            out.contains("rror") || out.contains("uv:"),
            "context lost: {out}"
        );
    }
}

/// T6: another URL's userinfo goes too; a URL without userinfo stays.
#[test]
fn any_url_userinfo_is_removed() {
    let out = redact_line(
        "fetch https://user:hunter2@registry.npmjs.org/x failed",
        CRED,
    );
    assert!(!out.contains("hunter2") && !out.contains("user:"), "{out}");
    let out = redact_line("GET https://registry.npmjs.org/x 404", CRED);
    assert!(out.contains("https://registry.npmjs.org/x"), "{out}");
}

/// A reader that counts what was taken from it.
struct Counting<R> {
    inner: R,
    read: usize,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read += n;
        Ok(n)
    }
}

/// T13 (J2): output past the cap is drained to EOF, the tail holds at most
/// the cap, and a final credential-bearing line with no trailing newline
/// survives, redacted.
#[test]
fn output_past_the_cap_keeps_its_last_line() {
    let mut text = "npm http fetch GET 200 https://registry.npmjs.org/x 12ms\n".repeat(4000);
    let last = format!("npm error proxy http://x:{CRED}@127.0.0.1:9 refused");
    text.push_str(&last);
    assert!(text.len() > 3 * TAIL_BYTES);
    let mut reader = Counting {
        inner: text.as_bytes(),
        read: 0,
    };
    let tail = read_tail(&mut reader).expect("read");
    assert_eq!(reader.read, text.len(), "not drained to EOF");
    assert!(tail.len() <= TAIL_BYTES, "tail is {} bytes", tail.len());
    let line = last_line(&tail, CRED);
    assert!(line.starts_with("npm error proxy"), "{line}");
    assert_clean(&line);
}

/// The last line skips trailing blank lines; empty output has none.
#[test]
fn the_last_line_is_the_last_non_blank_one() {
    assert_eq!(last_line(b"first\nsecond\n\n  \n", CRED), "second");
    assert_eq!(last_line(b"", CRED), "");
}

/// A cut inside a secret cannot be repaired by matching the whole secret.
#[test]
fn a_tail_cut_inside_the_final_credential_shows_no_fragment() {
    let kept_secret_bytes = CRED.len() / 2;
    let text = format!(
        "previous line\nfetch {CRED}{}",
        "-".repeat(TAIL_BYTES - kept_secret_bytes)
    );
    let cut = text.len() - TAIL_BYTES;
    assert_eq!(
        &text[cut..cut + kept_secret_bytes],
        &CRED[kept_secret_bytes..]
    );
    assert!(!text[cut..].contains('\n'));
    let mut reader = Counting {
        inner: text.as_bytes(),
        read: 0,
    };
    let tail = read_tail(&mut reader).expect("read");
    assert_eq!(reader.read, text.len(), "not drained to EOF");
    let line = last_line(&tail, CRED);
    for len in 6..=CRED.len() {
        assert!(
            !line.contains(&CRED[CRED.len() - len..]),
            "credential suffix of {len} bytes left"
        );
    }
    assert!(line.is_empty(), "unterminated cut fragment shown");
}

/// Host normalization can recreate a literal; paths retain their input case.
#[test]
fn credential_case_variants_never_leave_in_urls() {
    let upper = CRED.to_ascii_uppercase();
    for url in [
        format!("https://{upper}/x"),
        format!("https://prefix{upper}suffix.example/x"),
        format!("https://registry.npmjs.org/{upper}"),
    ] {
        let out = redact_line(&format!("fetch {url} failed"), CRED);
        assert!(
            !out.to_ascii_lowercase().contains(CRED),
            "credential case variant left: {out}"
        );
        assert!(out.starts_with("fetch ") && out.ends_with(" failed"));
    }
}

/// Keeping any hand-cut punctuation can keep a password or token with it.
#[test]
fn whole_url_words_leave_no_userinfo_query_or_fragment() {
    let line = format!(
        "fetch user:pw@host/x x:{CRED}@host https://u:p@ss@h/x \
         \"https://u:pw@h/x?token=!!!\". ?token=!!! #token=!!! \
         https://h/x#token=!!! https://u:pw@h:bad/x?token=!!! failed"
    );
    let out = redact_line(&line, CRED);
    assert_clean(&out);
    for secret in ["pw", "p@ss", "p%40ss", "token", "!!!", "user:", "x:", "u:"] {
        assert!(!out.contains(secret), "{secret} left: {out}");
    }
    assert!(out.starts_with("fetch ") && out.ends_with(" failed"));
}

/// Clean diagnostics remain useful, including quotes around ordinary words.
#[test]
fn ordinary_text_and_plain_urls_are_preserved() {
    for line in [
        "ordinary fetch error",
        "fetch \"ordinary\" 'words'. failed",
        "GET https://registry.npmjs.org/x 404",
        "fetch https://host:bad/x failed",
    ] {
        assert_eq!(redact_line(line, CRED), line);
    }
}
