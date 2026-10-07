// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An early exit's stderr tail as `doctor --start-stdio --show-stderr` shows
//! it (MIK-7978). Read only through
//! [`StdioTransport::last_failure_stderr`](super::StdioTransport::last_failure_stderr);
//! the gateway log and MCP errors never carry it.
//!
//! Masking is best effort, so the doctor prints the lines under a banner
//! saying they may still hold a secret: no pattern list is complete.

use std::collections::VecDeque;
use std::sync::LazyLock;

use regex::Regex;

/// Lines shown, the last ones.
const SHOWN_LINES: usize = 20;
/// Characters shown of one line, counted after masking so a cut never splits
/// a secret out of its pattern's reach.
const SHOWN_CHARS: usize = 240;
const MASK: &str = "[masked]";

/// Everything between a URL scheme and the last `@` of the word: userinfo,
/// however its slashes are spelled (`https:tok@`, `https:///tok@`).
static URL_USERINFO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b([a-z][a-z0-9+.-]*:)\S*@").expect("valid"));
/// The word after `Bearer` or `Basic`.
static AUTH_SCHEME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\b(bearer|basic)\s+[^\s"',;]+"#).expect("valid"));
/// A secret-named key's value, in env (`K=v`), YAML (`k: v`) and JSON
/// (`"k": "v"`, `{'k': 'v'}`) forms. A quoted value runs to its unescaped
/// closing quote.
static SECRET_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)([a-z0-9_.-]*(?:key|secret|token|passw(?:or)?d|passphrase|pwd|credential|auth)[a-z0-9_.-]*)(["']?\s*[:=]\s*)("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,;}&]+)"#,
    )
    .expect("valid")
});
/// A long run of token characters: most generated credentials, in every
/// build. Only a run holding both a letter and a digit is masked, so words
/// and plain numbers stay readable.
static LONG_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9_-]{24,}").expect("valid"));
/// A long base64 run that `+` and `/` would otherwise cut into pieces
/// shorter than [`LONG_TOKEN`]'s floor. Masked only when it holds a `+` or
/// ends in `=` padding and mixes letters with digits, so a slash-separated
/// path stays readable; a key body line without a cue is masked at capture
/// by [`captured_line`].
static BASE64_RUN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/]{40,}={0,2}").expect("valid"));
#[cfg(feature = "firewall")]
static REDACTOR: LazyLock<crate::security::firewall::redactor::Redactor> =
    LazyLock::new(crate::security::firewall::redactor::Redactor::new);

/// What the capture keeps of one raw stderr line: a line inside a
/// `-----BEGIN`/`-----END` block becomes the mask before the tail can evict
/// the `-----BEGIN` that marks it. A block left open masks the rest.
pub(super) fn captured_line(in_block: &mut bool, line: &[u8]) -> Vec<u8> {
    let body = *in_block && last(line, END).is_none();
    track_block(in_block, line);
    if body { MASK.as_bytes() } else { line }.to_vec()
}

const BEGIN: &[u8] = b"-----BEGIN";
const END: &[u8] = b"-----END";
/// Bytes a reader carries from one chunk into the next, so a marker cut by
/// the chunk boundary is still found. Too short to repeat a `-----BEGIN`; an
/// `-----END` it repeats was the chunk's last marker, so the state holds.
pub(super) const MARKER_CARRY: usize = BEGIN.len() - 1;

/// Update the block state from one chunk of a line: the last marker in it
/// decides. Also run over the unstored rest of an overlong line.
pub(super) fn track_block(in_block: &mut bool, chunk: &[u8]) {
    match (last(chunk, BEGIN), last(chunk, END)) {
        (Some(begin), end) if end.is_none_or(|end| end < begin) => *in_block = true,
        (_, Some(_)) => *in_block = false,
        _ => {}
    }
}

fn last(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

/// The tail as shown: UTF-8 lines only, control characters as spaces,
/// credentials masked, each line and the line count capped.
pub(super) fn sanitize(tail: &VecDeque<Vec<u8>>) -> Vec<String> {
    let lines: Vec<String> = tail
        .iter()
        .filter_map(|raw| std::str::from_utf8(raw).ok())
        .map(|line| line.trim_end_matches(['\r', '\n']))
        .filter(|line| !line.trim().is_empty())
        .map(|line| mask(line).chars().take(SHOWN_CHARS).collect())
        .collect();
    let skip = lines.len().saturating_sub(SHOWN_LINES);
    lines.into_iter().skip(skip).collect()
}

/// One line with control characters as spaces and every known credential
/// shape masked. Spaces first, so a tab still separates `Bearer` from its value.
fn mask(line: &str) -> String {
    let line: String = line
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    #[cfg(feature = "firewall")]
    let line = mask_spans(&line, &REDACTOR.credential_spans(&line));
    let line = URL_USERINFO.replace_all(&line, format!("${{1}}{MASK}@"));
    let line = AUTH_SCHEME.replace_all(&line, format!("${{1}} {MASK}"));
    let line = SECRET_VALUE.replace_all(&line, format!("${{1}}${{2}}{MASK}"));
    let line = BASE64_RUN.replace_all(&line, |run: &regex::Captures<'_>| {
        let run = &run[0];
        let cue = run.contains('+') || run.ends_with('=');
        if cue {
            mask_mixed(run)
        } else {
            run.to_string()
        }
    });
    LONG_TOKEN
        .replace_all(&line, |run: &regex::Captures<'_>| mask_mixed(&run[0]))
        .into_owned()
}

/// Only a run holding both a letter and a digit is masked.
fn mask_mixed(run: &str) -> String {
    let mixed =
        run.bytes().any(|b| b.is_ascii_alphabetic()) && run.bytes().any(|b| b.is_ascii_digit());
    if mixed { MASK } else { run }.to_string()
}

#[cfg(feature = "firewall")]
fn mask_spans(text: &str, spans: &[(usize, usize)]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for &(start, end) in spans {
        out.push_str(&text[cursor..start]);
        out.push_str(MASK);
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shown(lines: &[&[u8]]) -> Vec<String> {
        sanitize(&lines.iter().copied().map(<[u8]>::to_vec).collect())
    }

    fn one(line: &str) -> String {
        let out = shown(&[line.as_bytes()]);
        assert_eq!(out.len(), 1, "{out:?}");
        out[0].clone()
    }

    #[test]
    fn a_plain_line_is_shown_and_a_non_utf8_one_dropped() {
        let out = shown(&[b"Error: Cannot find module x\n", b"bad \xff\xfe byte\n"]);
        assert_eq!(out, vec!["Error: Cannot find module x".to_string()]);
    }

    #[test]
    fn control_characters_become_spaces() {
        let line = one("\x1b[31mred\x1b[0m\tBearer\tsecret-7978\r\n");
        assert!(!line.chars().any(char::is_control), "{line:?}");
        assert!(line.contains("red"), "{line:?}");
        // A tab is a separator: the bearer mask still sees its value.
        assert!(!line.contains("secret-7978"), "{line:?}");
    }

    #[test]
    fn bearer_and_basic_values_are_masked() {
        for (line, secret) in [
            ("Authorization: Bearer abc.def-7978", "abc.def-7978"),
            ("auth failed: basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ] {
            let out = one(line);
            assert!(!out.contains(secret), "{out}");
            assert!(out.contains("[masked]"), "{out}");
        }
    }

    #[test]
    fn key_value_secrets_are_masked_in_env_and_json_forms() {
        for (line, secret) in [
            ("API_KEY=k-7978-one", "k-7978-one"),
            ("password = hunter7978", "hunter7978"),
            (r#"{"api_key": "k-7978-two", "port": 3}"#, "k-7978-two"),
            ("client_secret: 'k-7978-three'", "k-7978-three"),
            (r#"{"password":"alpha\"rest-7978"}"#, "rest-7978"),
            (r"TOKEN='a\'rest-7979'", "rest-7979"),
            ("{'api_key': 'k-7978-four', 'port': 3}", "k-7978-four"),
            ("ssh passphrase: k-7978-five", "k-7978-five"),
        ] {
            let out = one(line);
            assert!(!out.contains(secret), "{out}");
            assert!(out.contains("[masked]"), "{out}");
        }
        assert!(one(r#"{"port": 3}"#).contains("\"port\": 3"));
    }

    #[test]
    fn url_credentials_are_removed() {
        for (line, secret) in [
            (
                "connect postgres://user:pw-7978@db:5432/x failed",
                "pw-7978",
            ),
            ("dial https://tok-7978@api.example.invalid/v1", "tok-7978"),
            ("dial https:tok-7978@host", "tok-7978"),
            ("dial https:///tok-7978@host", "tok-7978"),
            ("dial https:\\\\tok-7978@host", "tok-7978"),
            (r#"url="https://u:pw-7978@host/a","#, "pw-7978"),
        ] {
            let out = one(line);
            assert!(!out.contains(secret), "{line} -> {out}");
        }
        assert_eq!(
            one("fetch https://example.invalid/x failed"),
            "fetch https://example.invalid/x failed"
        );
    }

    // Every build, firewall feature or not.
    #[test]
    fn a_long_generated_token_is_masked() {
        let token = format!("ghp_{}", "a1".repeat(18));
        for line in [
            format!("using {token} to clone"),
            "key sk-live-0123456789abcdefghijklmn rejected".to_string(),
        ] {
            let out = one(&line);
            assert!(out.contains(MASK), "{line} -> {out}");
            assert!(!out.contains("0123456789abc"), "{out}");
            assert!(!out.contains(&token), "{out}");
        }
        let words =
            "node_modules/@modelcontextprotocol/server-filesystem abcdefghijklmnopqrstuvwxyz";
        assert_eq!(one(words), words);
        // The threshold: 23 token characters stay, 24 are masked.
        assert_eq!(
            one("id x1234567890abcdefghijkl."),
            "id x1234567890abcdefghijkl."
        );
        assert_eq!(one("id x1234567890abcdefghijklm."), "id [masked].");
    }

    #[test]
    fn a_base64_key_body_is_masked_whole() {
        // Letters and digits left once the masks are taken out.
        let residue = |s: &str| {
            s.replace(MASK, "")
                .chars()
                .filter(char::is_ascii_alphanumeric)
                .count()
        };
        let body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw+ggSjAgEAAoIB/AQC7k9x2Q==";
        for line in [body.to_string(), format!("stderr: {body} end")] {
            let out = one(&line);
            assert!(out.contains(MASK), "{line} -> {out}");
            assert_eq!(residue(&out), residue(&line.replace(body, "")), "{out}");
        }
        for path in [
            "/usr/lib/node/modules/server/filesystem/dist/index",
            "/usr/lib/python3/dist/packages/mcp/server/filesystem.py",
            "/usr/lib/python3/dist/packages/mcp/server/filesystem",
        ] {
            assert_eq!(one(path), path, "a path stays readable");
        }
    }

    #[test]
    fn the_capture_masks_a_block_body_whatever_its_shape() {
        let lines: [&[u8]; 6] = [
            b"-----BEGIN EXAMPLE BLOCK-----\n",
            b"MIIEvQIBADANBg/kqhkiG9w0BAQEFAASCBKcwggSjAgEA/AoIBAQC7k9x2Q\n",
            b"AQIDBAUGBwgJCgsMDQ4PEBE=\n",
            b"-----END EXAMPLE BLOCK-----\n",
            b"after the block\n",
            b"one line -----BEGIN X----- abc -----END X----- done\n",
        ];
        let mut open = false;
        let kept: Vec<Vec<u8>> = lines
            .iter()
            .map(|line| captured_line(&mut open, line))
            .collect();
        assert_eq!(kept[0], lines[0]);
        assert_eq!(kept[1], MASK.as_bytes(), "a cue-less body line");
        assert_eq!(kept[2], MASK.as_bytes(), "a short final body line");
        assert_eq!(kept[3..], lines[3..], "the block closed at END");
        assert!(!open, "a block opened and closed on one line stays closed");
        // A block never closed masks to the end.
        let mut open = false;
        let _ = captured_line(&mut open, b"-----BEGIN EXAMPLE BLOCK-----");
        assert_eq!(captured_line(&mut open, b"plain text"), MASK.as_bytes());
    }

    #[test]
    fn the_last_marker_on_a_line_decides_the_block() {
        let mut open = false;
        let _ = captured_line(&mut open, b"-----END A----- then -----BEGIN B-----");
        assert!(open, "a BEGIN after an END opens the block");
        let _ = captured_line(&mut open, b"-----BEGIN B----- x -----END B-----");
        assert!(!open, "an END after a BEGIN closes it");
    }

    #[test]
    fn lines_and_line_length_are_capped() {
        let many: Vec<Vec<u8>> = (0..30).map(|i| format!("line-{i}").into_bytes()).collect();
        let out = sanitize(&many.into_iter().collect());
        assert_eq!(out.len(), 20, "{out:?}");
        assert_eq!(out.last().map(String::as_str), Some("line-29"));
        let long = one(&"é".repeat(1000));
        assert_eq!(long.chars().count(), 240, "capped by characters");
    }
}
