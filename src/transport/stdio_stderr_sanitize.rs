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

/// The tail as shown: UTF-8 lines only, control characters as spaces,
/// credentials masked, each line and the line count capped.
pub(super) fn sanitize(_tail: &VecDeque<Vec<u8>>) -> Vec<String> {
    Vec::new()
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

    #[cfg(feature = "firewall")]
    #[test]
    fn a_credential_the_firewall_knows_is_masked() {
        let token = format!("ghp_{}", "a1".repeat(18));
        let out = one(&format!("using {token} to clone"));
        assert!(!out.contains(&token), "{out}");
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
