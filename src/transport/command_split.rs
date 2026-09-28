// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Split a configured stdio `command` string with host-platform rules.
//!
//! Five call sites must agree on the program name a config will spawn. Unix
//! keeps POSIX [`shlex::split`]; Windows follows `CommandLineToArgvW` so a
//! backslash is a path separator unless it sits in a run immediately before a
//! double quote. Both rule sets are pure functions and are tested on every
//! host; only [`split_command`] is `cfg`-selected.

/// Parse a configured stdio `command` with this host's rules.
///
/// Returns `None` when quoting is invalid (including an unterminated quote).
#[must_use]
pub fn split_command(command: &str) -> Option<Vec<String>> {
    #[cfg(windows)]
    {
        split_command_windows(command)
    }
    #[cfg(not(windows))]
    {
        split_command_unix(command)
    }
}

/// POSIX / unix rule set (`shlex::split`). Exposed so tests cover it on every host.
#[must_use]
pub fn split_command_unix(command: &str) -> Option<Vec<String>> {
    shlex::split(command)
}

/// Windows `CommandLineToArgvW` rule set. Exposed so tests cover it on every host.
///
/// Rules (MSDN / The Old New Thing):
/// - Outside quotes, space and tab delimit arguments.
/// - A `"` toggles quoting (and is not itself part of the argument).
/// - `n` backslashes not followed by `"` are literal.
/// - `2n` backslashes followed by `"` become `n` backslashes and the quote
///   toggles quoting.
/// - `2n+1` backslashes followed by `"` become `n` backslashes and a literal `"`.
///
/// An unterminated quote is an error (`None`), matching [`split_command_unix`]
/// rather than silently accepting a truncated argv.
#[must_use]
pub fn split_command_windows(command: &str) -> Option<Vec<String>> {
    let mut args: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut chars = command.chars().peekable();
    let mut in_quotes = false;
    // Empty `""` must still produce an argument; track whether the current
    // argv slot was opened (by any non-delimiter character or a quote pair).
    let mut arg_started = false;

    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let mut count = 1usize;
                while chars.peek() == Some(&'\\') {
                    chars.next();
                    count += 1;
                }
                if chars.peek() == Some(&'"') {
                    for _ in 0..(count / 2) {
                        cur.push('\\');
                    }
                    arg_started = true;
                    if count % 2 == 1 {
                        chars.next();
                        cur.push('"');
                    }
                    // Even count: leave the quote for the `'"'` arm below.
                } else {
                    for _ in 0..count {
                        cur.push('\\');
                    }
                    arg_started = true;
                }
            }
            '"' if in_quotes => {
                // Doubled quote inside a quoted argument → one literal quote
                // (MSVC / CommandLineToArgvW extension used by modern CRT).
                if chars.peek() == Some(&'"') {
                    chars.next();
                    cur.push('"');
                    arg_started = true;
                } else {
                    in_quotes = false;
                }
            }
            '"' => {
                in_quotes = true;
                arg_started = true;
            }
            c if (c == ' ' || c == '\t') && !in_quotes => {
                if arg_started {
                    args.push(std::mem::take(&mut cur));
                    arg_started = false;
                }
            }
            _ => {
                cur.push(c);
                arg_started = true;
            }
        }
    }

    if in_quotes {
        return None;
    }
    if arg_started {
        args.push(cur);
    }
    Some(args)
}

/// The inverse of [`split_command`] on this host: one command line whose
/// split is exactly `argv`, or `None` when an argument cannot be quoted (a
/// NUL). Discovery uses it so a client's `command` and `args` survive the
/// string the transport stores (#1876).
#[must_use]
pub fn join_command(argv: &[String]) -> Option<String> {
    #[cfg(windows)]
    {
        join_command_windows(argv)
    }
    #[cfg(not(windows))]
    {
        join_command_unix(argv)
    }
}

/// The inverse of [`split_command_unix`].
#[must_use]
#[cfg_attr(
    all(not(test), windows),
    expect(
        dead_code,
        reason = "the Unix rule set; Windows builds use it only in tests"
    )
)]
pub fn join_command_unix(argv: &[String]) -> Option<String> {
    shlex::try_join(argv.iter().map(String::as_str)).ok()
}

/// The inverse of [`split_command_windows`].
#[must_use]
#[cfg_attr(
    all(not(test), not(windows)),
    expect(
        dead_code,
        reason = "the Windows rule set; other builds use it only in tests"
    )
)]
pub fn join_command_windows(argv: &[String]) -> Option<String> {
    let mut line = String::new();
    for arg in argv {
        if arg.contains('\0') {
            return None;
        }
        if !line.is_empty() {
            line.push(' ');
        }
        let plain = !arg.is_empty() && !arg.contains([' ', '\t', '"']);
        if plain {
            line.push_str(arg);
            continue;
        }
        // Quote per the rules `split_command_windows` reads: backslashes are
        // literal unless they precede a quote, where they are doubled; a quote
        // is escaped with one backslash; trailing backslashes before the
        // closing quote are doubled.
        line.push('"');
        let mut backslashes = 0usize;
        for c in arg.chars() {
            match c {
                '\\' => backslashes += 1,
                '"' => {
                    line.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                    line.push('"');
                    backslashes = 0;
                }
                other => {
                    line.extend(std::iter::repeat_n('\\', backslashes));
                    line.push(other);
                    backslashes = 0;
                }
            }
        }
        line.extend(std::iter::repeat_n('\\', backslashes * 2));
        line.push('"');
    }
    Some(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The string reported in GH #523 / #527.
    const REPORTED_WIN_CMD: &str = r"C:\Windows\py.exe -3.11 -m markitdown_mcp";

    #[test]
    fn windows_rules_keep_backslash_paths() {
        let parts = split_command_windows(REPORTED_WIN_CMD).expect("split");
        assert_eq!(
            parts,
            vec![
                r"C:\Windows\py.exe".to_string(),
                "-3.11".to_string(),
                "-m".to_string(),
                "markitdown_mcp".to_string(),
            ]
        );
    }

    #[test]
    fn unix_rules_mangle_backslash_paths_as_posix_escapes() {
        // Documents why Windows must not use this rule set: POSIX shlex eats `\`.
        let parts = split_command_unix(REPORTED_WIN_CMD).expect("split");
        assert_eq!(parts.first().map(String::as_str), Some("C:Windowspy.exe"));
    }

    #[test]
    fn windows_rules_keep_quoted_path_with_spaces() {
        let parts = split_command_windows(r#""C:\Program Files\py.exe" -3.11"#).expect("split");
        assert_eq!(
            parts,
            vec![r"C:\Program Files\py.exe".to_string(), "-3.11".to_string()]
        );
    }

    #[test]
    fn unix_rules_keep_quoted_macos_path_with_spaces() {
        let parts = split_command_unix(r#""/Applications/My App/bin/tool" --flag"#).expect("split");
        assert_eq!(
            parts,
            vec![
                "/Applications/My App/bin/tool".to_string(),
                "--flag".to_string()
            ]
        );
    }

    #[test]
    fn windows_unterminated_quote_is_error() {
        assert!(split_command_windows(r#""C:\Program Files\py.exe"#).is_none());
    }

    #[test]
    fn unix_unterminated_quote_is_error() {
        assert!(split_command_unix(r#""/Applications/My App/bin"#).is_none());
    }

    #[test]
    fn windows_odd_backslashes_before_quote_are_literal_quote() {
        // `\\\"` → one `\`, then literal `"`
        let parts = split_command_windows(r#"a\\\"b"#).expect("split");
        assert_eq!(parts, vec![r#"a\"b"#.to_string()]);
    }

    #[test]
    fn host_split_command_selects_a_rule_set() {
        let parts = split_command("npx -y pkg").expect("split");
        assert_eq!(
            parts,
            vec!["npx".to_string(), "-y".to_string(), "pkg".to_string()]
        );
    }

    fn argv_table() -> Vec<Vec<String>> {
        let v = |xs: &[&str]| xs.iter().map(|x| (*x).to_string()).collect::<Vec<_>>();
        vec![
            v(&["npx"]),
            v(&["npx", "-y", "some-server"]),
            v(&["/Applications/My Tools/server", "--flag"]),
            v(&["prog", "a b", "c"]),
            v(&["prog", r#"say "hi""#]),
            v(&["prog", r"back\slash", "trailing\\"]),
            v(&["prog", "q\\\"x"]),
            v(&["prog", ""]),
            v(&["prog", "it's"]),
        ]
    }

    /// #1876: joining then splitting gives back the same argv, per rule set.
    #[test]
    fn join_then_split_round_trips_unix() {
        for argv in argv_table() {
            let line = join_command_unix(&argv).unwrap_or_else(|| panic!("join {argv:?}"));
            assert_eq!(
                split_command_unix(&line),
                Some(argv.clone()),
                "via {line:?}"
            );
        }
    }

    #[test]
    fn join_then_split_round_trips_windows() {
        for argv in argv_table() {
            let line = join_command_windows(&argv).unwrap_or_else(|| panic!("join {argv:?}"));
            assert_eq!(
                split_command_windows(&line),
                Some(argv.clone()),
                "via {line:?}"
            );
        }
    }

    #[test]
    fn a_nul_argument_cannot_be_joined() {
        let argv = vec!["prog".to_string(), "a\u{0}b".to_string()];
        assert_eq!(join_command_unix(&argv), None);
        assert_eq!(join_command_windows(&argv), None);
    }
}
