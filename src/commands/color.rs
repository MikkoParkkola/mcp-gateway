// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Whether a command colours its output (MIK-8044 P2c3a).
//!
//! `validate --no-color` is AUTO: colour follows the terminal and the
//! `NO_COLOR` convention (<https://no-color.org>), and the flag stays as a
//! hidden override.

/// Whether to colour output: never when the hidden `--no-color` flag is
/// given, never when `NO_COLOR` asks for none (see [`no_color_requested`]),
/// and otherwise only when the output is a terminal.
pub(crate) fn wanted(no_color_flag: bool, no_color_env: bool, stdout_is_terminal: bool) -> bool {
    !no_color_flag && !no_color_env && stdout_is_terminal
}

/// Whether a `NO_COLOR` value asks for no colour: present and not empty, as
/// no-color.org specifies. `NO_COLOR=` (empty) leaves colour on.
pub(crate) fn no_color_requested(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|v| !v.is_empty())
}

/// [`wanted`] for this process's stdout and environment.
pub(crate) fn for_stdout(no_color_flag: bool) -> bool {
    use std::io::IsTerminal as _;
    wanted(
        no_color_flag,
        no_color_requested(std::env::var_os("NO_COLOR").as_deref()),
        std::io::stdout().is_terminal(),
    )
}

#[cfg(test)]
mod tests {
    use super::{no_color_requested, wanted};

    #[test]
    fn colour_follows_the_terminal_and_no_color() {
        // A terminal with no override: colour.
        assert!(wanted(false, false, true));
        // Piped output: plain, with no flag needed.
        assert!(!wanted(false, false, false), "a pipe gets no colour");
        // NO_COLOR set: plain, even on a terminal.
        assert!(!wanted(false, true, true), "NO_COLOR is honoured");
        // The hidden flag still forces plain.
        assert!(!wanted(true, false, true), "--no-color still applies");
    }

    #[test]
    fn no_color_counts_only_when_present_and_not_empty() {
        use std::ffi::OsStr;
        assert!(!no_color_requested(None), "unset");
        assert!(
            !no_color_requested(Some(OsStr::new(""))),
            "NO_COLOR= is not a request"
        );
        assert!(
            no_color_requested(Some(OsStr::new("1"))),
            "any non-empty value"
        );
    }
}
