// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Whether a command colours its output (MIK-8044 P2c3a).
//!
//! `validate --no-color` is AUTO: colour follows the terminal and the
//! `NO_COLOR` convention (<https://no-color.org>), and the flag stays as a
//! hidden override.

/// Whether to colour output: never when the hidden `--no-color` flag is
/// given, never when `NO_COLOR` is set (to anything), and otherwise only
/// when the output is a terminal.
pub(crate) fn wanted(no_color_flag: bool, no_color_env: bool, stdout_is_terminal: bool) -> bool {
    !no_color_flag && !no_color_env && stdout_is_terminal
}

/// [`wanted`] for this process's stdout and environment.
pub(crate) fn for_stdout(no_color_flag: bool) -> bool {
    use std::io::IsTerminal as _;
    wanted(
        no_color_flag,
        std::env::var_os("NO_COLOR").is_some(),
        std::io::stdout().is_terminal(),
    )
}

#[cfg(test)]
mod tests {
    use super::wanted;

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
}
