// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Cut a string to a budget on a character boundary, with a marker (MIK-8667).
//!
//! Compiled into both the library and the binary (`mod truncate;` in each),
//! like `home_dir.rs`, so neither crate widens its API for it.

/// What the budget counts.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Budget {
    /// UTF-8 bytes.
    Bytes(usize),
    /// Characters (`char`s).
    Chars(usize),
}

/// Where the marker sits relative to the budget.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Suffix {
    /// The result, marker included, fits the budget. A marker longer than the
    /// budget is returned whole.
    Within,
    /// The kept text fits the budget; the marker is extra.
    After,
}

/// `s` unchanged when it fits `budget` (at any budget, `""` included);
/// otherwise its longest prefix that fits the room left, cut on a character
/// boundary, followed by `marker`.
pub(crate) fn truncate(s: &str, budget: Budget, marker: &str, placement: Suffix) -> String {
    let cut = match budget {
        Budget::Bytes(n) => {
            if s.len() <= n {
                return s.to_string();
            }
            let room = match placement {
                Suffix::Within => n.saturating_sub(marker.len()),
                Suffix::After => n,
            };
            s.floor_char_boundary(room)
        }
        Budget::Chars(n) => {
            // Bounded scan: the input can be large untrusted text.
            if s.chars().nth(n).is_none() {
                return s.to_string();
            }
            let room = match placement {
                Suffix::Within => n.saturating_sub(marker.chars().count()),
                Suffix::After => n,
            };
            s.char_indices().nth(room).map_or(s.len(), |(i, _)| i)
        }
    };
    let mut out = String::with_capacity(cut + marker.len());
    out.push_str(&s[..cut]);
    out.push_str(marker);
    out
}

#[cfg(test)]
mod tests {
    use super::{Budget, Suffix, truncate};

    #[test]
    fn a_string_that_fits_is_returned_unchanged() {
        assert_eq!(truncate("", Budget::Chars(0), ".", Suffix::Within), "");
        assert_eq!(truncate("x", Budget::Chars(1), ".", Suffix::Within), "x");
        assert_eq!(truncate("", Budget::Bytes(0), "...", Suffix::After), "");
        assert_eq!(
            truncate("héllo", Budget::Bytes(6), "...", Suffix::Within),
            "héllo"
        );
        assert_eq!(
            truncate("héllo", Budget::Chars(5), "...", Suffix::Within),
            "héllo"
        );
    }

    #[test]
    fn bytes_within_keeps_the_result_inside_the_budget() {
        assert_eq!(
            truncate("hello world", Budget::Bytes(8), "...", Suffix::Within),
            "hello..."
        );
        // A multi-byte char at the cut backs off to its start.
        assert_eq!(
            truncate("héllo world", Budget::Bytes(5), "...", Suffix::Within),
            "h..."
        );
        assert_eq!(
            truncate("héllo world", Budget::Bytes(6), "...", Suffix::Within),
            "hé..."
        );
    }

    #[test]
    fn bytes_after_keeps_the_text_inside_the_budget_and_adds_the_marker() {
        assert_eq!(
            truncate("abcdef", Budget::Bytes(4), "...", Suffix::After),
            "abcd..."
        );
        assert_eq!(
            truncate("abcé", Budget::Bytes(4), "…", Suffix::After),
            "abc…"
        );
        assert_eq!(
            truncate("abc", Budget::Bytes(0), "...", Suffix::After),
            "..."
        );
    }

    #[test]
    fn chars_within_counts_the_marker_in_characters() {
        assert_eq!(
            truncate("abcdefgh", Budget::Chars(6), "...", Suffix::Within),
            "abc..."
        );
        assert_eq!(
            truncate("ééééé", Budget::Chars(4), ".", Suffix::Within),
            "ééé."
        );
    }

    #[test]
    fn chars_after_keeps_n_characters_and_adds_the_marker() {
        assert_eq!(
            truncate("ééééé", Budget::Chars(3), "…", Suffix::After),
            "ééé…"
        );
        assert_eq!(
            truncate("abcd", Budget::Chars(3), "...", Suffix::After),
            "abc..."
        );
    }

    #[test]
    fn a_marker_longer_than_the_budget_is_returned_whole_when_cut() {
        assert_eq!(
            truncate("abcdef", Budget::Chars(2), "...", Suffix::Within),
            "..."
        );
        assert_eq!(
            truncate("abcdef", Budget::Bytes(2), "...", Suffix::Within),
            "..."
        );
        // kubernetes widths 0 and 1 give "." as today.
        assert_eq!(truncate("abc", Budget::Chars(0), ".", Suffix::Within), ".");
        assert_eq!(truncate("abc", Budget::Chars(1), ".", Suffix::Within), ".");
    }
}
