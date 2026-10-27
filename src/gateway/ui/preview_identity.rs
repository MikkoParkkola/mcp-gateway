// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The name and version a previewed server reports for itself: untrusted
//! display text, cleaned once here for both protocol eras.

use serde_json::Value;

/// The preview's `package` block for a reported `serverInfo` value.
pub(super) fn package(_info: Option<&Value>) -> Value {
    Value::Null
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::package;

    fn name_of(raw: &str) -> Value {
        package(Some(&json!({"name": raw, "version": "1"})))
    }

    #[test]
    fn a_name_at_the_cap_is_whole_and_one_past_it_is_truncated() {
        for (len, truncated) in [(127, false), (128, false), (129, true)] {
            let block = name_of(&"a".repeat(len));
            assert_eq!(
                block["name"].as_str().map(|n| n.chars().count()),
                Some(len.min(128)),
                "{len}"
            );
            assert_eq!(block["truncated"], truncated, "{len}");
        }
    }

    /// The cap counts characters, so a multibyte name is never cut inside one.
    #[test]
    fn a_multibyte_name_is_capped_on_a_character_boundary() {
        let block = name_of(&"ä".repeat(200));
        assert_eq!(block["name"], "ä".repeat(128));
        assert_eq!(block["truncated"], true);
    }

    /// Cc, Cf, Zl and Zp go; ordinary spaces inside the text stay.
    #[test]
    fn controls_formats_and_separators_are_stripped() {
        let block = name_of("\u{feff} my\u{200b} server\u{2029}\u{0085} ");
        assert_eq!(block["name"], "my server");
        assert_eq!(block["truncated"], false);
    }

    #[test]
    fn a_non_object_or_absent_info_is_null() {
        assert_eq!(package(None), Value::Null);
        assert_eq!(package(Some(&json!(["name"]))), Value::Null);
        assert_eq!(
            package(Some(&json!({"name": 1, "version": null}))),
            Value::Null
        );
    }
}
