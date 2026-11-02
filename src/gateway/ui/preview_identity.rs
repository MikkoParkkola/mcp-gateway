// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The name and version a previewed server reports for itself: untrusted
//! display text, cleaned once here for both protocol eras.

use serde_json::{Value, json};

use crate::cli_support::display_text;

/// Characters kept of a reported name or version. Counted in characters, so
/// a multibyte name is never cut inside one.
const CAP: usize = 128;

/// The preview's `package` block for a reported `serverInfo` value: each of
/// `name` and `version` cleaned on its own, null when it is missing or not
/// text, and the whole block null when neither survives.
pub(super) fn package(info: Option<&Value>) -> Value {
    let field = |key: &str| {
        info.and_then(|info| info.get(key))
            .and_then(Value::as_str)
            .and_then(|raw| display_text(raw, CAP))
    };
    let (name, version) = (field("name"), field("version"));
    if name.is_none() && version.is_none() {
        return Value::Null;
    }
    let truncated =
        name.as_ref().is_some_and(|(_, cut)| *cut) || version.as_ref().is_some_and(|(_, cut)| *cut);
    json!({
        "name": name.map(|(text, _)| text),
        "version": version.map(|(text, _)| text),
        "source": "reported_by_server",
        "truncated": truncated,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{display_text, package};

    /// The shared hidden-character check drops what can hide or break
    /// text, and nothing else: a backslash is kept.
    #[test]
    fn display_text_keeps_backslashes_and_drops_hidden_characters() {
        assert_eq!(
            display_text("a\\b\u{202e}c\u{2028}d", super::CAP),
            Some(("a\\bcd".to_string(), false))
        );
    }

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
