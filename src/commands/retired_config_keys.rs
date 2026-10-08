// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway upgrade` deletes `meta_mcp.cache_tools` (MIK-8064), a key
//! nothing ever read, in the same single rewrite as the URL keys, keeping
//! every other byte. A config the rewrite cannot prove safe keeps the key, and
//! `upgrade` names it for the operator to delete by hand.

/// What `upgrade`'s rewrite did with `meta_mcp.cache_tools`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Retired {
    /// The file sets no `meta_mcp.cache_tools`.
    #[default]
    Absent,
    /// The key's line, 1-based, was removed.
    Removed(usize),
    /// The file sets the key, but no single line could go without changing
    /// anything else, so it stays for the operator to delete.
    Left,
}

/// `text` without `meta_mcp.cache_tools`, and what happened to it. A line
/// is removed only when a strict parse shows that exactly the key went; a
/// flow-style mapping, a value spread over several lines, or the only key
/// under `meta_mcp` leaves the text as it was.
pub(crate) fn drop_cache_tools(text: &str) -> (Option<String>, Retired) {
    if !parse(text).is_some_and(|doc| doc["meta_mcp"].get("cache_tools").is_some()) {
        return (None, Retired::Absent);
    }
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let removed = lines
        .iter()
        .position(|l| {
            l.strip_prefix("meta_mcp:")
                .is_some_and(|rest| matches!(rest.trim_start().chars().next(), None | Some('#')))
        })
        .and_then(|header| {
            // A lookalike line inside a block scalar fails the parse check,
            // so every candidate in the block is tried in turn.
            (header + 1..lines.len())
                .take_while(|&i| {
                    let line = lines[i].trim_end();
                    line.is_empty() || line.starts_with([' ', '\t']) || line.starts_with('#')
                })
                .filter(|&i| lines[i].trim_start().starts_with("cache_tools:"))
                .find_map(|at| {
                    let after: String = lines
                        .iter()
                        .enumerate()
                        .filter(|&(i, _)| i != at)
                        .map(|(_, line)| *line)
                        .collect();
                    only_cache_tools_went(text, &after).then_some((after, at + 1))
                })
        });
    match removed {
        Some((after, line)) => (Some(after), Retired::Removed(line)),
        None => (None, Retired::Left),
    }
}

fn parse(text: &str) -> Option<serde_yaml::Value> {
    serde_yaml::from_str(text).ok()
}

/// Whether `after` parses to exactly `before` without
/// `meta_mcp.cache_tools`, with `meta_mcp` still a mapping.
fn only_cache_tools_went(before: &str, after: &str) -> bool {
    use serde_yaml::Value;
    let (Some(mut expected), Some(actual)) = (parse(before), parse(after)) else {
        return false;
    };
    let Some(meta) = expected.get_mut("meta_mcp").and_then(Value::as_mapping_mut) else {
        return false;
    };
    if meta.remove("cache_tools").is_none() || meta.is_empty() {
        return false;
    }
    expected == actual
}

#[cfg(test)]
mod tests {
    use super::{Retired, drop_cache_tools};

    fn removed(text: &str) -> (String, usize) {
        match drop_cache_tools(text) {
            (Some(after), Retired::Removed(line)) => (after, line),
            other => panic!("not removed: {other:?}"),
        }
    }

    #[test]
    fn the_key_line_goes_and_nothing_else() {
        let text = "meta_mcp:\n  enabled: true\n  cache_tools: false  # off\n  cache_ttl: 5m\n";
        let (after, line) = removed(text);
        assert_eq!(after, "meta_mcp:\n  enabled: true\n  cache_ttl: 5m\n");
        assert_eq!(line, 3);
    }

    #[test]
    fn a_file_the_rewrite_cannot_prove_safe_keeps_the_key() {
        for text in [
            "meta_mcp: {cache_tools: false, enabled: true}\n",
            "meta_mcp:\n  cache_tools: false\n",
        ] {
            assert_eq!(drop_cache_tools(text), (None, Retired::Left), "{text}");
        }
        for text in [
            "meta_mcp:\n  enabled: true\nother: |\n  cache_tools: false\n",
            "server:\n  port: 1\n",
            "meta_mcp: [\n",
        ] {
            assert_eq!(drop_cache_tools(text), (None, Retired::Absent), "{text}");
        }
    }

    #[test]
    fn a_lookalike_line_before_the_key_does_not_hide_it() {
        let text =
            "meta_mcp:\n  note: |\n    cache_tools: x\n  enabled: true\n  cache_tools: false\n";
        let (after, line) = removed(text);
        assert_eq!(
            after,
            "meta_mcp:\n  note: |\n    cache_tools: x\n  enabled: true\n"
        );
        assert_eq!(line, 5);
    }

    #[test]
    fn a_crlf_file_loses_the_line_and_its_ending_only() {
        let text = "meta_mcp:\r\n  cache_tools: false\r\n  enabled: true\r\n";
        let (after, line) = removed(text);
        assert_eq!(after, "meta_mcp:\r\n  enabled: true\r\n");
        assert_eq!(line, 2);
    }
}
