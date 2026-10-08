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
    /// The key's line, 1-based, was removed, with the `meta_mcp:` line it
    /// was alone under when that block would be left empty.
    Removed { line: usize, block: Option<usize> },
    /// The file sets the key, but it could not go without changing anything
    /// else, so it stays for the operator to delete.
    Left,
}

/// `text` without `meta_mcp.cache_tools`, and what happened to it. A line
/// is removed only when a strict parse shows that exactly the key went. When
/// it is the only key, the bare `meta_mcp:` line goes too: an empty or absent
/// block loads as the defaults (`Config` and `MetaMcpConfig` are
/// `serde(default)`). A flow-style mapping, a value spread over several lines,
/// or a `meta_mcp:` line carrying a comment leaves the text as it was.
pub(crate) fn drop_cache_tools(text: &str) -> (Option<String>, Retired) {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let header = lines.iter().position(|l| {
        l.strip_prefix("meta_mcp:")
            .is_some_and(|rest| matches!(rest.trim_start().chars().next(), None | Some('#')))
    });
    let candidates: Vec<usize> = header
        .map(|header| {
            (header + 1..lines.len())
                .take_while(|&i| {
                    let line = lines[i].trim_end();
                    line.is_empty() || line.starts_with([' ', '\t']) || line.starts_with('#')
                })
                .filter(|&i| lines[i].trim_start().starts_with("cache_tools:"))
                .collect()
        })
        .unwrap_or_default();
    // Only a bare header may go: one with a comment would lose the comment.
    let bare_header = header.filter(|&h| lines[h].trim_end() == "meta_mcp:");
    // Presence is read as the loader reads it (a repeated key is accepted);
    // an edit still needs the strict parse in `only_cache_tools_went`.
    let sets_key = serde_yaml::from_str::<figment::value::Dict>(text).is_ok_and(|doc| {
        doc.get("meta_mcp")
            .is_some_and(|meta| meta.find_ref("cache_tools").is_some())
    });
    if !sets_key {
        return (None, Retired::Absent);
    }
    // A lookalike line inside a block scalar fails the parse check, so every
    // candidate is tried in turn: alone, then with a bare header.
    let removed = candidates.into_iter().find_map(|at| {
        std::iter::once(None)
            .chain(bare_header.map(Some))
            .find_map(|block| {
                let after: String = lines
                    .iter()
                    .enumerate()
                    .filter(|&(i, _)| i != at && Some(i) != block)
                    .map(|(_, line)| *line)
                    .collect();
                only_cache_tools_went(text, &after).then(|| (after, at + 1, block.map(|h| h + 1)))
            })
    });
    match removed {
        Some((after, line, block)) => (Some(after), Retired::Removed { line, block }),
        None => (None, Retired::Left),
    }
}

fn parse(text: &str) -> Option<serde_yaml::Value> {
    serde_yaml::from_str(text).ok()
}

/// Whether `after` parses to exactly `before` without
/// `meta_mcp.cache_tools`, and without `meta_mcp` when nothing else was in it.
fn only_cache_tools_went(before: &str, after: &str) -> bool {
    use serde_yaml::Value;
    let (Some(mut expected), Some(actual)) = (parse(before), parse(after)) else {
        return false;
    };
    let Some(root) = expected.as_mapping_mut() else {
        return false;
    };
    let Some(meta) = root.get_mut("meta_mcp").and_then(Value::as_mapping_mut) else {
        return false;
    };
    if meta.remove("cache_tools").is_none() {
        return false;
    }
    if meta.is_empty() {
        root.remove("meta_mcp");
    }
    expected == actual
}

#[cfg(test)]
mod tests {
    use super::{Retired, drop_cache_tools};

    fn removed(text: &str) -> (String, usize) {
        match drop_cache_tools(text) {
            (Some(after), Retired::Removed { line, .. }) => (after, line),
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
            "meta_mcp:  # keep this note\n  cache_tools: false\nbackends: {}\n",
            "meta_mcp:\n  enabled: true\n  enabled: true\n  cache_tools: false\n",
            "meta_mcp: {enabled: true, enabled: true, \"cache_tools\": false}\n",
            "!cfg {meta_mcp: {enabled: true, cache_tools: false}}\n",
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
    fn a_key_alone_under_meta_mcp_goes_with_its_empty_block() {
        let text = "# mine\nmeta_mcp:\n  cache_tools: false  # off\nbackends: {}\n";
        let (after, line) = removed(text);
        assert_eq!(after, "# mine\nbackends: {}\n");
        assert_eq!(line, 3);
    }

    #[test]
    fn a_crlf_file_loses_the_line_and_its_ending_only() {
        let text = "meta_mcp:\r\n  cache_tools: false\r\n  enabled: true\r\n";
        let (after, line) = removed(text);
        assert_eq!(after, "meta_mcp:\r\n  enabled: true\r\n");
        assert_eq!(line, 2);
    }
}
