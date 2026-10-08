// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway upgrade` deletes `meta_mcp.cache_tools` (MIK-8064), a key
//! nothing ever read, in the same single rewrite as the URL keys, keeping
//! every other byte. A config the rewrite cannot prove safe keeps the key, and
//! the gateway's load warning stays the operator's cue to delete it by hand.

/// `text` without its one-line `meta_mcp.cache_tools` entry, and the
/// 1-based line that held it. `None` when there is no such line, or when
/// removing it would change anything else the file says (a flow-style
/// mapping, a value spread over several lines, or the only key under
/// `meta_mcp`).
pub(crate) fn drop_cache_tools(text: &str) -> Option<(String, usize)> {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let header = lines.iter().position(|l| {
        l.strip_prefix("meta_mcp:")
            .is_some_and(|rest| matches!(rest.trim_start().chars().next(), None | Some('#')))
    })?;
    let at = (header + 1..lines.len())
        .take_while(|&i| {
            let line = lines[i].trim_end();
            line.is_empty() || line.starts_with([' ', '\t']) || line.starts_with('#')
        })
        .find(|&i| lines[i].trim_start().starts_with("cache_tools:"))?;
    let after: String = lines
        .iter()
        .enumerate()
        .filter(|&(i, _)| i != at)
        .map(|(_, line)| *line)
        .collect();
    only_cache_tools_went(text, &after).then_some((after, at + 1))
}

/// Whether `after` parses to exactly `before` without
/// `meta_mcp.cache_tools`, with `meta_mcp` still a mapping.
fn only_cache_tools_went(before: &str, after: &str) -> bool {
    use serde_yaml::Value;
    let (Ok(mut expected), Ok(actual)) = (
        serde_yaml::from_str::<Value>(before),
        serde_yaml::from_str::<Value>(after),
    ) else {
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
    use super::drop_cache_tools;

    #[test]
    fn the_key_line_goes_and_nothing_else() {
        let text = "meta_mcp:\n  enabled: true\n  cache_tools: false  # off\n  cache_ttl: 5m\n";
        let (after, line) = drop_cache_tools(text).expect("removed");
        assert_eq!(after, "meta_mcp:\n  enabled: true\n  cache_ttl: 5m\n");
        assert_eq!(line, 3);
    }

    #[test]
    fn a_file_the_rewrite_cannot_prove_safe_keeps_the_key() {
        for text in [
            "meta_mcp: {cache_tools: false, enabled: true}\n",
            "meta_mcp:\n  cache_tools: false\n",
            "meta_mcp:\n  enabled: true\nother: |\n  cache_tools: false\n",
            "server:\n  port: 1\n",
        ] {
            assert_eq!(drop_cache_tools(text), None, "{text}");
        }
    }

    #[test]
    fn a_lookalike_line_before_the_key_does_not_hide_it() {
        let text =
            "meta_mcp:\n  note: |\n    cache_tools: x\n  enabled: true\n  cache_tools: false\n";
        let (after, line) = drop_cache_tools(text).expect("removed");
        assert_eq!(
            after,
            "meta_mcp:\n  note: |\n    cache_tools: x\n  enabled: true\n"
        );
        assert_eq!(line, 5);
    }

    #[test]
    fn a_crlf_file_loses_the_line_and_its_ending_only() {
        let text = "meta_mcp:\r\n  cache_tools: false\r\n  enabled: true\r\n";
        let (after, line) = drop_cache_tools(text).expect("removed");
        assert_eq!(after, "meta_mcp:\r\n  enabled: true\r\n");
        assert_eq!(line, 2);
    }
}
