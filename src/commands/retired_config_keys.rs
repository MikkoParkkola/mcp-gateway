// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway upgrade` deletes the config keys 4.0 removed (MIK-8044) and
//! `meta_mcp.cache_tools` (MIK-8064), in the same single rewrite as the URL
//! keys, keeping every other byte. A key the rewrite cannot prove safe to
//! delete stays, and `upgrade` names it for the operator to delete by hand.

/// What `upgrade`'s rewrite did with one removed key.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Retired {
    /// The file does not set the key.
    #[default]
    Absent,
    /// The key's lines were removed, starting at `line` (1-based), with the
    /// section header at `block` when the section would be left empty.
    Removed { line: usize, block: Option<usize> },
    /// The file sets the key, but it could not go without changing anything
    /// else, so it stays for the operator to delete.
    Left,
}

/// Whether a key that stays still lets the config load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnLoad {
    /// The loader warns and goes on (`meta_mcp.cache_tools`).
    Warns,
    /// The loader refuses the file.
    Refuses,
}

/// The keys `upgrade` deletes, by path; `*` is any backend name. The loader's
/// own lists live in `config::strict_keys`; the per-key rows of
/// `tests/surf2_upgrade_removed_keys.rs` and `tests/c1_unrecognised_config_keys.rs`
/// hold the two equal.
const REMOVED: &[(&[&str], OnLoad)] = &[
    (&["meta_mcp", "cache_tools"], OnLoad::Warns),
    (&["backends", "*", "idle_timeout"], OnLoad::Refuses),
    (&["backends", "*", "circuit_breaker"], OnLoad::Refuses),
    (&["marketplace"], OnLoad::Refuses),
    (&["server", "request_timeout"], OnLoad::Refuses),
    (&["server", "ws_port"], OnLoad::Refuses),
    (&["cost_governance", "currency"], OnLoad::Refuses),
];

/// One removed key the file set, by dotted path, and what became of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Removal {
    pub key: String,
    pub outcome: Retired,
    pub on_load: OnLoad,
}

impl Removal {
    /// Whether the key stays and the loader refuses it.
    pub(crate) fn blocks_load(&self) -> bool {
        self.outcome == Retired::Left && self.on_load == OnLoad::Refuses
    }
}

/// The document as the loader reads it: a repeated key is accepted, the last
/// value winning. Presence is read here; an edit is proven with [`parse`].
pub(crate) fn loose(text: &str) -> Option<serde_yaml::Value> {
    serde_yaml::from_str::<figment::value::Dict>(text)
        .ok()
        .and_then(|dict| serde_yaml::to_value(dict).ok())
}

/// Every concrete path `pattern` names in `doc`, `*` expanded over the
/// mapping keys at that place.
fn concrete(doc: &serde_yaml::Value, pattern: &[&str]) -> Vec<Vec<String>> {
    let Some((head, rest)) = pattern.split_first() else {
        return vec![Vec::new()];
    };
    let Some(map) = doc.as_mapping() else {
        return Vec::new();
    };
    let names: Vec<String> = if *head == "*" {
        map.keys()
            .filter_map(|k| k.as_str().map(str::to_owned))
            .collect()
    } else {
        vec![(*head).to_owned()]
    };
    names
        .into_iter()
        .filter_map(|name| map.get(name.as_str()).map(|child| (name, child)))
        .flat_map(|(name, child)| {
            concrete(child, rest).into_iter().map(move |mut tail| {
                tail.insert(0, name.clone());
                tail
            })
        })
        .collect()
}

/// `text` without every removed key, and what happened to each one set.
pub(crate) fn drop_removed_keys(text: &str) -> (Option<String>, Vec<Removal>) {
    let mut current = text.to_owned();
    let mut report = Vec::new();
    for (pattern, on_load) in REMOVED {
        let paths = loose(&current)
            .map(|doc| concrete(&doc, pattern))
            .unwrap_or_default();
        for path in paths {
            let (after, outcome) = drop_key(&current, &path);
            if let Some(after) = after {
                current = after;
            }
            report.push(Removal {
                key: path.join("."),
                outcome,
                on_load: *on_load,
            });
        }
    }
    ((current != text).then_some(current), report)
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start_matches([' ', '\t']).len()
}

fn is_blank_or_comment(line: &str) -> bool {
    let t = line.trim();
    t.is_empty() || t.starts_with('#')
}

/// The lines of the key that starts at `at`: it and every deeper-indented
/// line after it. Comment and blank lines inside the block go with it; those
/// after its last value line stay, since they may belong to what follows.
fn span(lines: &[&str], at: usize) -> std::ops::RangeInclusive<usize> {
    let own = indent(lines[at]);
    let mut last = at;
    for (i, line) in lines.iter().enumerate().skip(at + 1) {
        if is_blank_or_comment(line) {
            continue;
        }
        if indent(line) <= own {
            break;
        }
        last = i;
    }
    at..=last
}

/// `text` without the key at `path`, and what happened to it. Lines are
/// removed only when a strict parse shows that exactly the key went, and the
/// section it was alone in when that section would be left empty. A bare
/// section header (no comment on it) is the only header that may go. Flow
/// style, a repeated key, or a value the line rule cannot isolate leaves the
/// text as it was.
pub(crate) fn drop_key(text: &str, path: &[String]) -> (Option<String>, Retired) {
    let Some((leaf, parents)) = path.split_last() else {
        return (None, Retired::Absent);
    };
    let pattern: Vec<&str> = path.iter().map(String::as_str).collect();
    if loose(text).is_none_or(|doc| !concrete(&doc, &pattern).contains(&path.to_vec())) {
        return (None, Retired::Absent);
    }
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let key_line = format!("{leaf}:");
    let header = parents.last().map(|p| format!("{p}:"));
    // ponytail: every candidate costs a strict parse, quadratic in file lines;
    // configs are hundreds of lines. Index the candidates if that changes.
    let removed = (0..lines.len())
        .filter(|&i| lines[i].trim_start().starts_with(&key_line))
        .find_map(|at| {
            let lines_out = span(&lines, at);
            // The nearest shallower line above is the section header.
            let bare_header = header.as_ref().and_then(|h| {
                (0..at)
                    .rev()
                    .find(|&i| {
                        !is_blank_or_comment(lines[i]) && indent(lines[i]) < indent(lines[at])
                    })
                    .filter(|&i| lines[i].trim() == h.as_str())
            });
            std::iter::once(None)
                .chain(bare_header.map(Some))
                .find_map(|block| {
                    let after: String = lines
                        .iter()
                        .enumerate()
                        .filter(|&(i, _)| !lines_out.contains(&i) && Some(i) != block)
                        .map(|(_, line)| *line)
                        .collect();
                    only_key_went(text, &after, path).then(|| (after, at + 1, block.map(|h| h + 1)))
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

/// The mapping at `path` in `doc`; the root for an empty path.
fn section<'a>(
    doc: &'a mut serde_yaml::Value,
    path: &[String],
) -> Option<&'a mut serde_yaml::Mapping> {
    path.iter()
        .try_fold(doc, |node, name| {
            node.as_mapping_mut()?.get_mut(name.as_str())
        })?
        .as_mapping_mut()
}

/// Whether `after` parses to exactly `before` without the key at `path`, and
/// without its section when nothing else was in it.
fn only_key_went(before: &str, after: &str, path: &[String]) -> bool {
    let (Some(mut expected), Some(actual)) = (parse(before), parse(after)) else {
        return false;
    };
    let Some((leaf, parents)) = path.split_last() else {
        return false;
    };
    if section(&mut expected, parents)
        .and_then(|m| m.remove(leaf.as_str()))
        .is_none()
    {
        return false;
    }
    if section(&mut expected, parents).is_some_and(|m| m.is_empty())
        && let Some((name, grand)) = parents.split_last()
        && let Some(map) = section(&mut expected, grand)
    {
        map.remove(name.as_str());
    }
    expected == actual
}

#[cfg(test)]
mod tests {
    use super::{Retired, drop_key, drop_removed_keys};

    fn drop_cache_tools(text: &str) -> (Option<String>, Retired) {
        drop_key(text, &["meta_mcp".to_owned(), "cache_tools".to_owned()])
    }

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

    /// T7b (B2): comment and blank lines after a removed key or block stay;
    /// a comment inside a removed block goes with it.
    #[test]
    fn comments_after_a_removed_key_stay_and_inside_it_go() {
        let text = "server:\n  ws_port: 1\n  # the port we serve\n  port: 2\n";
        let (after, _) = drop_removed_keys(text);
        assert_eq!(
            after.as_deref(),
            Some("server:\n  # the port we serve\n  port: 2\n")
        );
        let text = "marketplace:\n  # old\n  plugin_dir: /p\n\n# --- next ---\nbackends: {}\n";
        let (after, _) = drop_removed_keys(text);
        assert_eq!(after.as_deref(), Some("\n# --- next ---\nbackends: {}\n"));
    }

    /// T6c: every backend's copy goes, each named.
    #[test]
    fn every_backend_occurrence_is_removed_and_named() {
        let text = "backends:\n  a:\n    command: y\n    idle_timeout: 1m\n  b:\n    command: z\n    idle_timeout: 2m\n";
        let (after, report) = drop_removed_keys(text);
        assert_eq!(
            after.as_deref(),
            Some("backends:\n  a:\n    command: y\n  b:\n    command: z\n")
        );
        let keys: Vec<&str> = report.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(keys, ["backends.a.idle_timeout", "backends.b.idle_timeout"]);
        assert!(report.iter().all(|r| !r.blocks_load()));
    }

    /// A removed key that stays blocks the load; `cache_tools` does not.
    #[test]
    fn a_key_left_in_flow_style_blocks_the_load_unless_it_only_warns() {
        let (after, report) = drop_removed_keys(
            "server: {ws_port: 1, port: 2}\nmeta_mcp: {cache_tools: false, enabled: true}\n",
        );
        assert_eq!(after, None);
        let blocking: Vec<&str> = report
            .iter()
            .filter(|r| r.blocks_load())
            .map(|r| r.key.as_str())
            .collect();
        assert_eq!(blocking, ["server.ws_port"]);
        assert_eq!(report.len(), 2);
    }
}
