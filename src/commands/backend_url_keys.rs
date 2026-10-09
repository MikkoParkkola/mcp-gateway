// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rewrite a backend's `http_url` or `ws_url` as `url` in gateway.yaml text.
//!
//! The rewrite works on the text, line by line, so every comment and every
//! other line stays as it was. It renames a key only where it is a direct
//! field of an entry under `backends:` and that entry has no `url` already.
//! A backend written in flow style (`name: { ... }`) is reported, not edited.

use std::collections::BTreeSet;

/// The result of a rewrite: the new text, the 1-based numbers of the lines
/// it changed, the backends it could not edit, and the backends it left on
/// their alias because the value is not an address of that key's scheme
/// (renaming would switch transport, or leave a `url` that does not load).
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct UrlRewrite {
    pub text: String,
    pub changed: Vec<usize>,
    pub skipped: Vec<String>,
    pub kept: Vec<String>,
    /// What the same rewrite did with the retired `meta_mcp.cache_tools`
    /// (MIK-8064).
    pub retired: super::retired_config_keys::Retired,
}

/// The transport key a `url` stands for, by scheme. A private copy of the
/// library's table, which is not public; a test holds the two equal.
pub(crate) fn transport_key_for(url: &str) -> Option<&'static str> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        Some("http_url")
    } else if lower.starts_with("ws://") || lower.starts_with("wss://") {
        Some("ws_url")
    } else {
        None
    }
}

/// Rewrite the aliases of every backend, or only of the backends in `only`.
pub(crate) fn rewrite_url_aliases(text: &str, only: Option<&BTreeSet<String>>) -> UrlRewrite {
    let mut lines: Vec<String> = text.split_inclusive('\n').map(str::to_string).collect();
    let mut changed = Vec::new();
    let mut skipped = Vec::new();
    let mut kept = Vec::new();
    let mut renamed: Vec<(String, &'static str)> = Vec::new();
    let doc = loader_view(text);
    for entry in backend_entries(&lines) {
        if only.is_some_and(|names| !names.contains(&entry.name)) {
            continue;
        }
        if entry.flow {
            // Placed below from the parsed file, by its value.
            continue;
        }
        if entry.aliases.len() > 1 {
            skipped.push(entry.name);
            continue;
        }
        if entry.has_url {
            // `url` beside an alias is the loader's to refuse, naming both.
            continue;
        }
        if let Some(&(at, alias)) = entry.aliases.first() {
            let value = doc
                .as_ref()
                .and_then(|d| d.get("backends")?.get(entry.name.as_str())?.get(alias))
                .and_then(serde_yaml::Value::as_str);
            let Some(value) = value else {
                // The parsed file has no such key: the line is text inside a
                // value, so the backend needs a hand edit.
                skipped.push(entry.name);
                continue;
            };
            if transport_key_for(value) != Some(alias) {
                // Renaming would switch transport or would not load.
                kept.push(entry.name);
                continue;
            }
            lines[at] = lines[at].replacen(alias, "url", 1);
            changed.push(at + 1);
            renamed.push((entry.name, alias));
        }
    }
    if let Some(doc) = &doc {
        let placed: BTreeSet<String> = renamed
            .iter()
            .map(|(name, _)| name)
            .chain(&skipped)
            .chain(&kept)
            .cloned()
            .collect();
        report_unplaced(doc, &placed, only, &mut skipped, &mut kept);
    }
    let rewritten = lines.concat();
    if !changed.is_empty() && !only_renamed(text, &rewritten, &renamed) {
        // A line that looked like a key was text inside a value. Nothing is
        // saved; each backend involved is reported for a hand edit.
        skipped.extend(renamed.into_iter().map(|(name, _)| name));
        return UrlRewrite {
            text: text.to_string(),
            changed: Vec::new(),
            skipped,
            kept,
            retired: super::retired_config_keys::Retired::Absent,
        };
    }
    UrlRewrite {
        text: rewritten,
        changed,
        skipped,
        kept,
        retired: super::retired_config_keys::Retired::Absent,
    }
}

/// The file as the gateway's loader reads it, where a repeated key keeps its
/// last value. It only decides what to report and which values to test; every
/// edit is still proved against the strict parse in [`only_renamed`].
fn loader_view(text: &str) -> Option<serde_yaml::Value> {
    use figment::providers::Format as _;
    let dict = figment::providers::Yaml::from_str::<figment::value::Dict>(text).ok()?;
    serde_yaml::to_value(dict).ok()
}

/// Report each backend the parsed file gives an older key that the line scan
/// did not place (a flow-style entry, or a flow-style `backends:` map). None
/// is edited: one whose value is not an address of its key's scheme is kept,
/// as a hand edit to `url` would be refused or switch transport; any other is
/// left for a hand edit.
fn report_unplaced(
    doc: &serde_yaml::Value,
    placed: &BTreeSet<String>,
    only: Option<&BTreeSet<String>>,
    skipped: &mut Vec<String>,
    kept: &mut Vec<String>,
) {
    let Some(backends) = doc.get("backends").and_then(serde_yaml::Value::as_mapping) else {
        return;
    };
    for (name, fields) in backends {
        let (Some(name), Some(fields)) = (name.as_str(), fields.as_mapping()) else {
            continue;
        };
        if placed.contains(name)
            || only.is_some_and(|names| !names.contains(name))
            || fields.contains_key("url")
        {
            // `url` beside an alias is the loader's to refuse, naming both.
            continue;
        }
        let aliases: Vec<(&str, Option<&str>)> = ["http_url", "ws_url"]
            .into_iter()
            .filter_map(|alias| fields.get(alias).map(|v| (alias, v.as_str())))
            .collect();
        match aliases.as_slice() {
            [] => {}
            [(alias, Some(value))] if transport_key_for(value) == Some(*alias) => {
                skipped.push(name.to_string());
            }
            [_] => kept.push(name.to_string()),
            _ => skipped.push(name.to_string()),
        }
    }
}

/// Whether `after` parses to exactly `before` with each `(backend, alias)`
/// key renamed `url` and every value, comment-free, unchanged.
fn only_renamed(before: &str, after: &str, renamed: &[(String, &'static str)]) -> bool {
    use serde_yaml::Value;
    let (Ok(mut expected), Ok(actual)) = (
        serde_yaml::from_str::<Value>(before),
        serde_yaml::from_str::<Value>(after),
    ) else {
        return false;
    };
    for (name, alias) in renamed {
        let Some(fields) = expected
            .get_mut("backends")
            .and_then(|b| b.get_mut(name.as_str()))
            .and_then(Value::as_mapping_mut)
        else {
            return false;
        };
        let Some(value) = fields.remove(*alias) else {
            return false;
        };
        fields.insert(Value::from("url"), value);
    }
    expected == actual
}

/// One entry under `backends:`: its name, whether it is written in flow
/// style, whether it has `url`, and the line index of each alias key.
struct Entry {
    name: String,
    flow: bool,
    has_url: bool,
    aliases: Vec<(usize, &'static str)>,
}

/// Indentation of a line, or `None` for a blank or comment-only line.
fn indent(line: &str) -> Option<usize> {
    let body = line.trim_start_matches(' ');
    (!body.trim().is_empty() && !body.starts_with('#')).then(|| line.len() - body.len())
}

/// The key a mapping line starts with, unquoted, and the text after its `:`.
/// As in YAML, a quoted key ends at its closing quote and a plain one at the
/// first `:` that a space or the line end follows, so a name may hold `:`.
fn key_of(line: &str) -> Option<(String, &str)> {
    let body = line.trim_start();
    let (key, rest) = if let Some(quote @ ('"' | '\'')) = body.chars().next() {
        let inner = &body[1..];
        let end = inner.find(quote)?;
        (&inner[..end], inner[end + 1..].trim_start())
    } else {
        let (at, _) = body.char_indices().find(|&(i, c)| {
            c == ':' && body[i + 1..].chars().next().is_none_or(char::is_whitespace)
        })?;
        (body[..at].trim_end(), &body[at..])
    };
    let rest = rest.strip_prefix(':')?;
    // A backend name may hold spaces; a list item is not a key.
    (!key.is_empty() && !key.starts_with('-')).then(|| (key.to_string(), rest.trim_start()))
}

/// The entries of the top-level `backends:` block.
fn backend_entries(lines: &[String]) -> Vec<Entry> {
    let Some(start) = lines
        .iter()
        .position(|l| indent(l) == Some(0) && key_of(l).is_some_and(|(key, _)| key == "backends"))
    else {
        return Vec::new();
    };
    let mut entries: Vec<Entry> = Vec::new();
    let mut entry_indent = None;
    let mut field_indent = None;
    for (at, line) in lines.iter().enumerate().skip(start + 1) {
        let Some(depth) = indent(line) else { continue };
        if depth == 0 {
            break;
        }
        let entry_level = *entry_indent.get_or_insert(depth);
        if depth == entry_level {
            let Some((name, rest)) = key_of(line) else {
                continue;
            };
            entries.push(Entry {
                name,
                flow: rest.starts_with('{'),
                has_url: false,
                aliases: Vec::new(),
            });
            field_indent = None;
        } else if depth > entry_level
            && let Some(entry) = entries.last_mut()
            && depth == *field_indent.get_or_insert(depth)
        {
            match key_of(line).as_ref().map(|(key, _)| key.as_str()) {
                Some("url") => entry.has_url = true,
                Some("http_url") => entry.aliases.push((at, "http_url")),
                Some("ws_url") => entry.aliases.push((at, "ws_url")),
                _ => {}
            }
        }
    }
    entries
}

#[cfg(test)]
#[path = "backend_url_keys_tests.rs"]
mod tests;
