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
/// it changed, and the backends it could not edit.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct UrlRewrite {
    pub text: String,
    pub changed: Vec<usize>,
    pub skipped: Vec<String>,
}

/// Rewrite the aliases of every backend, or only of the backends in `only`.
pub(crate) fn rewrite_url_aliases(text: &str, only: Option<&BTreeSet<String>>) -> UrlRewrite {
    let mut lines: Vec<String> = text.split_inclusive('\n').map(str::to_string).collect();
    let mut changed = Vec::new();
    let mut skipped = Vec::new();
    for entry in backend_entries(&lines) {
        if only.is_some_and(|names| !names.contains(&entry.name)) {
            continue;
        }
        if entry.flow || entry.aliases.len() > 1 {
            skipped.push(entry.name);
            continue;
        }
        if entry.has_url {
            // `url` beside an alias is the loader's to refuse, naming both.
            continue;
        }
        if let Some(&(at, alias)) = entry.aliases.first() {
            lines[at] = lines[at].replacen(alias, "url", 1);
            changed.push(at + 1);
        }
    }
    UrlRewrite {
        text: lines.concat(),
        changed,
        skipped,
    }
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

/// The key a mapping line starts with, unquoted.
fn key_of(line: &str) -> Option<String> {
    let body = line.trim_start();
    let (key, _) = body.split_once(':')?;
    let key = key.trim().trim_matches(|c| c == '"' || c == '\'');
    (!key.is_empty() && !key.contains(' ')).then(|| key.to_string())
}

/// The entries of the top-level `backends:` block.
fn backend_entries(lines: &[String]) -> Vec<Entry> {
    let Some(start) = lines
        .iter()
        .position(|l| indent(l) == Some(0) && key_of(l).as_deref() == Some("backends"))
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
            let Some(name) = key_of(line) else { continue };
            let rest = line
                .trim_start()
                .split_once(':')
                .map_or("", |(_, r)| r)
                .trim_start();
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
            match key_of(line).as_deref() {
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
