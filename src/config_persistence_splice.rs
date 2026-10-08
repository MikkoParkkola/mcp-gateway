// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Adding, removing or editing one backend in gateway.yaml as a text edit, so
//! the file's comments survive. A re-serialised `Config` drops every comment,
//! including the security warning `init` writes next to `bearer_token`.

use serde_yaml::{Mapping, Value};

use super::eol::{Line, render as render_lines};

use crate::config::Config;

/// The text at `original` with the one backend edit that turns `before` into
/// `config`: `name` added to the top-level `backends:` mapping, removed from
/// it, or edited in place key by key. `None` when the edit cannot be proven
/// right, which sends the caller to the full re-serialisation or a refusal.
/// Proven means: `config` differs from `before` only by `name`, and the
/// edited text parses to the original document with exactly that entry added,
/// removed, or given the changed keys' new values.
pub(super) fn with_backend_edited(
    original: &str,
    before: &Config,
    config: &Config,
    name: &str,
) -> Option<String> {
    if !only_differs_by(before, config, name) {
        return None;
    }
    let mut want: Value = serde_yaml::from_str(original).ok()?;
    let root = want.as_mapping_mut()?;
    let key = Value::from("backends");
    match root.get(&key) {
        None | Some(Value::Null) => {
            root.insert(key.clone(), Value::Mapping(Mapping::new()));
        }
        Some(Value::Mapping(_)) => {}
        Some(_) => return None,
    }
    let backends = root.get_mut(&key)?.as_mapping_mut()?;
    let edited = match (before.backends.get(name), config.backends.get(name)) {
        (None, Some(backend)) => {
            let mut entry_value = serde_yaml::to_value(backend).ok()?;
            super::url_spelling::spell_as_url(entry_value.as_mapping_mut()?);
            let mut entry = Mapping::new();
            entry.insert(name.into(), entry_value.clone());
            backends.insert(name.into(), entry_value);
            splice(original, &serde_yaml::to_string(&entry).ok()?)?
        }
        (Some(_), None) => {
            backends.remove(name)?;
            remove_entry(original, name)?
        }
        (Some(old), Some(new)) => {
            let (Value::Mapping(mut old), Value::Mapping(mut new)) = (
                serde_yaml::to_value(old).ok()?,
                serde_yaml::to_value(new).ok()?,
            ) else {
                return None;
            };
            let raw = backends.get_mut(name)?.as_mapping_mut()?;
            super::url_spelling::follow_file_spelling(raw, &mut old, &mut new);
            // `want` is the file's own spelling of the entry with only the
            // changed keys replaced, never the fully serialised backend.
            apply_delta(raw, &old, &new);
            edit_entry(original, name, &old, &new)?
        }
        (None, None) => return None,
    };
    let got: Value = serde_yaml::from_str(&edited).ok()?;
    // The text must also load as `config` itself: `original` is re-read at
    // write time, and a file another writer changed since `before` was
    // loaded would otherwise be written without `config`'s validation.
    let loaded = serde_json::to_value(Config::from_file_text(&edited).ok()?).ok()?;
    (got == want && loaded == serde_json::to_value(config).ok()?).then_some(edited)
}

/// Whether `config` differs from `before` only by the backend `name`.
fn only_differs_by(before: &Config, config: &Config, name: &str) -> bool {
    let added = |c: &Config| -> Option<serde_json::Value> {
        let mut value = serde_json::to_value(c).ok()?;
        if let Some(backends) = value.get_mut("backends").and_then(|b| b.as_object_mut()) {
            backends.remove(name);
        }
        Some(value)
    };
    matches!((added(before), added(config)), (Some(a), Some(b)) if a == b)
}

/// Append `block` (a one-key YAML mapping) to the top-level `backends:`
/// mapping of `original`, indented as its existing entries are. A file with
/// no such key gets one at the end. Comments that lead the next top-level
/// key stay with that key.
fn splice(original: &str, block: &str) -> Option<String> {
    let lines: Vec<&str> = original.lines().collect();
    let indented = |line: &str| line.starts_with([' ', '\t']);
    let Some(header) = lines.iter().position(|l| l.starts_with("backends:")) else {
        let mut out: Vec<Line> = (0..lines.len()).map(Line::Kept).collect();
        out.push(Line::New("backends:".to_owned()));
        out.extend(block.lines().map(|l| Line::New(format!("  {l}"))));
        return Some(render_lines(original, &out));
    };
    // Only an empty or block-style mapping is edited; flow style such as
    // `backends: {a: ...}` is left to the full rewrite.
    let after_key = lines[header]["backends:".len()..].trim_start();
    let comment = after_key.find('#').map_or("", |at| &after_key[at..]);
    let head = match after_key[..after_key.len() - comment.len()].trim() {
        "" | "{}" => format!(
            "backends:{}{comment}",
            if comment.is_empty() { "" } else { " " }
        ),
        _ => return None,
    };
    let end = lines[header + 1..]
        .iter()
        .position(|l| !l.is_empty() && !indented(l) && !l.starts_with('#'))
        .map_or(lines.len(), |i| header + 1 + i);
    let last = (header + 1..end)
        .rev()
        .find(|&i| indented(lines[i]))
        .unwrap_or(header);
    let child_indent = lines[header + 1..end]
        .iter()
        .find(|l| indented(l) && !l.trim_start().starts_with('#'))
        .map_or("  ", |l| &l[..l.len() - l.trim_start().len()]);

    let mut out: Vec<Line> = (0..header).map(Line::Kept).collect();
    out.push(Line::Replaced(header, head));
    out.extend((header + 1..=last).map(Line::Kept));
    out.extend(
        block
            .lines()
            .map(|l| Line::New(format!("{child_indent}{l}"))),
    );
    out.extend((last + 1..lines.len()).map(Line::Kept));
    Some(render_lines(original, &out))
}

/// Remove the entry `name` from the top-level block-style `backends:`
/// mapping of `original`, with every line it spans. Blank lines and comments
/// that lead the next entry stay. An emptied mapping becomes `backends: {}`.
fn remove_entry(original: &str, name: &str) -> Option<String> {
    let lines: Vec<&str> = original.lines().collect();
    let indented = |line: &str| line.starts_with([' ', '\t']);
    let content = |line: &str| {
        let t = line.trim_start();
        !t.is_empty() && !t.starts_with('#')
    };
    let header = lines.iter().position(|l| l.starts_with("backends:"))?;
    let end = lines[header + 1..]
        .iter()
        .position(|l| !l.is_empty() && !indented(l) && !l.starts_with('#'))
        .map_or(lines.len(), |i| header + 1 + i);
    let child = lines[header + 1..end].iter().find(|l| content(l))?;
    let depth = child.len() - child.trim_start().len();
    let names_entry = |line: &str| {
        let Some(rest) = line.get(depth..) else {
            return false;
        };
        if rest.starts_with([' ', '\t']) {
            return false;
        }
        rest.split_once(':')
            .is_some_and(|(key, _)| key.trim().trim_matches(|c| c == '"' || c == '\'') == name)
    };
    let start = (header + 1..end).find(|&i| names_entry(lines[i]))?;
    // The entry runs to the next line at the child depth or shallower.
    let next = (start + 1..end)
        .find(|&i| content(lines[i]) && lines[i].len() - lines[i].trim_start().len() <= depth)
        .unwrap_or(end);
    // Give back the blank and comment lines that lead whatever follows.
    let mut stop = next;
    while stop > start + 1 && !content(lines[stop - 1]) {
        stop -= 1;
    }

    let mut out: Vec<Line> = (0..start).map(Line::Kept).collect();
    out.extend((stop..lines.len()).map(Line::Kept));
    let emptied = !lines[header + 1..end]
        .iter()
        .enumerate()
        .any(|(k, l)| !(start..stop).contains(&(header + 1 + k)) && content(l));
    if emptied {
        let after_key = lines[header]["backends:".len()..].trim_start();
        let empty = if after_key.starts_with('#') {
            format!("backends: {{}} {after_key}")
        } else if after_key.is_empty() {
            "backends: {}".to_owned()
        } else {
            // An anchor or tag on the header (`backends: &pool # keep`)
            // cannot be carried onto `{}` here; leave it to the caller.
            return None;
        };
        out[header] = Line::Replaced(header, empty);
    }
    Some(render_lines(original, &out))
}

/// The trailing comment of `line` with the blanks before it (`  # why`):
/// a `#` after a blank and outside a quoted scalar. A quote opens a scalar
/// only where a token starts, so the one in `it's` or `say "hi` does not, and
/// `\"` or `''` inside a quoted scalar does not end it. A misread here only
/// matters with a `#` left in the value, which [`edit_block`] refuses.
fn inline_comment(line: &str) -> Option<&str> {
    let mut quote = None;
    let mut prev = ' ';
    // Only blanks since the start, a `:`, or a flow indicator.
    let mut token_start = true;
    let mut chars = line.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        match (quote, c) {
            (None, '\'' | '"') if token_start => quote = Some(c),
            (Some('"'), '\\') => {
                chars.next();
            }
            (Some('\''), '\'') if chars.peek().is_some_and(|&(_, next)| next == '\'') => {
                chars.next();
            }
            (Some(q), _) if c == q => quote = None,
            (None, '#') if prev == ' ' || prev == '\t' => {
                let start = line[..at].trim_end_matches([' ', '\t']).len();
                return Some(&line[start..]);
            }
            _ => {}
        }
        token_start = match c {
            ' ' | '\t' => token_start,
            ':' | '[' | '{' | ',' => true,
            _ => false,
        };
        prev = c;
    }
    None
}

/// Columns of indent before `line`'s first non-blank character.
fn depth(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Whether `line` holds YAML content: neither blank nor a comment line.
fn content(line: &str) -> bool {
    let t = line.trim_start();
    !t.is_empty() && !t.starts_with('#')
}

/// The key `line` names at exactly `at` columns of indent.
fn key_at(line: &str, at: usize) -> Option<&str> {
    let rest = line.get(at..)?;
    if depth(line) != at || rest.starts_with('-') {
        return None;
    }
    let (key, _) = rest.split_once(':')?;
    Some(key.trim().trim_matches(|c| c == '"' || c == '\''))
}

/// The end of the lines the key at `start` spans inside `..end`: up to the
/// next content line at its depth or shallower, less the blank and comment
/// lines that lead that next line.
fn key_span(lines: &[&str], start: usize, end: usize) -> usize {
    let at = depth(lines[start]);
    let next = (start + 1..end)
        .find(|&i| content(lines[i]) && depth(lines[i]) <= at)
        .unwrap_or(end);
    let mut stop = next;
    while stop > start + 1 && !content(lines[stop - 1]) {
        stop -= 1;
    }
    stop
}

/// One text edit: lines `.0..` `.1` replaced by `.2`.
type Edit = (usize, usize, Vec<String>);

/// `key: value` as block YAML, each line led by `pad`.
fn render(key: &Value, value: &Value, pad: &str) -> Option<Vec<String>> {
    let mut one = Mapping::new();
    one.insert(key.clone(), value.clone());
    let text = serde_yaml::to_string(&one).ok()?;
    Some(text.lines().map(|l| format!("{pad}{l}")).collect())
}

/// The edits that turn the block mapping on lines `start..end` from `old`
/// into `new`, key by key, so an unchanged key is never touched. `None` when
/// a comment inside a replaced or removed value could not be kept.
fn edit_block(
    lines: &[&str],
    start: usize,
    end: usize,
    old: &Mapping,
    new: &Mapping,
    edits: &mut Vec<Edit>,
) -> Option<()> {
    let child = (start..end).find(|&i| content(lines[i]))?;
    let at = depth(lines[child]);
    let pad = &lines[child][..at];
    let mut tail = end;
    while tail > start && !content(lines[tail - 1]) {
        tail -= 1;
    }
    let commented = |from: usize, to: usize| lines[from..to].iter().any(|l| l.contains('#'));
    for key in old
        .keys()
        .chain(new.keys().filter(|k| !old.contains_key(*k)))
    {
        let (was, now) = (old.get(key), new.get(key));
        if was == now {
            continue;
        }
        let name = key.as_str()?;
        let Some(line) = (start..end).find(|&i| key_at(lines[i], at) == Some(name)) else {
            // A default the file never spelled out goes at the mapping's end.
            if let Some(now) = now {
                edits.push((tail, tail, render(key, now, pad)?));
            }
            continue;
        };
        let stop = key_span(lines, line, end);
        let colon = at + lines[line][at..].find(':')?;
        let value_text = &lines[line][colon + 1..];
        let comment = inline_comment(value_text);
        let value = &value_text[..value_text.len() - comment.map_or(0, str::len)];
        let block = value.trim().is_empty();
        // The scanner only proposes a comment; the parser decides. A tag,
        // anchor or flow collection can hide a quote from the scanner, and
        // then the "comment" is the rest of the old value: carrying it would
        // leave old (secret) text on the edited line.
        if comment.is_some_and(|comment| !parsed_as_comment(lines, line, comment)) {
            return None;
        }
        match (was, now) {
            // A removed key takes its own line's comment; one inside its
            // value cannot be kept.
            (_, None) if !commented(line + 1, stop) => edits.push((line, stop, Vec::new())),
            (Some(Value::Mapping(was)), Some(Value::Mapping(now))) if block && stop > line + 1 => {
                edit_block(lines, line + 1, stop, was, now, edits)?;
            }
            // A `#` left in the replaced value may be a comment the scanner
            // misread; replacing it could drop that silently, so refuse.
            (_, Some(now)) if !commented(line + 1, stop) && !value.contains('#') => {
                let mut replaced = render(key, now, pad)?;
                if let (Some(first), Some(comment)) = (replaced.first_mut(), comment) {
                    first.push_str(comment);
                }
                edits.push((line, stop, replaced));
            }
            _ => return None,
        }
    }
    Some(())
}

/// Whether the YAML parser reads `comment`, the tail of `lines[line]`, as a
/// comment: the whole document parses the same with and without it, so
/// anchors defined elsewhere still resolve. Text the parser keeps as part of
/// a value is never carried as a comment.
pub(super) fn parsed_as_comment(lines: &[&str], line: usize, comment: &str) -> bool {
    let parse = |text: &[&str]| serde_yaml::from_str::<Value>(&text.join("\n")).ok();
    let mut cut = lines.to_vec();
    cut[line] = &lines[line][..lines[line].len() - comment.len()];
    matches!((parse(lines), parse(&cut)), (Some(with), Some(without)) if with == without)
}

/// The text of `original` with backend `name`'s block entry edited from
/// `old` to `new` in place. Flow style, at either level, gives `None`.
fn edit_entry(original: &str, name: &str, old: &Mapping, new: &Mapping) -> Option<String> {
    let lines: Vec<&str> = original.lines().collect();
    let header = lines.iter().position(|l| l.starts_with("backends:"))?;
    let after_key = &lines[header]["backends:".len()..];
    let comment = inline_comment(after_key).map_or(0, str::len);
    if !after_key[..after_key.len() - comment].trim().is_empty() {
        return None;
    }
    let end = (header + 1..lines.len())
        .find(|&i| content(lines[i]) && depth(lines[i]) == 0)
        .unwrap_or(lines.len());
    let child = (header + 1..end).find(|&i| content(lines[i]))?;
    let at = depth(lines[child]);
    let start = (header + 1..end).find(|&i| key_at(lines[i], at) == Some(name))?;
    let stop = key_span(&lines, start, end);
    let mut edits = Vec::new();
    edit_block(&lines, start + 1, stop, old, new, &mut edits)?;
    // Applied from the bottom up, so each edit's line numbers still hold.
    edits.sort_by_key(|edit| std::cmp::Reverse(edit.0));
    let mut out: Vec<Line> = (0..lines.len()).map(Line::Kept).collect();
    for (from, to, with) in edits {
        // Each written line replaces one source line in order and keeps its
        // ending; lines beyond those are new.
        let written = with.into_iter().enumerate().map(|(k, text)| {
            if from + k < to {
                Line::Replaced(from + k, text)
            } else {
                Line::New(text)
            }
        });
        out.splice(from..to, written);
    }
    Some(render_lines(original, &out))
}

/// `raw`, the file's own spelling of an entry, with the keys that differ
/// between `old` and `new` set to `new`'s values, recursing where both sides
/// are mappings, as [`edit_block`] does in the text.
fn apply_delta(raw: &mut Mapping, old: &Mapping, new: &Mapping) {
    for key in old.keys().chain(new.keys()) {
        let (was, now) = (old.get(key), new.get(key));
        if was == now {
            continue;
        }
        match (was, now) {
            (_, None) => {
                raw.remove(key);
            }
            (Some(Value::Mapping(was)), Some(Value::Mapping(now)))
                if matches!(raw.get(key), Some(Value::Mapping(_))) =>
            {
                if let Some(Value::Mapping(raw)) = raw.get_mut(key) {
                    apply_delta(raw, was, now);
                }
            }
            (_, Some(now)) => {
                raw.insert(key.clone(), now.clone());
            }
        }
    }
}

/// Every backend that differs between `before` and `config` (added, removed,
/// or edited in place), sorted so a multi-backend splice is deterministic.
pub(super) fn changed_backends(before: &Config, config: &Config) -> Vec<String> {
    let value = |b: &crate::config::BackendConfig| serde_json::to_value(b).ok();
    let changed = before
        .backends
        .iter()
        .filter(|(name, b)| {
            config
                .backends
                .get(*name)
                .is_none_or(|c| value(b) != value(c))
        })
        .map(|(name, _)| name)
        .chain(
            config
                .backends
                .keys()
                .filter(|name| !before.backends.contains_key(*name)),
        );
    let mut names: Vec<String> = changed.cloned().collect();
    names.sort();
    names
}

/// `text` with every backend that differs between `before` and `config`
/// spliced in one at a time, each step through [`with_backend_edited`] and
/// its proof. `None` when a step cannot be spliced, when several backends
/// differ and `scope` is `Splice::One` or one of them is a removal, or
/// when `config` differs from `before` outside `backends`.
pub(super) fn with_backends_edited(
    text: &str,
    before: &Config,
    config: &Config,
    scope: super::Splice,
) -> Option<String> {
    let names = changed_backends(before, config);
    // Several changes are spliced only under `Splice::NoRemoval` and only when
    // none is a removal (setup and discovery add backends, and discovery
    // replaces a same-named one). A removal among several is what a stale
    // `config` looks like after another writer added a backend, and under
    // `Splice::One` an extra addition is what it looks like after another
    // writer removed one. Either takes the ordinary path:
    // refused when comments would be lost, otherwise the full rewrite, last
    // writer wins (MIK-8042 tracks a base-revision check).
    if names.len() > 1
        && (scope == super::Splice::One || names.iter().any(|n| !config.backends.contains_key(n)))
    {
        return None;
    }
    let mut text = text.to_owned();
    let mut done = before.clone();
    for name in names {
        let mut next = done.clone();
        match config.backends.get(&name) {
            Some(backend) => next.backends.insert(name.clone(), backend.clone()),
            None => next.backends.remove(&name),
        };
        text = with_backend_edited(&text, &done, &next, &name)?;
        done = next;
    }
    let value = |c: &Config| serde_json::to_value(c).ok();
    matches!((value(&done), value(config)), (Some(a), Some(b)) if a == b).then_some(text)
}

/// The refusal for a write that would drop the comments in `text`. Any `#`
/// counts: a false one only refuses a write the splice could not keep. It
/// names line numbers only: a `#` inside a quoted value (`TOKEN: "#secret"`)
/// would otherwise put a credential into an API answer.
pub(super) fn comment_loss(path: &std::path::Path, text: &str) -> String {
    const SHOWN: usize = 5;
    let comments: Vec<String> = text
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains('#'))
        .map(|(n, _)| format!("line {}", n + 1))
        .collect();
    let rest = comments.len().saturating_sub(SHOWN);
    let more = if rest == 0 {
        String::new()
    } else {
        format!(" (and {rest} more)")
    };
    format!(
        "Not saved: this edit cannot be written into {} as a text change (flow style, or a \
         comment inside the changed value), and a full rewrite would drop its comments: {}{more}. \
         Edit the file by hand, or use the CLI with `--force` to rewrite the file \
         without its comments.",
        path.display(),
        comments[..comments.len().min(SHOWN)].join("; ")
    )
}

#[cfg(test)]
mod tests {
    use super::{edit_entry, inline_comment, remove_entry, splice};

    const BLOCK: &str = "new:\n  command: echo\n";

    #[test]
    fn appends_inside_the_mapping_before_the_next_keys_comment() {
        let original = "# top\nbackends:\n    old:\n      command: x  # why\n\n# leads auth\nauth:\n  enabled: true\n";
        let edited = splice(original, BLOCK).expect("block style");
        assert_eq!(
            edited,
            "# top\nbackends:\n    old:\n      command: x  # why\n    new:\n      command: echo\n\n# leads auth\nauth:\n  enabled: true\n"
        );
    }

    #[test]
    fn adds_a_mapping_when_there_is_none() {
        let edited = splice("# only a comment\nserver:\n  port: 1", BLOCK).expect("appends");
        assert_eq!(
            edited,
            // The file ends without a line break, and still does (MIK-8029).
            "# only a comment\nserver:\n  port: 1\nbackends:\n  new:\n    command: echo"
        );
        // A commented-out example is not the mapping.
        let edited = splice("# backends:\n#   x: {}\n", BLOCK).expect("appends");
        assert!(edited.ends_with("#   x: {}\nbackends:\n  new:\n    command: echo\n"));
    }

    #[test]
    fn fills_an_empty_mapping_and_leaves_flow_style_alone() {
        let edited = splice("backends: {}  # none yet\nauth: {}\n", BLOCK).expect("empty");
        assert_eq!(
            edited,
            "backends: # none yet\n  new:\n    command: echo\nauth: {}\n"
        );
        assert_eq!(splice("backends: {a: {command: x}}\n", BLOCK), None);
    }

    #[test]
    fn a_file_changed_since_it_was_loaded_is_not_spliced() {
        use super::with_backend_edited;
        use crate::config::Config;
        let config_of = |yaml: &str| serde_yaml::from_str::<Config>(yaml).expect("config");
        let before = config_of("backends: {}\n");
        let config = config_of("backends:\n  new:\n    command: echo\n");
        assert!(
            with_backend_edited("backends: {}\n", &before, &config, "new").is_some(),
            "the unchanged file is spliced"
        );
        // Another writer added `other` after `before` was loaded: the edit
        // would write a config nobody validated.
        let changed = "backends:\n  other:\n    command: x\n";
        assert_eq!(with_backend_edited(changed, &before, &config, "new"), None);
    }

    #[test]
    fn removes_one_entry_and_keeps_the_rest() {
        let original = "backends:\n  # a's note\n  a:\n    command: x\n\n  # leads b\n  b:\n    command: y\n# leads auth\nauth: {}\n";
        assert_eq!(
            remove_entry(original, "a").expect("a"),
            "backends:\n  # a's note\n\n  # leads b\n  b:\n    command: y\n# leads auth\nauth: {}\n"
        );
        assert_eq!(
            remove_entry(original, "b").expect("b"),
            "backends:\n  # a's note\n  a:\n    command: x\n\n  # leads b\n# leads auth\nauth: {}\n"
        );
        assert_eq!(remove_entry(original, "missing"), None);
    }

    #[test]
    fn removing_the_last_entry_leaves_an_empty_mapping() {
        assert_eq!(
            remove_entry("backends:  # mine\n  a:\n    command: x\n", "a").expect("a"),
            "backends: {} # mine\n"
        );
        // Bare `backends:` would load as null, not the empty mapping.
        assert_eq!(
            remove_entry("backends:\n  a:\n    command: x\nauth: {}\n", "a").expect("a"),
            "backends: {}\nauth: {}\n"
        );
        // An anchor on the header cannot be kept on `{}`: no splice.
        assert_eq!(
            remove_entry("backends: &pool # keep\n  a:\n    command: x\n", "a"),
            None
        );
    }

    fn map(yaml: &str) -> serde_yaml::Mapping {
        serde_yaml::from_str(yaml).expect("mapping")
    }

    fn edited(original: &str, old: &str, new: &str) -> Option<String> {
        edit_entry(original, "svc", &map(old), &map(new))
    }

    #[test]
    fn the_inline_comment_scanner_skips_quoted_hashes() {
        assert_eq!(inline_comment("a: \"x # y\"  # z"), Some("  # z"));
        assert_eq!(inline_comment("a: x#y"), None);
        assert_eq!(inline_comment("a: x\t# t"), Some("\t# t"));
        // An apostrophe inside a word opens no quote.
        assert_eq!(inline_comment("a: it's old  # kept"), Some("  # kept"));
        // Nor does a quote after a word, and escapes do not end a quote.
        assert_eq!(inline_comment("a: say \"hi  # kept"), Some("  # kept"));
        assert_eq!(
            inline_comment("a: \"x \\\" # y\"  # kept"),
            Some("  # kept")
        );
        assert_eq!(inline_comment("a: 'it''s # y'  # kept"), Some("  # kept"));
    }

    #[test]
    fn a_hash_left_in_a_replaced_value_refuses() {
        let original = "backends:\n  svc:\n    description: \"a # b\"\n";
        let old = "description: \"a # b\"\n";
        assert_eq!(edited(original, old, "description: c\n"), None);
    }

    #[test]
    fn a_tagged_value_with_a_hash_refuses() {
        let original = "backends:\n  svc:\n    env:\n      TOKEN: !!str \"old # secret\"\n";
        let old = "env:\n  TOKEN: \"old # secret\"\n";
        assert_eq!(edited(original, old, "env:\n  TOKEN: new\n"), None);
        let flow = "backends:\n  svc:\n    env: {TOKEN: !!str \"old # secret\"}\n";
        assert_eq!(edited(flow, old, "env:\n  TOKEN: new\n"), None);
        let sequence = "backends:\n  svc:\n    args: [!!str \"old # secret\"]\n";
        let old = "args: [\"old # secret\"]\n";
        assert_eq!(edited(sequence, old, "args: [new]\n"), None);
    }

    #[test]
    fn a_real_comment_after_a_tag_or_alias_is_kept() {
        let tagged = "backends:\n  svc:\n    env:\n      TOKEN: !!str \"old\"  # keep\n";
        assert_eq!(
            edited(tagged, "env:\n  TOKEN: old\n", "env:\n  TOKEN: new\n"),
            Some("backends:\n  svc:\n    env:\n      TOKEN: new  # keep\n".to_owned())
        );
        // The alias resolves only in the whole document.
        let aliased = "x: &shared {A: one}\nbackends:\n  svc:\n    env: *shared  # keep\n";
        assert_eq!(
            edited(aliased, "env:\n  A: one\n", "env:\n  A: one\n  B: two\n"),
            Some(
                "x: &shared {A: one}\nbackends:\n  svc:\n    env:  # keep\n      A: one\n      B: two\n"
                    .to_owned()
            )
        );
    }

    #[test]
    fn an_edit_touches_only_the_keys_that_changed() {
        let original = "backends:\n  svc:\n    command: \"x\"  # why\n    description: a\n";
        assert_eq!(
            edited(
                original,
                "command: x\ndescription: a\n",
                "command: x\ndescription: b\n"
            ),
            Some("backends:\n  svc:\n    command: \"x\"  # why\n    description: b\n".to_owned())
        );
    }

    #[test]
    fn an_omitted_default_is_appended_inside_the_entry() {
        let original =
            "backends:\n  svc:\n    command: x\n  # leads other\n  other:\n    command: y\n";
        assert_eq!(
            edited(original, "command: x\nenabled: true\n", "command: x\nenabled: false\n"),
            Some(
                "backends:\n  svc:\n    command: x\n    enabled: false\n  # leads other\n  other:\n    command: y\n"
                    .to_owned()
            )
        );
    }

    #[test]
    fn a_block_mapping_is_edited_key_by_key() {
        let original = "backends:\n  svc:\n    env:\n      # vault\n      A: one\n";
        assert_eq!(
            edited(original, "env:\n  A: one\n", "env:\n  A: one\n  B: two\n"),
            Some(
                "backends:\n  svc:\n    env:\n      # vault\n      A: one\n      B: two\n"
                    .to_owned()
            )
        );
    }

    #[test]
    fn a_comment_inside_a_replaced_or_removed_value_refuses() {
        let original = "backends:\n  svc:\n    secrets:\n      # pinned\n      - a\n";
        assert_eq!(edited(original, "secrets: [a]\n", "secrets: [b]\n"), None);
        assert_eq!(edited(original, "secrets: [a]\n", "{}\n"), None);
        let flow = "backends:\n  svc:\n    env: {\n      # vault\n      A: one\n    }\n";
        assert_eq!(
            edited(flow, "env: {A: one}\n", "env: {A: one, B: two}\n"),
            None
        );
        assert_eq!(
            edited(
                "backends: {svc: {env: {}}}\n",
                "env: {}\n",
                "env: {B: two}\n"
            ),
            None
        );
    }

    #[test]
    fn a_type_change_replaces_the_value_and_keeps_its_inline_comment() {
        let original = "backends:\n  svc:\n    timeout: 5s  # slow host\n";
        assert_eq!(
            edited(original, "timeout: 5s\n", "timeout:\n  secs: 9\n"),
            Some("backends:\n  svc:\n    timeout:  # slow host\n      secs: 9\n".to_owned())
        );
    }

    /// The web UI loaded `a` and `b`, another writer then removed `b`, and the
    /// UI now adds `c`. Two differences on a commented file are refused: a
    /// splice of both would put `b` back.
    #[test]
    fn a_web_ui_write_after_a_concurrent_removal_is_refused() {
        use crate::config::Config;
        use crate::config_persistence::{CommentLoss, Unwritten, write_config_with};
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        let current = "backends:\n  a:  # kept by hand\n    command: a\n";
        crate::gateway::test_helpers::write_owner_only(&path, current).expect("write");
        let stale: Config = serde_yaml::from_str(
            "backends:\n  a: {command: a}\n  b: {command: b}\n  c: {command: c}\n",
        )
        .expect("config");
        let held = crate::config_persistence::lock::lock_config_blocking(
            &path,
            std::time::Instant::now(),
            |_| {},
        )
        .expect("config lock");
        let result = write_config_with(&path, &stale, CommentLoss::Refuse, &held);
        assert!(
            matches!(result, Err(Unwritten::CommentLoss(_))),
            "{result:?}"
        );
        assert_eq!(std::fs::read_to_string(&path).expect("read"), current);
    }

    /// The one public writer: `Ok` when it keeps the comments, otherwise the
    /// refusal as `Err`, naming the lines and leaving the file untouched.
    #[test]
    fn the_preserving_writer_reports_each_outcome() {
        use crate::config::Config;
        use crate::config_persistence::write_config_preserving;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        // Owner-only, as the loader requires (CONFIG.2): a file it refuses to
        // load would be refused for that reason, not the one under test.
        let write = crate::gateway::test_helpers::write_owner_only;
        let flow = "backends: {a: {command: a}}  # kept by hand\n";
        write(&path, flow).expect("write");
        let two: Config = serde_yaml::from_str("backends:\n  a: {command: a}\n  b: {command: b}\n")
            .expect("config");
        let refusal = write_config_preserving(&path, &two).expect_err("refused");
        assert!(
            refusal.starts_with("Not saved:") && refusal.contains("line 1"),
            "{refusal}"
        );
        assert_eq!(std::fs::read_to_string(&path).expect("read"), flow);
        let block = "backends:\n  a:  # kept by hand\n    command: a\n";
        write(&path, block).expect("write");
        assert_eq!(write_config_preserving(&path, &two), Ok(()));
        assert!(
            std::fs::read_to_string(&path)
                .expect("read")
                .contains("# kept by hand")
        );
    }
}

#[cfg(test)]
#[path = "config_persistence_splice_url_tests.rs"]
mod url_tests;
