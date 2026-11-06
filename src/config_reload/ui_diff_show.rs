// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The diff as shown, and the rule that keeps it safe: an emitted line is
//! exactly a changed field's key and value (masked for a secret field),
//! a parent key the edit removes, or text the editor wrote; a trailing
//! comment shows as a marker. Any other byte of the file gives up.

use std::ops::Range;

use crate::config_persistence::keyedit::{self, Change, FieldPath, GiveUp, Hunk};
use crate::yaml::Node;

use super::{ShownHunk, UnifiedDiff};

const COMMENT: &str = "# <comment>";
const NEW_SECRET: &str = "<new secret>";

/// One original line as admitted: its shown text, and where its value
/// starts (for the line an edit replaced).
struct Admitted {
    shown: String,
    value_at: Option<usize>,
}

/// `hunks` as shown, or the code to give up with. `secrets` are the paths
/// of secret fields among `changes`.
pub(super) fn diff(
    original: &str,
    changes: &[(FieldPath, Change)],
    secrets: &[FieldPath],
    hunks: &[Hunk],
) -> Result<UnifiedDiff, GiveUp> {
    let lines: Vec<&str> = original
        .split_inclusive('\n')
        .map(|l| l.trim_end_matches(['\n', '\r']))
        .collect();
    let starts: Vec<usize> = original
        .split_inclusive('\n')
        .scan(0, |at, l| {
            let start = *at;
            *at += l.len();
            Some(start)
        })
        .collect();
    let nodes = crate::yaml::block_nodes(original).map_err(|_| GiveUp::Other)?;
    // Any refusal names a secret when the edit touches a secret field.
    let refuse = if secrets.is_empty() {
        GiveUp::Other
    } else {
        GiveUp::SecretSpan
    };
    let mut out = Vec::with_capacity(hunks.len());
    for hunk in hunks {
        let mut old = Vec::with_capacity(hunk.old.len());
        let mut admitted = std::collections::BTreeMap::new();
        for &i in &hunk.old {
            let line = admit(lines[i], starts[i], &nodes, changes, secrets).ok_or(refuse)?;
            old.push(line.shown.clone());
            admitted.insert(i, line);
        }
        let mut new = Vec::with_capacity(hunk.new.len());
        for line in &hunk.new {
            new.push(match line.replaced {
                Some((i, before, after)) => {
                    let was = admitted.get(&i).ok_or(refuse)?;
                    if was.value_at != Some(before) {
                        return Err(refuse);
                    }
                    let value = &line.text[before..line.text.len() - after];
                    let suffix = &lines[i][lines[i].len() - after..];
                    format!(
                        "{}{}{}",
                        &line.text[..before],
                        masked_new(value, changes),
                        tail(suffix).ok_or(refuse)?
                    )
                }
                None => masked_new(&line.text, changes),
            });
        }
        out.push(ShownHunk {
            old_start: hunk.old_start,
            old,
            new_start: hunk.new_start,
            new,
        });
    }
    Ok(UnifiedDiff { hunks: out })
}

/// `text` the editor wrote, with each new secret's slot placeholder shown
/// as `<new secret>`.
fn masked_new(text: &str, changes: &[(FieldPath, Change)]) -> String {
    let mut out = text.to_owned();
    for (_, change) in changes {
        if let Change::Secret(id) = change {
            out = out.replace(&keyedit::slot_text(id), NEW_SECRET);
        }
    }
    out
}

/// What may follow a value on its line: blanks, then at most a comment,
/// shown as a marker. `None` for anything else.
fn tail(rest: &str) -> Option<String> {
    let body = rest.trim_start_matches([' ', '\t']);
    let blanks = &rest[..rest.len() - body.len()];
    if body.is_empty() {
        Some(rest.to_owned())
    } else if body.starts_with('#') && !blanks.is_empty() {
        Some(format!("{blanks}{COMMENT}"))
    } else {
        None
    }
}

/// Original line `line`, starting at byte `at`, as it may be shown, or
/// `None` when it holds a byte the edit does not own.
fn admit(
    line: &str,
    at: usize,
    nodes: &[Node],
    changes: &[(FieldPath, Change)],
    secrets: &[FieldPath],
) -> Option<Admitted> {
    let local = |r: &Range<usize>| Some(r.start.checked_sub(at)?..r.end.checked_sub(at)?);
    let on_line = |r: &Range<usize>| r.start >= at && r.end <= at + line.len();
    // The key of an entry on this line, written `key:` after the indent (and
    // a list item's dash).
    let keyed = nodes.iter().find(|n| n.key.as_ref().is_some_and(on_line))?;
    let key: Range<usize> = local(keyed.key.as_ref()?)?;
    let lead = line[..key.start].trim_start_matches([' ', '\t']);
    if !(lead.is_empty() || lead.trim_end_matches([' ', '\t']) == "-") {
        return None;
    }
    if changes
        .iter()
        .any(|(p, _)| keyedit::is_node_at(&keyed.path, &p.0))
    {
        // A changed field: its value must lie on this line, alone.
        if keyed.end > at + line.len() || !on_line(&keyed.bytes) {
            return None;
        }
        let value: Range<usize> = local(&keyed.bytes)?;
        let between = &line[key.end..value.start];
        if !between.starts_with(':') || !between[1..].chars().all(|c| c == ' ' || c == '\t') {
            return None;
        }
        let text = &line[value.clone()];
        let secret = secrets
            .iter()
            .any(|p| keyedit::is_node_at(&keyed.path, &p.0));
        let shown_value = if secret {
            let literal = crate::yaml::from_str::<crate::yaml::Value>(text).ok()?;
            crate::config::secret_slot(literal.as_str().unwrap_or_default())
        } else {
            text.to_owned()
        };
        // A reference is shown as written once decoded: an escaped newline
        // would print as a line of its own.
        if shown_value.chars().any(char::is_control) {
            return None;
        }
        return Some(Admitted {
            shown: format!(
                "{}{shown_value}{}",
                &line[..value.start],
                tail(&line[value.end..])?
            ),
            value_at: Some(value.start),
        });
    }
    // A parent the edit removes: `key:` alone, its children on later lines.
    let parent = changes.iter().any(|(p, c)| {
        *c == Change::Remove
            && p.0.len() > keyed.path.len()
            && keyedit::is_node_at(&keyed.path, &p.0[..keyed.path.len()])
    });
    let rest = &line[key.end..];
    if parent && rest.starts_with(':') && keyed.end > at + line.len() {
        return Some(Admitted {
            shown: format!("{}:{}", &line[..key.end], tail(&rest[1..])?),
            value_at: None,
        });
    }
    None
}
