// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a kept config version is shown: a fresh text built line by line from
//! the parse, so no byte of the stored file is ever copied into it. Only keys
//! and values appear; a secret slot appears as its reference or `<set>`.

use std::fmt::Write as _;

use sha2::{Digest, Sha256};

use crate::config::secret_slot;
use crate::config::secret_values::names_a_credential;
use crate::config_reload::ui_fields::{FIELDS, Seg};
use crate::yaml::{Node, Shape, Step, block_nodes, renderable};

/// Secret slots a credential-like name does not reveal. Here `Seg::Backend`
/// stands for any key and `Seg::Index` for any position. Every secret field
/// of the settings table counts too, read from `FIELDS` itself.
const SLOT_PATHS: &[&[Seg]] = &[
    &[Seg::Key("auth"), Seg::Key("bearer_token")],
    &[
        Seg::Key("auth"),
        Seg::Key("api_keys"),
        Seg::Index,
        Seg::Key("key"),
    ],
    &[
        Seg::Key("auth"),
        Seg::Key("api_keys"),
        Seg::Index,
        Seg::Key("key_sha256"),
    ],
    &[
        Seg::Key("auth"),
        Seg::Key("api_keys"),
        Seg::Index,
        Seg::Key("previous_key_sha256"),
    ],
    &[
        Seg::Key("agent_auth"),
        Seg::Key("agents"),
        Seg::Index,
        Seg::Key("hs256_secret"),
    ],
    &[Seg::Key("key_server"), Seg::Key("admin_token")],
    &[
        Seg::Key("backends"),
        Seg::Backend,
        Seg::Key("oauth"),
        Seg::Key("client_secret"),
    ],
];

/// One rendered line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Line {
    /// The node's path, keys escaped so two paths never print alike.
    pub(crate) path: String,
    /// The whole line as printed.
    pub(crate) text: String,
    /// For a masked line, a digest of its stored value, kept in memory only
    /// to tell whether it changed between two versions. Never printed.
    pub(crate) secret: Option<[u8; 32]>,
}

/// A rendered text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rendered {
    pub(crate) lines: Vec<Line>,
}

impl Rendered {
    /// Every line, each ended by a line break.
    pub(crate) fn text(&self) -> String {
        self.lines.iter().map(|line| line.text.clone() + "\n").collect()
    }
}

/// A text the masker will not render, as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Withheld;

/// The masked rendering of a gateway.yaml text: one line per scalar value
/// and per empty collection, in document order. A text that is not one plain
/// mapping (anchors, aliases, tags, merge keys, collection keys, a parse
/// error, a second document) is withheld whole.
pub(crate) fn rendered_yaml(text: &str) -> Result<Rendered, Withheld> {
    if !renderable(text) {
        return Err(Withheld);
    }
    let nodes = block_nodes(text).map_err(|_| Withheld)?;
    let merge_key = |node: &Node| matches!(node.path.last(), Some(Step::Key(k)) if k == "<<");
    if nodes.iter().any(merge_key) {
        return Err(Withheld);
    }
    match nodes.first().map(|root| root.shape) {
        None | Some(Shape::Scalar { empty: true }) => return Ok(Rendered { lines: Vec::new() }),
        Some(Shape::Mapping) => {}
        Some(_) => return Err(Withheld),
    }
    let mut lines = Vec::new();
    let mut at = 1;
    while let Some(node) = nodes.get(at) {
        let below = nodes[at + 1..]
            .iter()
            .take_while(|n| n.path.len() > node.path.len() && n.path.starts_with(&node.path))
            .count();
        let path = printed_path(&node.path);
        match node.shape {
            Shape::Scalar { empty } => {
                let value = if empty {
                    ""
                } else {
                    node.value.as_deref().unwrap_or_default()
                };
                lines.push(if masked_value(&node.path) {
                    let token = escaped(&secret_slot(value));
                    Line {
                        text: format!("{path}: {token}"),
                        path,
                        secret: Some(Sha256::digest(value.as_bytes()).into()),
                    }
                } else {
                    let shown = escaped(value);
                    let text = if shown.is_empty() {
                        format!("{path}:")
                    } else {
                        format!("{path}: {shown}")
                    };
                    Line {
                        text,
                        path,
                        secret: None,
                    }
                });
            }
            Shape::Mapping | Shape::Sequence if hidden_collection(&node.path) => {
                // One line for the whole collection; nothing under it is read
                // into the output, only into the in-memory digest.
                let mut digest = Sha256::new();
                for n in &nodes[at + 1..=at + below] {
                    digest.update(printed_path(&n.path[node.path.len()..]).as_bytes());
                    digest.update([0]);
                    digest.update(n.value.as_deref().unwrap_or_default().as_bytes());
                    digest.update([0]);
                }
                lines.push(Line {
                    text: format!("{path}: <set>"),
                    path,
                    secret: Some(digest.finalize().into()),
                });
                at += below;
            }
            Shape::Mapping | Shape::Sequence if below == 0 => {
                let empty = if node.shape == Shape::Mapping {
                    "{}"
                } else {
                    "[]"
                };
                lines.push(Line {
                    text: format!("{path}: {empty}"),
                    path,
                    secret: None,
                });
            }
            Shape::Mapping | Shape::Sequence => {}
        }
        at += 1;
    }
    Ok(Rendered { lines })
}

/// The names an env file sets, in file order, each as `NAME=<set>`, read by
/// the gateway's own env-file reader. A file that reader refuses is withheld.
/// The reader substitutes `$NAME` from the process environment, so nothing
/// printed depends on a value.
pub(crate) fn rendered_env(text: &str) -> Result<Rendered, Withheld> {
    let mut lines = Vec::new();
    for item in dotenvy::from_read_iter(std::io::Cursor::new(text.as_bytes())) {
        let (name, value) = item.map_err(|_| Withheld)?;
        let path = escaped(&name);
        lines.push(Line {
            text: format!("{path}=<set>"),
            path,
            secret: Some(Sha256::digest(value.as_bytes()).into()),
        });
    }
    Ok(Rendered { lines })
}

/// Whether a node at `path` (decoded key segments and positions) is a secret
/// slot by the table, whatever its key is named.
pub(crate) fn slot_path(path: &[Step]) -> bool {
    let fits = |pattern: &[Seg]| {
        pattern.len() == path.len()
            && pattern.iter().zip(path).all(|(seg, step)| match (seg, step) {
                (Seg::Key(want), Step::Key(key)) => want == key,
                (Seg::Backend, Step::Key(_)) | (Seg::Index, Step::Index(_)) => true,
                _ => false,
            })
    };
    SLOT_PATHS.iter().any(|pattern| fits(pattern))
        || FIELDS
            .iter()
            .filter(|field| field.secret())
            .any(|field| fits(field.path))
}

/// A collection shown as one `<set>` line: its own key names a credential,
/// or its path is a slot.
fn hidden_collection(path: &[Step]) -> bool {
    matches!(path.last(), Some(Step::Key(key)) if names_a_credential(key)) || slot_path(path)
}

/// A scalar shown through `secret_slot`: a backend's env or header value, a
/// slot path, or a credential-like key as its own key or anywhere below the
/// top-level section.
fn masked_value(path: &[Step]) -> bool {
    let backend_slot = matches!(
        path,
        [Step::Key(top), _, Step::Key(kind), _, ..]
            if top == "backends" && (kind == "env" || kind == "headers")
    );
    let named = path.iter().enumerate().any(|(i, step)| {
        (i > 0 || i + 1 == path.len()) && matches!(step, Step::Key(key) if names_a_credential(key))
    });
    backend_slot || slot_path(path) || named
}

/// A path as printed: keys joined by dots, positions as `[n]`.
fn printed_path(path: &[Step]) -> String {
    let mut out = String::new();
    for step in path {
        match step {
            Step::Index(n) => {
                let _ = write!(out, "[{n}]");
            }
            Step::Key(key) => {
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(&printed_key(key));
            }
        }
    }
    out
}

/// A key as printed: bare when nothing in it could be read as path syntax,
/// else double-quoted with the value escaping plus an escaped quote.
fn printed_key(key: &str) -> String {
    let bare = !key.is_empty()
        && !key.contains(['.', '[', ']', '"', '\\'])
        && !key.contains(": ")
        && !key.chars().any(char::is_control);
    if bare {
        key.to_owned()
    } else {
        format!("\"{}\"", escaped(key).replace('"', "\\\""))
    }
}

/// `text` on one line, reversibly: a backslash doubled, a line break as
/// `\n`, any other control character as `\xHH`.
fn escaped(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if c.is_control() => {
                let _ = write!(out, "\\x{:02x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

/// A masked line of `newer` whose stored value differs from the line at the
/// same path, with the same token, in `older` reads `(changed)`.
// ponytail: linear scan per line; a path index if renderings reach thousands of lines.
pub(crate) fn mark_changed(older: &[Line], newer: &mut [Line]) {
    for line in newer.iter_mut() {
        let Some(digest) = line.secret else {
            continue;
        };
        let rotated = older.iter().any(|old| {
            old.path == line.path && old.text == line.text && old.secret.is_some_and(|d| d != digest)
        });
        if rotated {
            line.text.push_str(" (changed)");
        }
    }
}

#[cfg(tp3)]
#[cfg(test)]
#[path = "history_mask_tests.rs"]
mod tests;
