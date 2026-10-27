// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `to_string`'s writer (design section 4, O2a): libyaml's block layout as
//! the replaced backend drove it, byte-equal to the MIG.0 writer goldens.
//! A scalar's indent is its container's plus 2 (a root scalar's is 2); a
//! block mapping at the root sits at 0; a sequence that is a mapping value
//! is indentless (its dashes sit at the mapping's indent).

mod scalar;

use std::fmt::Write as _;

use scalar::{analyze, double_quoted, scalar_text, simple_key_ok, single_quoted};

/// The emitter's double-quoted escaper, for an in-place edit that writes one
/// scalar into existing text.
pub(crate) use scalar::double_quoted as quote_double;

use super::ser::{PAIRS_MARK, PLAIN_MARK, QUOTED_MARK};
use super::tagged::{TaggedValue, nobang};
use super::{Error, Tag, Value};

/// A tag as libyaml writes it: `!` and the name, with every byte outside
/// its URI set written as `%XX` (`!foo%20bar`).
fn tag_text(tag: &Tag) -> String {
    let name = nobang(&tag.string);
    // The non-specific tag `!` has no name after its handle, which libyaml
    // will not write, so it goes in verbatim form: `!<%21>`.
    let verbatim = name == "!";
    let mut out = String::from(if verbatim { "!<" } else { "!" });
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || "-_;/?:@&=+$,.~*'()[]".contains(ch) {
            out.push(ch);
        } else {
            let mut bytes = [0; 4];
            for byte in ch.encode_utf8(&mut bytes).bytes() {
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    if verbatim {
        out.push('>');
    }
    out
}

/// The entries of a `to_string` pairs mark: a map that repeated a key,
/// kept entry by entry as the replaced text serializer wrote it.
fn pairs(v: &Value) -> Option<&[Value]> {
    match v {
        Value::Tagged(t) if t.tag.string == PAIRS_MARK => match &t.value {
            Value::Sequence(entries) => Some(entries),
            _ => None,
        },
        _ => None,
    }
}

/// The text of a `to_string` mark (see `ser::Mode::Text`): a wide integer's
/// digits written plain, or a `char` always quoted.
fn marked(tagged: &TaggedValue, indent: usize) -> Option<String> {
    let Value::String(text) = &tagged.value else {
        return None;
    };
    if tagged.tag.string == PLAIN_MARK {
        Some(text.clone())
    } else if tagged.tag.string == QUOTED_MARK {
        Some(if analyze(text).single {
            single_quoted(text, indent)
        } else {
            double_quoted(text)
        })
    } else {
        None
    }
}

/// A scalar-like node's text at `indent`, and whether it ended on a break;
/// None for a non-empty collection.
fn inline(v: &Value, indent: usize, simple_key: bool) -> Option<(String, bool)> {
    if let Value::Tagged(t) = v
        && let Some(text) = marked(t, indent)
    {
        return Some((text, false));
    }
    Some(match v {
        Value::Null => ("null".into(), false),
        Value::Bool(b) => (b.to_string(), false),
        Value::Number(n) => (n.to_string(), false),
        Value::String(s) => scalar_text(s, simple_key, indent),
        Value::Sequence(s) if s.is_empty() => ("[]".into(), false),
        Value::Mapping(m) if m.is_empty() => ("{}".into(), false),
        _ => return None,
    })
}

fn end_line(out: &mut String, ended_on_break: bool) {
    if !ended_on_break {
        out.push('\n');
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Ctx {
    Top,
    MapValue,
    SeqItem,
    ComplexValue,
}

/// The caller has written `key:`, `:` or `-` (no trailing space), or nothing
/// at Top. `indent` is the container's indent.
fn node(v: &Value, indent: usize, ctx: Ctx, out: &mut String) -> Result<(), Error> {
    let lead = if ctx == Ctx::Top { "" } else { " " };
    let scalar_indent = if ctx == Ctx::Top { 2 } else { indent + 2 };
    if pairs(v).is_some() {
        return match ctx {
            Ctx::Top => block(v, 0, false, out),
            Ctx::MapValue => {
                out.push('\n');
                block(v, indent + 2, false, out)
            }
            Ctx::SeqItem | Ctx::ComplexValue => {
                out.push(' ');
                block(v, indent + 2, true, out)
            }
        };
    }
    if let Value::Tagged(t) = v
        && marked(t, scalar_indent).is_none()
    {
        out.push_str(lead);
        out.push_str(&tag_text(&t.tag));
        if let Some((text, br)) = inline(&t.value, scalar_indent, false) {
            out.push(' ');
            out.push_str(&text);
            end_line(out, br);
            return Ok(());
        }
        out.push('\n');
        // As untagged: a sequence that is a mapping value is indentless.
        let child = match (ctx, &t.value) {
            (Ctx::Top, _) => 0,
            (Ctx::MapValue | Ctx::ComplexValue, Value::Sequence(_)) => indent,
            _ => indent + 2,
        };
        return block(&t.value, child, false, out);
    }
    if let Some((text, br)) = inline(v, scalar_indent, false) {
        out.push_str(lead);
        out.push_str(&text);
        end_line(out, br);
        return Ok(());
    }
    match (v, ctx) {
        (_, Ctx::Top) => block(v, 0, false, out),
        (Value::Mapping(_), Ctx::MapValue) => {
            out.push('\n');
            block(v, indent + 2, false, out)
        }
        (Value::Sequence(_), Ctx::MapValue) => {
            out.push('\n');
            block(v, indent, false, out)
        }
        (_, Ctx::SeqItem | Ctx::ComplexValue) => {
            out.push(' ');
            block(v, indent + 2, true, out)
        }
        _ => Err(Error::message("a scalar in block position")),
    }
}

fn is_simple_key(k: &Value) -> bool {
    match k {
        Value::String(s) => simple_key_ok(s),
        Value::Sequence(s) => s.is_empty(),
        Value::Mapping(m) => m.is_empty(),
        Value::Tagged(t) => {
            marked(t, 0).is_some() && matches!(&t.value, Value::String(s) if simple_key_ok(s))
        }
        _ => true,
    }
}

/// A non-empty collection whose entries sit at `indent`. With `first_inline`
/// the first entry continues the current line (after `- `).
fn block(v: &Value, indent: usize, first_inline: bool, out: &mut String) -> Result<(), Error> {
    let pad = " ".repeat(indent);
    match v {
        Value::Mapping(m) => entries(m.iter(), indent, first_inline, out)?,
        _ if pairs(v).is_some() => {
            let list = pairs(v).unwrap_or_default();
            let mut kv = Vec::with_capacity(list.len());
            for entry in list {
                match entry {
                    Value::Sequence(pair) if pair.len() == 2 => kv.push((&pair[0], &pair[1])),
                    _ => return Err(Error::message("a malformed entry list")),
                }
            }
            entries(kv.into_iter(), indent, first_inline, out)?;
        }
        Value::Sequence(s) => {
            for (i, item) in s.iter().enumerate() {
                if !(i == 0 && first_inline) {
                    out.push_str(&pad);
                }
                out.push('-');
                node(item, indent, Ctx::SeqItem, out)?;
            }
        }
        _ => return Err(Error::message("a scalar in block position")),
    }
    Ok(())
}

/// A mapping's entries at `indent`, in the order given.
fn entries<'v>(
    list: impl Iterator<Item = (&'v Value, &'v Value)>,
    indent: usize,
    first_inline: bool,
    out: &mut String,
) -> Result<(), Error> {
    let pad = " ".repeat(indent);
    for (i, (k, val)) in list.enumerate() {
        if !(i == 0 && first_inline) {
            out.push_str(&pad);
        }
        if is_simple_key(k) {
            let (text, _) = inline(k, indent + 2, true)
                .ok_or_else(|| Error::message("a collection as a simple key"))?;
            out.push_str(&text);
            out.push(':');
        } else {
            // libyaml's complex key: `? key`, then `: value` on its own line.
            out.push('?');
            node(k, indent, Ctx::SeqItem, out)?;
            out.push_str(&pad);
            out.push(':');
            // After `:` of a complex key, a collection value continues
            // the line like a sequence item does.
            node(val, indent, Ctx::ComplexValue, out)?;
            continue;
        }
        node(val, indent, Ctx::MapValue, out)?;
    }
    Ok(())
}

/// `v` as YAML text.
pub(crate) fn emit(v: &Value) -> Result<String, Error> {
    let mut out = String::new();
    node(v, 0, Ctx::Top, &mut out)?;
    Ok(out)
}
