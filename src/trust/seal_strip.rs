// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Removing provenance seals before a redaction. A seal made before a value
//! is redacted carries the digest of the unredacted bytes, so every point
//! that can redact a sealed answer strips its seals first, through this one
//! function.
use serde_json::Value;

/// What [`strip_seals`] did: whether every seal it could see came off, and
/// whether it removed any.
#[derive(Clone, Copy)]
pub(crate) struct Strip {
    pub(crate) complete: bool,
    pub(crate) removed: bool,
}

/// Remove every provenance seal from `value`, at any depth and inside JSON
/// text. Seals in text are the gateway's own chain and playbook steps,
/// written by `serde_json`, so text naming `public_signature` is parsed,
/// unsealed and, only when a seal came off, written back compact (lossless
/// for text `serde_json` wrote). Such text that will not parse makes the
/// strip incomplete. Iterative over each value; text inside text recurses
/// once per level of escaping, and each level doubles the escapes, so the
/// depth stays a few dozen at most.
pub(crate) fn strip_seals(value: &mut Value) -> Strip {
    let mut strip = Strip {
        complete: true,
        removed: false,
    };
    let mut pending = vec![value];
    while let Some(next) = pending.pop() {
        match next {
            Value::Object(object) => {
                if let Some(provenance) = object
                    .get_mut("_meta")
                    .and_then(|meta| meta.get_mut("provenance"))
                    .and_then(Value::as_object_mut)
                {
                    strip.removed |= provenance.remove("public_signature").is_some();
                }
                pending.extend(object.values_mut());
            }
            Value::Array(items) => pending.extend(items.iter_mut()),
            Value::String(text) if text.contains("public_signature") => {
                match serde_json::from_str::<Value>(text) {
                    Ok(mut inner) => {
                        let inside = strip_seals(&mut inner);
                        strip.complete &= inside.complete;
                        if inside.removed {
                            *text = inner.to_string();
                            strip.removed = true;
                        }
                    }
                    Err(_) => strip.complete = false,
                }
            }
            _ => {}
        }
    }
    strip
}

/// [`strip_seals`] over everything but the named top-level members of an
/// object, which are set aside and put back whole. For a member the firewall
/// holds immutable (an interim answer's question and state): it refuses on a
/// finding there and never rewrites it, so a seal inside it cannot be left
/// over redacted bytes, and stripping it would silently change what the
/// backend asked.
pub(crate) fn strip_seals_keeping(value: &mut Value, keep: &[&str]) -> Strip {
    let kept: Vec<(String, Value)> = value.as_object_mut().map_or_else(Vec::new, |object| {
        keep.iter()
            .filter_map(|member| {
                object
                    .remove(*member)
                    .map(|held| ((*member).to_owned(), held))
            })
            .collect()
    });
    let strip = strip_seals(value);
    if let Some(object) = value.as_object_mut() {
        object.extend(kept);
    }
    strip
}
