// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The value-tree edits behind the meaning proof: reaching or creating a slot, and removing a key.

use super::{Mapping, Segment, Value};

/// The node at `path`, creating missing mapping keys and one element past a
/// sequence's end on the way. `None` when a step meets the wrong shape.
pub(super) fn slot_mut<'v>(node: &'v mut Value, path: &[Segment]) -> Option<&'v mut Value> {
    let Some((first, rest)) = path.split_first() else {
        return Some(node);
    };
    let child = match first {
        Segment::Key(key) => {
            if node.is_null() {
                *node = Value::Mapping(Mapping::new());
            }
            let map = node.as_mapping_mut()?;
            if map.get_mut(key.as_str()).is_none() {
                map.insert(Value::from(key.as_str()), Value::Null);
            }
            map.get_mut(key.as_str())?
        }
        Segment::Index(at) => {
            if node.is_null() {
                *node = Value::Sequence(Vec::new());
            }
            let seq = node.as_sequence_mut()?;
            if *at == seq.len() {
                seq.push(Value::Null);
            }
            seq.get_mut(*at)?
        }
    };
    slot_mut(child, rest)
}

/// Remove the key or list element at `path`, if present (later elements
/// shift down), then every mapping on the way that this left empty, and a
/// list it emptied (only `auth.api_keys` gets here). A missing key, or a
/// path into a sequence element that does not exist, changes nothing.
pub(super) fn remove(node: &mut Value, path: &[Segment]) -> bool {
    let Some((first, rest)) = path.split_first() else {
        return false;
    };
    match first {
        Segment::Key(key) => {
            let Some(map) = node.as_mapping_mut() else {
                return false;
            };
            if rest.is_empty() {
                return map.shift_remove(key.as_str()).is_some();
            }
            let Some(child) = map.get_mut(key.as_str()) else {
                return false;
            };
            let removed = remove(child, rest);
            let emptied = child.as_mapping().is_some_and(Mapping::is_empty)
                || child.as_sequence().is_some_and(Vec::is_empty);
            if removed && emptied {
                map.shift_remove(key.as_str());
            }
            removed
        }
        Segment::Index(at) => match node.as_sequence_mut() {
            Some(seq) if rest.is_empty() && *at < seq.len() => {
                seq.remove(*at);
                true
            }
            Some(seq) => seq.get_mut(*at).is_some_and(|child| remove(child, rest)),
            None => false,
        },
    }
}
