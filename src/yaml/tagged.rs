// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A YAML tag and a tagged value, as the replaced backend held them. A tag
//! keeps its spelling but compares, hashes and prints without the leading
//! `!` it may or may not carry, so `!exact` and `exact` are one tag and both
//! print as `!exact`.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

use serde::ser::{Serialize, SerializeMap, Serializer};

use super::Value;

#[derive(Clone)]
pub(crate) struct Tag {
    pub(crate) string: String,
}

/// A value under a tag: `!pair {x: 1}` is the tag `pair` over the mapping.
#[derive(Clone, PartialEq, PartialOrd, Hash, Debug)]
pub(crate) struct TaggedValue {
    pub(crate) tag: Tag,
    pub(crate) value: Value,
}

impl Tag {
    /// # Panics
    ///
    /// On an empty tag, which YAML cannot spell.
    pub(crate) fn new(string: impl Into<String>) -> Self {
        let string = string.into();
        assert!(!string.is_empty(), "empty YAML tag is not allowed");
        Tag { string }
    }
}

/// `tag` without one leading `!`, unless that leaves nothing.
pub(crate) fn nobang(tag: &str) -> &str {
    match tag.strip_prefix('!') {
        Some("") | None => tag,
        Some(rest) => rest,
    }
}

impl PartialEq for Tag {
    fn eq(&self, other: &Tag) -> bool {
        nobang(&self.string) == nobang(&other.string)
    }
}

impl<T: ?Sized + AsRef<str>> PartialEq<T> for Tag {
    fn eq(&self, other: &T) -> bool {
        nobang(&self.string) == nobang(other.as_ref())
    }
}

impl Eq for Tag {}

impl Ord for Tag {
    fn cmp(&self, other: &Self) -> Ordering {
        nobang(&self.string).cmp(nobang(&other.string))
    }
}

impl PartialOrd for Tag {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for Tag {
    fn hash<H: Hasher>(&self, state: &mut H) {
        nobang(&self.string).hash(state);
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "!{}", nobang(&self.string))
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for TaggedValue {
    /// A one-entry map from `!tag` to the value: the form the writer turns
    /// back into a tag.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        struct AsText<'a>(&'a Tag);
        impl Serialize for AsText<'_> {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self.0)
            }
        }
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry(&AsText(&self.tag), &self.value)?;
        map.end()
    }
}
