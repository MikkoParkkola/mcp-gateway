// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Whether JSON text is a document `serde_json::from_str::<Value>` accepts,
//! decided without building it (MIK-8774). Read through the same
//! deserializer as `Value`, so surrogates, number range, nesting depth and
//! trailing characters are judged by the same code; the only memory it adds
//! is serde_json's own scratch for one escaped token.

use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

/// The first object key serde_json's `raw_value` feature reads specially.
const RAW_VALUE_TOKEN: &str = "$serde_json::private::RawValue";

/// What [`check`] found in an accepted document.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Document {
    /// The top level is an object, an array or a string (the redactor's gate).
    pub(crate) walkable: bool,
    /// Some object's first key is [`RAW_VALUE_TOKEN`], which `Value` does not
    /// read as an ordinary key: the redactor does not follow such a document.
    pub(crate) raw_value_token: bool,
}

/// `Some` when `text` is one JSON document `Value` would accept.
pub(crate) fn check(text: &str) -> Option<Document> {
    let mut raw_value_token = false;
    let mut de = serde_json::Deserializer::from_str(text);
    let shape = Any {
        token: &mut raw_value_token,
    }
    .deserialize(&mut de)
    .ok()?;
    de.end().ok()?;
    Some(Document {
        walkable: matches!(shape, Shape::Container | Shape::String),
        raw_value_token,
    })
}

enum Shape {
    Container,
    String,
    Scalar,
}

/// One value, read and dropped; sets `token` when an object below it is led
/// by [`RAW_VALUE_TOKEN`].
struct Any<'a> {
    token: &'a mut bool,
}

impl<'de> DeserializeSeed<'de> for Any<'_> {
    type Value = Shape;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Shape, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Any<'_> {
    type Value = Shape;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Shape, E> {
        Ok(Shape::Scalar)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Shape, E> {
        Ok(Shape::Scalar)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Shape, E> {
        Ok(Shape::Scalar)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Shape, E> {
        Ok(Shape::Scalar)
    }
    fn visit_unit<E>(self) -> Result<Shape, E> {
        Ok(Shape::Scalar)
    }
    fn visit_str<E>(self, _: &str) -> Result<Shape, E> {
        Ok(Shape::String)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Shape, A::Error> {
        while seq
            .next_element_seed(Any {
                token: &mut *self.token,
            })?
            .is_some()
        {}
        Ok(Shape::Container)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Shape, A::Error> {
        let mut first = true;
        while let Some(is_token) = map.next_key_seed(Key)? {
            if first && is_token {
                *self.token = true;
            }
            first = false;
            map.next_value_seed(Any {
                token: &mut *self.token,
            })?;
        }
        Ok(Shape::Container)
    }
}

/// An object key, read as a string: whether it is [`RAW_VALUE_TOKEN`].
struct Key;

impl<'de> DeserializeSeed<'de> for Key {
    type Value = bool;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<bool, D::Error> {
        deserializer.deserialize_str(self)
    }
}

impl Visitor<'_> for Key {
    type Value = bool;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object key")
    }

    fn visit_str<E: de::Error>(self, key: &str) -> Result<bool, E> {
        Ok(key == RAW_VALUE_TOKEN)
    }
}

#[cfg(test)]
#[path = "json_valid_tests.rs"]
mod tests;
