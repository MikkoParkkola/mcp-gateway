// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Whether JSON text is a document `serde_json::from_str::<Value>` accepts,
//! decided without building it (MIK-8774). Read through the same
//! deserializer as `Value`, so surrogates, number range, nesting depth and
//! trailing characters are judged by the same code; the only memory it adds
//! is `serde_json`'s own scratch for one escaped token.

use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

/// The first object key `serde_json`'s `raw_value` feature reads specially:
/// `Value` takes the member's string as a nested JSON document, which stands
/// for the whole object, and accepts no member after it.
const RAW_VALUE_TOKEN: &str = "$serde_json::private::RawValue";

/// `None` when `Value` rejects `text`; otherwise whether the `Value` it would
/// build is an object, an array or a string (the redactor's gate).
pub(crate) fn walkable(text: &str) -> Option<bool> {
    shape(text).map(|shape| matches!(shape, Shape::Container | Shape::String))
}

fn shape(text: &str) -> Option<Shape> {
    let mut de = serde_json::Deserializer::from_str(text);
    let shape = Any.deserialize(&mut de).ok()?;
    de.end().ok()?;
    Some(shape)
}

#[derive(Clone, Copy)]
enum Shape {
    Container,
    String,
    Scalar,
}

/// One value, read and dropped: the shape of the `Value` it would be.
struct Any;

impl<'de> DeserializeSeed<'de> for Any {
    type Value = Shape;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Shape, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Any {
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
        while seq.next_element_seed(Any)?.is_some() {}
        Ok(Shape::Container)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Shape, A::Error> {
        // As `Value`'s visitor: only the first key is classified, and a
        // raw-value member returns at once, so the deserializer's own end of
        // the map rejects any member after it.
        match map.next_key_seed(Key)? {
            Some(true) => {
                let nested: String = map.next_value()?;
                shape(&nested).ok_or_else(|| de::Error::custom("invalid raw value"))
            }
            Some(false) => {
                map.next_value_seed(Any)?;
                while map.next_key_seed(Key)?.is_some() {
                    map.next_value_seed(Any)?;
                }
                Ok(Shape::Container)
            }
            None => Ok(Shape::Container),
        }
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
