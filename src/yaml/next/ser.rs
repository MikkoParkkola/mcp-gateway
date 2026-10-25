// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `to_value`: a serde `Serializer` into the tree, with the replaced
//! backend's shapes (design section 4). A unit variant is its name; a
//! newtype, tuple or struct variant is a `Tagged` value under `!variant`
//! (D5); a one-entry map whose key is a tag written as a tag is a `Tagged`
//! value again, so a tree serializes back to itself.

use std::fmt;

use serde::ser::{self, Impossible, Serialize};

use super::{Error, Mapping, Number, Sequence, Tag, TaggedValue, Value};

/// `value` as a tree.
pub(crate) fn to_value<T: ?Sized + Serialize>(value: &T) -> Result<Value, Error> {
    value.serialize(ValueSerializer)
}

/// The replaced backend's refusal of an empty variant name, which cannot be
/// written as a tag.
fn empty_tag() -> Error {
    Error::message("empty YAML tag is not allowed")
}

fn tagged(tag: &str, value: Value) -> Value {
    Value::Tagged(Box::new(TaggedValue {
        tag: Tag::new(tag),
        value,
    }))
}

pub(crate) struct ValueSerializer;

impl ser::Serializer for ValueSerializer {
    type Ok = Value;
    type Error = Error;
    type SerializeSeq = SerializeArray;
    type SerializeTuple = SerializeArray;
    type SerializeTupleStruct = SerializeArray;
    type SerializeTupleVariant = SerializeTupleVariant;
    type SerializeMap = SerializeMap;
    type SerializeStruct = SerializeStruct;
    type SerializeStructVariant = SerializeStructVariant;

    fn serialize_bool(self, v: bool) -> Result<Value, Error> {
        Ok(Value::Bool(v))
    }
    fn serialize_i8(self, v: i8) -> Result<Value, Error> {
        Ok(Value::Number(Number::from(v)))
    }
    fn serialize_i16(self, v: i16) -> Result<Value, Error> {
        Ok(Value::Number(Number::from(v)))
    }
    fn serialize_i32(self, v: i32) -> Result<Value, Error> {
        Ok(Value::Number(Number::from(v)))
    }
    fn serialize_i64(self, v: i64) -> Result<Value, Error> {
        Ok(Value::Number(Number::from(v)))
    }
    /// Past `i64` and `u64`, a number is kept as its digits.
    fn serialize_i128(self, v: i128) -> Result<Value, Error> {
        if let Ok(v) = u64::try_from(v) {
            self.serialize_u64(v)
        } else if let Ok(v) = i64::try_from(v) {
            self.serialize_i64(v)
        } else {
            Ok(Value::String(v.to_string()))
        }
    }
    fn serialize_u8(self, v: u8) -> Result<Value, Error> {
        Ok(Value::Number(Number::from(v)))
    }
    fn serialize_u16(self, v: u16) -> Result<Value, Error> {
        Ok(Value::Number(Number::from(v)))
    }
    fn serialize_u32(self, v: u32) -> Result<Value, Error> {
        Ok(Value::Number(Number::from(v)))
    }
    fn serialize_u64(self, v: u64) -> Result<Value, Error> {
        Ok(Value::Number(Number::from(v)))
    }
    fn serialize_u128(self, v: u128) -> Result<Value, Error> {
        match u64::try_from(v) {
            Ok(v) => self.serialize_u64(v),
            Err(_) => Ok(Value::String(v.to_string())),
        }
    }
    fn serialize_f32(self, v: f32) -> Result<Value, Error> {
        Ok(Value::Number(Number::from(v)))
    }
    fn serialize_f64(self, v: f64) -> Result<Value, Error> {
        Ok(Value::Number(Number::from(v)))
    }
    fn serialize_char(self, v: char) -> Result<Value, Error> {
        Ok(Value::String(v.to_string()))
    }
    fn serialize_str(self, v: &str) -> Result<Value, Error> {
        Ok(Value::String(v.to_owned()))
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<Value, Error> {
        Ok(Value::Sequence(
            v.iter().map(|&b| Value::Number(Number::from(b))).collect(),
        ))
    }
    fn serialize_none(self) -> Result<Value, Error> {
        Ok(Value::Null)
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Value, Error> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<Value, Error> {
        Ok(Value::Null)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Value, Error> {
        Ok(Value::Null)
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<Value, Error> {
        Ok(Value::String(variant.to_owned()))
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Value, Error> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Value, Error> {
        if variant.is_empty() {
            return Err(empty_tag());
        }
        Ok(tagged(variant, to_value(value)?))
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<SerializeArray, Error> {
        Ok(SerializeArray(Sequence::with_capacity(len.unwrap_or(0))))
    }
    fn serialize_tuple(self, len: usize) -> Result<SerializeArray, Error> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<SerializeArray, Error> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<SerializeTupleVariant, Error> {
        if variant.is_empty() {
            return Err(empty_tag());
        }
        Ok(SerializeTupleVariant {
            tag: variant,
            items: Sequence::with_capacity(len),
        })
    }
    /// A one-entry map may be a tag written back (`TaggedValue`'s form).
    fn serialize_map(self, len: Option<usize>) -> Result<SerializeMap, Error> {
        Ok(if len == Some(1) {
            SerializeMap::CheckForTag
        } else {
            SerializeMap::Untagged {
                mapping: Mapping::new(),
                next_key: None,
            }
        })
    }
    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<SerializeStruct, Error> {
        Ok(SerializeStruct(Mapping::new()))
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<SerializeStructVariant, Error> {
        if variant.is_empty() {
            return Err(empty_tag());
        }
        Ok(SerializeStructVariant {
            tag: variant,
            mapping: Mapping::new(),
        })
    }
}

pub(crate) struct SerializeArray(Sequence);

impl ser::SerializeSeq for SerializeArray {
    type Ok = Value;
    type Error = Error;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, elem: &T) -> Result<(), Error> {
        self.0.push(to_value(elem)?);
        Ok(())
    }
    fn end(self) -> Result<Value, Error> {
        Ok(Value::Sequence(self.0))
    }
}

impl ser::SerializeTuple for SerializeArray {
    type Ok = Value;
    type Error = Error;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, elem: &T) -> Result<(), Error> {
        ser::SerializeSeq::serialize_element(self, elem)
    }
    fn end(self) -> Result<Value, Error> {
        ser::SerializeSeq::end(self)
    }
}

impl ser::SerializeTupleStruct for SerializeArray {
    type Ok = Value;
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        ser::SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<Value, Error> {
        ser::SerializeSeq::end(self)
    }
}

pub(crate) struct SerializeTupleVariant {
    tag: &'static str,
    items: Sequence,
}

impl ser::SerializeTupleVariant for SerializeTupleVariant {
    type Ok = Value;
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        self.items.push(to_value(value)?);
        Ok(())
    }
    fn end(self) -> Result<Value, Error> {
        Ok(tagged(self.tag, Value::Sequence(self.items)))
    }
}

pub(crate) enum SerializeMap {
    /// A one-entry map before its key is seen.
    CheckForTag,
    /// Its one key was a tag.
    Tagged(TaggedValue),
    Untagged {
        mapping: Mapping,
        next_key: Option<Value>,
    },
}

impl SerializeMap {
    /// The map so far as an ordinary mapping: a tag already taken becomes
    /// its `!tag` key again.
    fn untagged(&mut self) -> (&mut Mapping, &mut Option<Value>) {
        if !matches!(self, SerializeMap::Untagged { .. }) {
            let mut mapping = Mapping::new();
            if let SerializeMap::Tagged(tagged) = std::mem::replace(self, SerializeMap::CheckForTag)
            {
                mapping.insert(Value::String(tagged.tag.to_string()), tagged.value);
            }
            *self = SerializeMap::Untagged {
                mapping,
                next_key: None,
            };
        }
        match self {
            SerializeMap::Untagged { mapping, next_key } => (mapping, next_key),
            SerializeMap::CheckForTag | SerializeMap::Tagged(_) => {
                unreachable!("made untagged above")
            }
        }
    }
}

impl ser::SerializeMap for SerializeMap {
    type Ok = Value;
    type Error = Error;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), Error> {
        let key = to_value(key)?;
        *self.untagged().1 = Some(key);
        Ok(())
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Error> {
        let value = to_value(value)?;
        let (mapping, next_key) = self.untagged();
        let key = next_key
            .take()
            .ok_or_else(|| Error::message("serialize_value called before serialize_key"))?;
        mapping.insert(key, value);
        Ok(())
    }

    fn serialize_entry<K: ?Sized + Serialize, V: ?Sized + Serialize>(
        &mut self,
        key: &K,
        value: &V,
    ) -> Result<(), Error> {
        if matches!(self, SerializeMap::CheckForTag)
            && let Ok(tag) = key.serialize(TagProbe)
        {
            *self = SerializeMap::Tagged(TaggedValue {
                tag: Tag::new(tag),
                value: to_value(value)?,
            });
            return Ok(());
        }
        let key = to_value(key)?;
        let value = to_value(value)?;
        self.untagged().0.insert(key, value);
        Ok(())
    }

    fn end(self) -> Result<Value, Error> {
        Ok(match self {
            SerializeMap::CheckForTag => Value::Mapping(Mapping::new()),
            SerializeMap::Tagged(tagged) => Value::Tagged(Box::new(tagged)),
            SerializeMap::Untagged { mapping, .. } => Value::Mapping(mapping),
        })
    }
}

pub(crate) struct SerializeStruct(Mapping);

impl ser::SerializeStruct for SerializeStruct {
    type Ok = Value;
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.0
            .insert(Value::String(key.to_owned()), to_value(value)?);
        Ok(())
    }
    fn end(self) -> Result<Value, Error> {
        Ok(Value::Mapping(self.0))
    }
}

pub(crate) struct SerializeStructVariant {
    tag: &'static str,
    mapping: Mapping,
}

impl ser::SerializeStructVariant for SerializeStructVariant {
    type Ok = Value;
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.mapping
            .insert(Value::String(key.to_owned()), to_value(value)?);
        Ok(())
    }
    fn end(self) -> Result<Value, Error> {
        Ok(tagged(self.tag, Value::Mapping(self.mapping)))
    }
}

/// Accepts only a key written through `collect_str` as `"!"` and then a
/// tag name (how a tag displays), and answers with the name; every other
/// key is refused, and the map writes it as an ordinary key.
struct TagProbe;

fn not_tag() -> Error {
    Error::message("not a tag")
}

macro_rules! refuse {
    ($($method:ident($($arg:ty),*))*) => {$(
        fn $method(self, $(_: $arg),*) -> Result<String, Error> {
            Err(not_tag())
        }
    )*};
}

impl ser::Serializer for TagProbe {
    type Ok = String;
    type Error = Error;
    type SerializeSeq = Impossible<String, Error>;
    type SerializeTuple = Impossible<String, Error>;
    type SerializeTupleStruct = Impossible<String, Error>;
    type SerializeTupleVariant = Impossible<String, Error>;
    type SerializeMap = Impossible<String, Error>;
    type SerializeStruct = Impossible<String, Error>;
    type SerializeStructVariant = Impossible<String, Error>;

    refuse!(
        serialize_bool(bool) serialize_i8(i8) serialize_i16(i16) serialize_i32(i32)
        serialize_i64(i64) serialize_i128(i128) serialize_u8(u8) serialize_u16(u16)
        serialize_u32(u32) serialize_u64(u64) serialize_u128(u128) serialize_f32(f32)
        serialize_f64(f64) serialize_char(char) serialize_str(&str) serialize_bytes(&[u8])
        serialize_none() serialize_unit() serialize_unit_struct(&'static str)
        serialize_unit_variant(&'static str, u32, &'static str)
    );

    fn serialize_some<T: ?Sized + Serialize>(self, _value: &T) -> Result<String, Error> {
        Err(not_tag())
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _value: &T,
    ) -> Result<String, Error> {
        Err(not_tag())
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<String, Error> {
        Err(not_tag())
    }
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        Err(not_tag())
    }
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Error> {
        Err(not_tag())
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        Err(not_tag())
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        Err(not_tag())
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Error> {
        Err(not_tag())
    }
    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Error> {
        Err(not_tag())
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        Err(not_tag())
    }

    /// `"!"` written on its own and then a name is a tag; anything else is
    /// not.
    fn collect_str<T: ?Sized + fmt::Display>(self, value: &T) -> Result<String, Error> {
        enum Probe {
            Empty,
            Bang,
            Tag(String),
            NotTag,
        }
        impl fmt::Write for Probe {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                if s.is_empty() {
                    return Ok(());
                }
                *self = match std::mem::replace(self, Probe::NotTag) {
                    Probe::Empty if s == "!" => Probe::Bang,
                    Probe::Bang => Probe::Tag(s.to_owned()),
                    Probe::Tag(mut tag) => {
                        tag.push_str(s);
                        Probe::Tag(tag)
                    }
                    Probe::Empty | Probe::NotTag => Probe::NotTag,
                };
                Ok(())
            }
        }
        let mut probe = Probe::Empty;
        fmt::write(&mut probe, format_args!("{value}")).map_err(|_| not_tag())?;
        match probe {
            Probe::Tag(tag) => Ok(tag),
            Probe::Empty | Probe::Bang | Probe::NotTag => Err(not_tag()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Mapping, Tag, TaggedValue, Value};
    use super::to_value;

    #[test]
    fn a_tagged_value_serializes_back_to_itself_and_a_bang_key_does_not() {
        let tagged = Value::Tagged(Box::new(TaggedValue {
            tag: Tag::new("pair"),
            value: Value::from(1_u8),
        }));
        assert_eq!(to_value(&tagged).expect("serializes"), tagged);
        let mut map = Mapping::new();
        map.insert(Value::from("!x"), Value::from(1_u8));
        assert_eq!(
            to_value(&Value::Mapping(map.clone())).expect("serializes"),
            Value::Mapping(map)
        );
    }
}
