// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `from_value`: a serde `Deserializer` over a tree the caller already has
//! (design section 3), with the replaced backend's rules. A tagged value
//! is an enum; a string names a unit variant; a mapping is refused where an
//! enum is wanted (G3).

use serde::de::{self, DeserializeSeed, IntoDeserializer as _, Unexpected, Visitor};

use super::{Error, Mapping, TaggedValue, Value, tagged::nobang};

impl Value {
    /// What a serde type error names this value as.
    fn unexpected(&self) -> Unexpected<'_> {
        match self {
            Value::Null => Unexpected::Unit,
            Value::Bool(b) => Unexpected::Bool(*b),
            Value::Number(n) => n.unexpected(),
            Value::String(s) => Unexpected::Str(s),
            Value::Sequence(_) => Unexpected::Seq,
            Value::Mapping(_) => Unexpected::Map,
            Value::Tagged(_) => Unexpected::Enum,
        }
    }

    fn invalid_type(&self, exp: &dyn de::Expected) -> Error {
        de::Error::invalid_type(self.unexpected(), exp)
    }

    fn deserialize_number<'de, V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.untag() {
            Value::Number(n) => n.visit(visitor),
            other => Err(other.invalid_type(&visitor)),
        }
    }
}

/// A sequence's items to `visitor`; items it leaves unread are refused.
fn visit_sequence<'de, V: Visitor<'de>>(items: Vec<Value>, visitor: V) -> Result<V::Value, Error> {
    let len = items.len();
    let mut access = SeqDeserializer(items.into_iter());
    let value = visitor.visit_seq(&mut access)?;
    if access.0.len() == 0 {
        Ok(value)
    } else {
        Err(de::Error::invalid_length(
            len,
            &"fewer elements in sequence",
        ))
    }
}

/// A mapping's entries to `visitor`; entries it leaves unread are refused.
fn visit_mapping<'de, V: Visitor<'de>>(mapping: Mapping, visitor: V) -> Result<V::Value, Error> {
    let len = mapping.len();
    let mut access = MapDeserializer {
        iter: mapping.into_iter(),
        value: None,
    };
    let value = visitor.visit_map(&mut access)?;
    if access.iter.len() == 0 {
        Ok(value)
    } else {
        Err(de::Error::invalid_length(len, &"fewer elements in map"))
    }
}

struct SeqDeserializer(std::vec::IntoIter<Value>);

impl<'de> de::SeqAccess<'de> for SeqDeserializer {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        self.0
            .next()
            .map(|value| seed.deserialize(value))
            .transpose()
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.0.len())
    }
}

struct MapDeserializer {
    iter: indexmap::map::IntoIter<Value, Value>,
    value: Option<Value>,
}

impl<'de> de::MapAccess<'de> for MapDeserializer {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        match self.iter.next() {
            Some((key, value)) => {
                self.value = Some(value);
                seed.deserialize(key).map(Some)
            }
            None => Ok(None),
        }
    }

    fn next_value_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<T::Value, Error> {
        match self.value.take() {
            Some(value) => seed.deserialize(value),
            None => Err(de::Error::custom("value is missing")),
        }
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.iter.len())
    }
}

macro_rules! number {
    ($($method:ident)*) => {$(
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            self.deserialize_number(visitor)
        }
    )*};
}

impl<'de> de::Deserializer<'de> for Value {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self {
            Value::Null => visitor.visit_unit(),
            Value::Bool(b) => visitor.visit_bool(b),
            Value::Number(n) => n.visit(visitor),
            Value::String(s) => visitor.visit_string(s),
            Value::Sequence(items) => visit_sequence(items, visitor),
            Value::Mapping(mapping) => visit_mapping(mapping, visitor),
            Value::Tagged(tagged) => visitor.visit_enum(*tagged),
        }
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.untag() {
            Value::Bool(b) => visitor.visit_bool(b),
            other => Err(other.invalid_type(&visitor)),
        }
    }

    number!(
        deserialize_i8 deserialize_i16 deserialize_i32 deserialize_i64 deserialize_i128
        deserialize_u8 deserialize_u16 deserialize_u32 deserialize_u64 deserialize_u128
        deserialize_f32 deserialize_f64
    );

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_string(visitor)
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_string(visitor)
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.untag() {
            Value::String(s) => visitor.visit_string(s),
            other => Err(other.invalid_type(&visitor)),
        }
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_byte_buf(visitor)
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.untag() {
            Value::String(s) => visitor.visit_string(s),
            Value::Sequence(items) => visit_sequence(items, visitor),
            other => Err(other.invalid_type(&visitor)),
        }
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self {
            Value::Null => visitor.visit_none(),
            _ => visitor.visit_some(self),
        }
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self {
            Value::Null => visitor.visit_unit(),
            _ => Err(self.invalid_type(&visitor)),
        }
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_unit(visitor)
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.untag() {
            Value::Sequence(items) => visit_sequence(items, visitor),
            Value::Null => visit_sequence(Vec::new(), visitor),
            other => Err(other.invalid_type(&visitor)),
        }
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.untag() {
            Value::Mapping(mapping) => visit_mapping(mapping, visitor),
            Value::Null => visit_mapping(Mapping::new(), visitor),
            other => Err(other.invalid_type(&visitor)),
        }
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_map(visitor)
    }

    /// A tagged value names its variant by its tag; a string names a unit
    /// variant; anything else is refused.
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        match self {
            Value::Tagged(tagged) => visitor.visit_enum(*tagged),
            Value::String(variant) => visitor.visit_enum(UnitVariant(variant)),
            other => Err(de::Error::invalid_type(
                other.unexpected(),
                &"a Value::Tagged enum",
            )),
        }
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_string(visitor)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_unit()
    }
}

impl<'de> de::EnumAccess<'de> for TaggedValue {
    type Error = Error;
    type Variant = Value;

    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, Value), Error> {
        let variant = seed.deserialize(nobang(&self.tag.string).into_deserializer())?;
        Ok((variant, self.value))
    }
}

impl<'de> de::VariantAccess<'de> for Value {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        serde::Deserialize::deserialize(self)
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, Error> {
        seed.deserialize(self)
    }

    fn tuple_variant<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value, Error> {
        match self {
            Value::Sequence(items) => visit_sequence(items, visitor),
            other => Err(other.invalid_type(&"tuple variant")),
        }
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        match self {
            Value::Mapping(mapping) => visit_mapping(mapping, visitor),
            other => Err(other.invalid_type(&"struct variant")),
        }
    }
}

/// A string naming a unit variant.
struct UnitVariant(String);

impl<'de> de::EnumAccess<'de> for UnitVariant {
    type Error = Error;
    type Variant = UnitOnly;

    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, UnitOnly), Error> {
        Ok((seed.deserialize(self.0.into_deserializer())?, UnitOnly))
    }
}

struct UnitOnly;

impl<'de> de::VariantAccess<'de> for UnitOnly {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        Ok(())
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, _seed: T) -> Result<T::Value, Error> {
        Err(de::Error::invalid_type(
            Unexpected::UnitVariant,
            &"newtype variant",
        ))
    }

    fn tuple_variant<V: Visitor<'de>>(self, _len: usize, _visitor: V) -> Result<V::Value, Error> {
        Err(de::Error::invalid_type(
            Unexpected::UnitVariant,
            &"tuple variant",
        ))
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Error> {
        Err(de::Error::invalid_type(
            Unexpected::UnitVariant,
            &"struct variant",
        ))
    }
}
