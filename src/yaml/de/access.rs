// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The serde access types the typed reader hands a visitor: a sequence's
//! items, a mapping's entries, and an enum's variant.

use serde::de::{self, DeserializeSeed, IntoDeserializer as _, Unexpected, Visitor};

use super::super::Error;
use super::super::rep::{Kind, NodeId};
use super::{CurrentEnum, De, Path};

/// A sequence's items, each read one level down the path.
pub(super) struct SeqAccess<'s, 'a> {
    pub(super) de: &'s mut De<'a>,
    pub(super) items: &'a [NodeId],
    pub(super) next: usize,
}

impl<'de> de::SeqAccess<'de> for SeqAccess<'_, '_> {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        let Some(&id) = self.items.get(self.next) else {
            return Ok(None);
        };
        let index = self.next;
        self.next += 1;
        let de = &mut *self.de;
        let mut item = De {
            document: de.document,
            id,
            budget: &mut *de.budget,
            path: Path::Seq {
                parent: &de.path,
                index,
            },
            depth: de.depth,
            current_enum: None,
        };
        seed.deserialize(&mut item).map(Some)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.items.len() - self.next)
    }
}

/// A mapping's entries in order, a repeated key included: the target
/// decides what a repeat means.
pub(super) struct MapAccess<'s, 'a> {
    pub(super) de: &'s mut De<'a>,
    pub(super) entries: &'a [(NodeId, NodeId)],
    pub(super) next: usize,
}

impl<'de> de::MapAccess<'de> for MapAccess<'_, '_> {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        let Some(&(key, _)) = self.entries.get(self.next) else {
            return Ok(None);
        };
        let de = &mut *self.de;
        let mut key_de = De {
            document: de.document,
            id: key,
            budget: &mut *de.budget,
            path: de.path,
            depth: de.depth,
            current_enum: None,
        };
        seed.deserialize(&mut key_de).map(Some)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
        let (key, value) = self.entries[self.next];
        self.next += 1;
        let de = &mut *self.de;
        // A scalar key names the path; any other key is `?`.
        let key_text = match &de.document.node(key).kind {
            Kind::Scalar { text, .. } => Some(text.as_str()),
            _ => None,
        };
        let path = match key_text {
            Some(key) => Path::Map {
                parent: &de.path,
                key,
            },
            None => Path::Unknown { parent: &de.path },
        };
        let mut value_de = De {
            document: de.document,
            id: value,
            budget: &mut *de.budget,
            path,
            depth: de.depth,
            current_enum: None,
        };
        seed.deserialize(&mut value_de)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.entries.len() - self.next)
    }
}

/// An enum named by a local tag: the tag is the variant, the tagged node
/// its content.
pub(super) struct EnumAccess<'s, 'a> {
    pub(super) de: &'s mut De<'a>,
    pub(super) name: Option<&'static str>,
    pub(super) tag: &'a str,
}

impl<'de, 's, 'a> de::EnumAccess<'de> for EnumAccess<'s, 'a> {
    type Error = Error;
    type Variant = VariantDe<'s, 'a>;

    fn variant_seed<V: DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant), Error> {
        let variant = seed.deserialize(self.tag.into_deserializer())?;
        self.de.current_enum = Some(CurrentEnum {
            name: self.name,
            tag: self.tag,
        });
        Ok((variant, VariantDe { de: self.de }))
    }
}

/// The tagged node, read as a variant's content.
pub(super) struct VariantDe<'s, 'a> {
    pub(super) de: &'s mut De<'a>,
}

impl<'de> de::VariantAccess<'de> for VariantDe<'_, '_> {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        serde::Deserialize::deserialize(&mut *self.de)
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, Error> {
        seed.deserialize(&mut *self.de)
    }

    fn tuple_variant<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value, Error> {
        de::Deserializer::deserialize_seq(&mut *self.de, visitor)
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        de::Deserializer::deserialize_struct(&mut *self.de, "", fields, visitor)
    }
}

/// A unit variant named by a scalar's text, of any style.
pub(super) struct UnitVariantAccess<'s, 'a> {
    pub(super) de: &'s mut De<'a>,
}

impl<'de> de::EnumAccess<'de> for UnitVariantAccess<'_, '_> {
    type Error = Error;
    type Variant = Self;

    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, Self), Error> {
        Ok((seed.deserialize(&mut *self.de)?, self))
    }
}

impl<'de> de::VariantAccess<'de> for UnitVariantAccess<'_, '_> {
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
