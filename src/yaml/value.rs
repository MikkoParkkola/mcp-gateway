// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The YAML tree, owned by the adapter, in the replaced backend's shapes:
//! the same variants, the same accessors (each looks through tags), the
//! same hashing and ordering, so `tests/common/mik_8425_golden.rs` and every
//! call site read it unchanged (plan section 3b).

use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use super::{Mapping, Number, TaggedValue};

pub(crate) type Sequence = Vec<Value>;

#[derive(Clone, Default, PartialEq, PartialOrd)]
pub(crate) enum Value {
    #[default]
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Sequence(Sequence),
    Mapping(Mapping),
    Tagged(Box<TaggedValue>),
}

impl Eq for Value {}

impl Hash for Value {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Value::Null => {}
            Value::Bool(v) => v.hash(state),
            Value::Number(v) => v.hash(state),
            Value::String(v) => v.hash(state),
            Value::Sequence(v) => v.hash(state),
            Value::Mapping(v) => v.hash(state),
            Value::Tagged(v) => v.hash(state),
        }
    }
}

impl Value {
    /// The hash `Value::String(text)` has, without building it: a mapping
    /// looked up by `&str` must land where the string key was stored.
    pub(crate) fn hash_string<H: Hasher>(text: &str, state: &mut H) {
        std::mem::discriminant(&Value::String(String::new())).hash(state);
        text.hash(state);
    }

    /// A total order, used to compare mappings without regard to order:
    /// null, bool, number, string, sequence, mapping, tagged.
    pub(crate) fn total_cmp(&self, other: &Self) -> Ordering {
        fn rank(v: &Value) -> u8 {
            match v {
                Value::Null => 0,
                Value::Bool(_) => 1,
                Value::Number(_) => 2,
                Value::String(_) => 3,
                Value::Sequence(_) => 4,
                Value::Mapping(_) => 5,
                Value::Tagged(_) => 6,
            }
        }
        match (self, other) {
            (Value::Bool(a), Value::Bool(b)) => a.cmp(b),
            (Value::Number(a), Value::Number(b)) => a.total_cmp(b),
            (Value::String(a), Value::String(b)) => a.cmp(b),
            (Value::Sequence(a), Value::Sequence(b)) => a
                .iter()
                .zip(b)
                .map(|(x, y)| x.total_cmp(y))
                .find(|o| o.is_ne())
                .unwrap_or_else(|| a.len().cmp(&b.len())),
            (Value::Mapping(a), Value::Mapping(b)) => a
                .iter()
                .zip(b)
                .map(|((ak, av), (bk, bv))| ak.total_cmp(bk).then_with(|| av.total_cmp(bv)))
                .find(|o| o.is_ne())
                .unwrap_or_else(|| a.len().cmp(&b.len())),
            (Value::Tagged(a), Value::Tagged(b)) => {
                a.tag.cmp(&b.tag).then_with(|| a.value.total_cmp(&b.value))
            }
            _ => rank(self).cmp(&rank(other)),
        }
    }

    /// The value under every tag.
    pub(crate) fn untag(self) -> Self {
        let mut cur = self;
        while let Value::Tagged(tagged) = cur {
            cur = tagged.value;
        }
        cur
    }

    pub(crate) fn untag_ref(&self) -> &Self {
        let mut cur = self;
        while let Value::Tagged(tagged) = cur {
            cur = &tagged.value;
        }
        cur
    }

    pub(crate) fn untag_mut(&mut self) -> &mut Self {
        let mut cur = self;
        while let Value::Tagged(tagged) = cur {
            cur = &mut tagged.value;
        }
        cur
    }

    pub(crate) fn is_null(&self) -> bool {
        matches!(self.untag_ref(), Value::Null)
    }

    pub(crate) fn as_null(&self) -> Option<()> {
        self.is_null().then_some(())
    }

    pub(crate) fn as_bool(&self) -> Option<bool> {
        match self.untag_ref() {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub(crate) fn is_bool(&self) -> bool {
        self.as_bool().is_some()
    }

    pub(crate) fn is_number(&self) -> bool {
        matches!(self.untag_ref(), Value::Number(_))
    }

    fn number(&self) -> Option<&Number> {
        match self.untag_ref() {
            Value::Number(n) => Some(n),
            _ => None,
        }
    }

    pub(crate) fn as_i64(&self) -> Option<i64> {
        self.number().and_then(Number::as_i64)
    }

    pub(crate) fn is_i64(&self) -> bool {
        self.as_i64().is_some()
    }

    pub(crate) fn as_u64(&self) -> Option<u64> {
        self.number().and_then(Number::as_u64)
    }

    pub(crate) fn is_u64(&self) -> bool {
        self.as_u64().is_some()
    }

    pub(crate) fn as_f64(&self) -> Option<f64> {
        self.number().and_then(Number::as_f64)
    }

    pub(crate) fn is_f64(&self) -> bool {
        self.number().is_some_and(Number::is_f64)
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        match self.untag_ref() {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn is_string(&self) -> bool {
        self.as_str().is_some()
    }

    pub(crate) fn as_sequence(&self) -> Option<&Sequence> {
        match self.untag_ref() {
            Value::Sequence(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn as_sequence_mut(&mut self) -> Option<&mut Sequence> {
        match self.untag_mut() {
            Value::Sequence(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn is_sequence(&self) -> bool {
        self.as_sequence().is_some()
    }

    pub(crate) fn as_mapping(&self) -> Option<&Mapping> {
        match self.untag_ref() {
            Value::Mapping(m) => Some(m),
            _ => None,
        }
    }

    pub(crate) fn as_mapping_mut(&mut self) -> Option<&mut Mapping> {
        match self.untag_mut() {
            Value::Mapping(m) => Some(m),
            _ => None,
        }
    }

    pub(crate) fn is_mapping(&self) -> bool {
        self.as_mapping().is_some()
    }
}

/// What `Value::get` and `value[...]` accept: a position in a sequence (or
/// a number key), or a mapping key.
pub(crate) trait Index {
    fn index_into<'v>(&self, v: &'v Value) -> Option<&'v Value>;
    fn index_into_mut<'v>(&self, v: &'v mut Value) -> Option<&'v mut Value>;
}

impl Index for usize {
    fn index_into<'v>(&self, v: &'v Value) -> Option<&'v Value> {
        match v.untag_ref() {
            Value::Sequence(s) => s.get(*self),
            Value::Mapping(m) => m.get(Value::Number((*self).into())),
            _ => None,
        }
    }
    fn index_into_mut<'v>(&self, v: &'v mut Value) -> Option<&'v mut Value> {
        match v.untag_mut() {
            Value::Sequence(s) => s.get_mut(*self),
            Value::Mapping(m) => m.get_mut(Value::Number((*self).into())),
            _ => None,
        }
    }
}

macro_rules! index_by_key {
    ($($t:ty)*) => {$(
        impl Index for $t {
            fn index_into<'v>(&self, v: &'v Value) -> Option<&'v Value> {
                v.as_mapping().and_then(|m| m.get(self))
            }
            fn index_into_mut<'v>(&self, v: &'v mut Value) -> Option<&'v mut Value> {
                v.as_mapping_mut().and_then(|m| m.get_mut(self))
            }
        }
    )*};
}

index_by_key!(Value str String);

impl<T: ?Sized + Index> Index for &T {
    fn index_into<'v>(&self, v: &'v Value) -> Option<&'v Value> {
        (**self).index_into(v)
    }
    fn index_into_mut<'v>(&self, v: &'v mut Value) -> Option<&'v mut Value> {
        (**self).index_into_mut(v)
    }
}

impl Value {
    pub(crate) fn get<I: Index>(&self, index: I) -> Option<&Value> {
        index.index_into(self)
    }

    pub(crate) fn get_mut<I: Index>(&mut self, index: I) -> Option<&mut Value> {
        index.index_into_mut(self)
    }
}

impl<I: Index> std::ops::Index<I> for Value {
    type Output = Value;
    /// A missing key or position reads as null, as the replaced backend's
    /// did.
    fn index(&self, index: I) -> &Value {
        static NULL: Value = Value::Null;
        index.index_into(self).unwrap_or(&NULL)
    }
}

macro_rules! from_number {
    ($($t:ty)*) => {$(
        impl From<$t> for Value {
            fn from(n: $t) -> Self {
                Value::Number(n.into())
            }
        }
    )*};
}

from_number!(i8 i16 i32 i64 isize u8 u16 u32 u64 usize f32 f64);

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(s)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::String(s.to_owned())
    }
}

impl From<Mapping> for Value {
    fn from(m: Mapping) -> Self {
        Value::Mapping(m)
    }
}

impl<T: Into<Value>> From<Vec<T>> for Value {
    fn from(v: Vec<T>) -> Self {
        Value::Sequence(v.into_iter().map(Into::into).collect())
    }
}

impl<T: Into<Value>> FromIterator<T> for Value {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Value::Sequence(iter.into_iter().map(Into::into).collect())
    }
}

impl std::fmt::Debug for Value {
    /// `Null`, `Bool(true)`, `Number(1)`, `String("a")`, `Sequence [..]`,
    /// `Mapping {..}`, and a tagged value's own form.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Null => f.write_str("Null"),
            Value::Bool(b) => write!(f, "Bool({b})"),
            Value::Number(n) => write!(f, "Number({n})"),
            Value::String(s) => write!(f, "String({s:?})"),
            Value::Sequence(s) => {
                f.write_str("Sequence ")?;
                f.debug_list().entries(s).finish()
            }
            Value::Mapping(m) => std::fmt::Debug::fmt(m, f),
            Value::Tagged(t) => std::fmt::Debug::fmt(t, f),
        }
    }
}

impl serde::Serialize for Value {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Value::Null => serializer.serialize_unit(),
            Value::Bool(b) => serializer.serialize_bool(*b),
            Value::Number(n) => n.serialize(serializer),
            Value::String(s) => serializer.serialize_str(s),
            Value::Sequence(s) => s.serialize(serializer),
            Value::Mapping(m) => m.serialize(serializer),
            Value::Tagged(t) => t.serialize(serializer),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Value {
    /// Any YAML value; an enum (a tagged node) becomes `Tagged`, and a
    /// repeated mapping key is refused.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::{self, VariantAccess as _};
        struct ValueVisitor;
        impl<'de> de::Visitor<'de> for ValueVisitor {
            type Value = Value;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any YAML value")
            }
            fn visit_bool<E: de::Error>(self, b: bool) -> Result<Value, E> {
                Ok(Value::Bool(b))
            }
            fn visit_i64<E: de::Error>(self, i: i64) -> Result<Value, E> {
                Ok(Value::Number(i.into()))
            }
            fn visit_u64<E: de::Error>(self, u: u64) -> Result<Value, E> {
                Ok(Value::Number(u.into()))
            }
            fn visit_f64<E: de::Error>(self, f: f64) -> Result<Value, E> {
                Ok(Value::Number(f.into()))
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<Value, E> {
                Ok(Value::String(s.to_owned()))
            }
            fn visit_string<E: de::Error>(self, s: String) -> Result<Value, E> {
                Ok(Value::String(s))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_none<E: de::Error>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_some<D: serde::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
                serde::Deserialize::deserialize(d)
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, data: A) -> Result<Value, A::Error> {
                let de = de::value::SeqAccessDeserializer::new(data);
                Ok(Value::Sequence(serde::Deserialize::deserialize(de)?))
            }
            fn visit_map<A: de::MapAccess<'de>>(self, data: A) -> Result<Value, A::Error> {
                let de = de::value::MapAccessDeserializer::new(data);
                Ok(Value::Mapping(serde::Deserialize::deserialize(de)?))
            }
            fn visit_enum<A: de::EnumAccess<'de>>(self, data: A) -> Result<Value, A::Error> {
                let (tag, contents) = data.variant::<String>()?;
                if tag.is_empty() {
                    return Err(de::Error::custom("empty YAML tag is not allowed"));
                }
                let value = contents.newtype_variant()?;
                Ok(Value::Tagged(Box::new(TaggedValue {
                    tag: super::Tag::new(tag),
                    value,
                })))
            }
        }
        deserializer.deserialize_any(ValueVisitor)
    }
}
