// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A YAML mapping, as the replaced backend held it: insertion-ordered, any
//! `Value` as a key, looked up by `&str` without building a key, compared
//! and hashed without regard to order.
//!
//! ponytail: the subset of the replaced `Mapping` API the gateway can
//! reach (no `Entry` API, no capacity controls); the switch commit's
//! compile lists anything missing.

use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};

use indexmap::IndexMap;

use super::Value;

#[derive(Clone, Default, Eq, PartialEq)]
pub(crate) struct Mapping {
    map: IndexMap<Value, Value>,
}

/// A key a lookup accepts: a `Value`, or a string matched against string
/// keys only.
pub(crate) trait Key {
    fn get_in<'m>(&self, map: &'m Mapping) -> Option<&'m Value>;
    fn get_mut_in<'m>(&self, map: &'m mut Mapping) -> Option<&'m mut Value>;
    fn swap_remove_from(&self, map: &mut Mapping) -> Option<Value>;
    fn shift_remove_from(&self, map: &mut Mapping) -> Option<Value>;
}

/// A `&str` that hashes and compares as `Value::String` of itself.
struct StrKey<'a>(&'a str);

impl indexmap::Equivalent<Value> for StrKey<'_> {
    fn equivalent(&self, key: &Value) -> bool {
        matches!(key, Value::String(s) if s == self.0)
    }
}

impl Hash for StrKey<'_> {
    // Must agree with `Value`'s `Hash` for a string.
    fn hash<H: Hasher>(&self, state: &mut H) {
        Value::hash_string(self.0, state);
    }
}

impl Key for Value {
    fn get_in<'m>(&self, map: &'m Mapping) -> Option<&'m Value> {
        map.map.get(self)
    }
    fn get_mut_in<'m>(&self, map: &'m mut Mapping) -> Option<&'m mut Value> {
        map.map.get_mut(self)
    }
    fn swap_remove_from(&self, map: &mut Mapping) -> Option<Value> {
        map.map.swap_remove(self)
    }
    fn shift_remove_from(&self, map: &mut Mapping) -> Option<Value> {
        map.map.shift_remove(self)
    }
}

impl Key for str {
    fn get_in<'m>(&self, map: &'m Mapping) -> Option<&'m Value> {
        map.map.get(&StrKey(self))
    }
    fn get_mut_in<'m>(&self, map: &'m mut Mapping) -> Option<&'m mut Value> {
        map.map.get_mut(&StrKey(self))
    }
    fn swap_remove_from(&self, map: &mut Mapping) -> Option<Value> {
        map.map.swap_remove(&StrKey(self))
    }
    fn shift_remove_from(&self, map: &mut Mapping) -> Option<Value> {
        map.map.shift_remove(&StrKey(self))
    }
}

impl Key for String {
    fn get_in<'m>(&self, map: &'m Mapping) -> Option<&'m Value> {
        self.as_str().get_in(map)
    }
    fn get_mut_in<'m>(&self, map: &'m mut Mapping) -> Option<&'m mut Value> {
        self.as_str().get_mut_in(map)
    }
    fn swap_remove_from(&self, map: &mut Mapping) -> Option<Value> {
        self.as_str().swap_remove_from(map)
    }
    fn shift_remove_from(&self, map: &mut Mapping) -> Option<Value> {
        self.as_str().shift_remove_from(map)
    }
}

impl<T: ?Sized + Key> Key for &T {
    fn get_in<'m>(&self, map: &'m Mapping) -> Option<&'m Value> {
        (**self).get_in(map)
    }
    fn get_mut_in<'m>(&self, map: &'m mut Mapping) -> Option<&'m mut Value> {
        (**self).get_mut_in(map)
    }
    fn swap_remove_from(&self, map: &mut Mapping) -> Option<Value> {
        (**self).swap_remove_from(map)
    }
    fn shift_remove_from(&self, map: &mut Mapping) -> Option<Value> {
        (**self).shift_remove_from(map)
    }
}

impl Mapping {
    pub(crate) fn new() -> Self {
        Mapping::default()
    }

    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Mapping {
            map: IndexMap::with_capacity(capacity),
        }
    }

    /// Insert at the end, or replace in place; returns the old value.
    pub(crate) fn insert(&mut self, k: Value, v: Value) -> Option<Value> {
        self.map.insert(k, v)
    }

    pub(crate) fn contains_key<K: Key>(&self, key: K) -> bool {
        key.get_in(self).is_some()
    }

    pub(crate) fn get<K: Key>(&self, key: K) -> Option<&Value> {
        key.get_in(self)
    }

    pub(crate) fn get_mut<K: Key>(&mut self, key: K) -> Option<&mut Value> {
        key.get_mut_in(self)
    }

    /// Removes by swapping the last entry into its place, as the replaced
    /// backend's `remove` did; `shift_remove` keeps the order.
    pub(crate) fn remove<K: Key>(&mut self, key: K) -> Option<Value> {
        key.swap_remove_from(self)
    }

    pub(crate) fn swap_remove<K: Key>(&mut self, key: K) -> Option<Value> {
        key.swap_remove_from(self)
    }

    pub(crate) fn shift_remove<K: Key>(&mut self, key: K) -> Option<Value> {
        key.shift_remove_from(self)
    }

    pub(crate) fn retain(&mut self, mut keep: impl FnMut(&Value, &mut Value) -> bool) {
        self.map.retain(|k, v| keep(k, v));
    }

    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub(crate) fn clear(&mut self) {
        self.map.clear();
    }

    pub(crate) fn iter(&self) -> indexmap::map::Iter<'_, Value, Value> {
        self.map.iter()
    }

    pub(crate) fn iter_mut(&mut self) -> indexmap::map::IterMut<'_, Value, Value> {
        self.map.iter_mut()
    }

    pub(crate) fn keys(&self) -> indexmap::map::Keys<'_, Value, Value> {
        self.map.keys()
    }

    pub(crate) fn values(&self) -> indexmap::map::Values<'_, Value, Value> {
        self.map.values()
    }

    pub(crate) fn values_mut(&mut self) -> indexmap::map::ValuesMut<'_, Value, Value> {
        self.map.values_mut()
    }
}

impl Hash for Mapping {
    /// Order-insensitive, as equality is: each entry hashed on its own, then
    /// combined with xor.
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut xor = 0;
        for (k, v) in self {
            let mut hasher = DefaultHasher::new();
            k.hash(&mut hasher);
            v.hash(&mut hasher);
            xor ^= hasher.finish();
        }
        xor.hash(state);
    }
}

impl PartialOrd for Mapping {
    /// Both sides' entries sorted by `Value::total_cmp`, then compared
    /// entry by entry with `PartialOrd`, as the replaced backend did, so the
    /// result does not depend on insertion order.
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        fn sorted(m: &Mapping) -> Vec<(&Value, &Value)> {
            let mut entries: Vec<(&Value, &Value)> = m.iter().collect();
            entries.sort_by(|(ak, av), (bk, bv)| ak.total_cmp(bk).then_with(|| av.total_cmp(bv)));
            entries
        }
        sorted(self).partial_cmp(&sorted(other))
    }
}

impl fmt::Debug for Mapping {
    /// `Mapping {"a": Number(1)}`: string, bool and number keys print bare.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Bare<'a>(&'a dyn fmt::Display);
        impl fmt::Debug for Bare<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
        f.write_str("Mapping ")?;
        let mut debug = f.debug_map();
        for (k, v) in self {
            match k {
                Value::Bool(b) => debug.entry(b, v),
                Value::Number(n) => debug.entry(&Bare(n), v),
                Value::String(s) => debug.entry(s, v),
                _ => debug.entry(k, v),
            };
        }
        debug.finish()
    }
}

impl<'a> IntoIterator for &'a Mapping {
    type Item = (&'a Value, &'a Value);
    type IntoIter = indexmap::map::Iter<'a, Value, Value>;
    fn into_iter(self) -> Self::IntoIter {
        self.map.iter()
    }
}

impl<'a> IntoIterator for &'a mut Mapping {
    type Item = (&'a Value, &'a mut Value);
    type IntoIter = indexmap::map::IterMut<'a, Value, Value>;
    fn into_iter(self) -> Self::IntoIter {
        self.map.iter_mut()
    }
}

impl IntoIterator for Mapping {
    type Item = (Value, Value);
    type IntoIter = indexmap::map::IntoIter<Value, Value>;
    fn into_iter(self) -> Self::IntoIter {
        self.map.into_iter()
    }
}

impl FromIterator<(Value, Value)> for Mapping {
    fn from_iter<I: IntoIterator<Item = (Value, Value)>>(iter: I) -> Self {
        Mapping {
            map: IndexMap::from_iter(iter),
        }
    }
}

impl Extend<(Value, Value)> for Mapping {
    fn extend<I: IntoIterator<Item = (Value, Value)>>(&mut self, iter: I) {
        self.map.extend(iter);
    }
}

impl<K: Key> std::ops::Index<K> for Mapping {
    type Output = Value;
    /// # Panics
    ///
    /// When the key is absent, as the replaced backend's `Index` did.
    fn index(&self, key: K) -> &Value {
        key.get_in(self).expect("key not found in YAML mapping")
    }
}

impl serde::Serialize for Mapping {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for (k, v) in self {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for Mapping {
    /// A repeated key is refused, with the replaced backend's wording.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Mapping;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a YAML mapping")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Mapping, E> {
                Ok(Mapping::new())
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut data: A,
            ) -> Result<Mapping, A::Error> {
                let mut mapping = Mapping::new();
                while let Some(key) = data.next_key::<Value>()? {
                    if mapping.map.contains_key(&key) {
                        return Err(serde::de::Error::custom(duplicate_key(&key)));
                    }
                    let value = data.next_value()?;
                    mapping.map.insert(key, value);
                }
                Ok(mapping)
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

/// The replaced backend's refusal of a repeated key in a tree.
pub(crate) fn duplicate_key(key: &Value) -> String {
    match key {
        Value::Null => "duplicate entry with null key".to_owned(),
        Value::Bool(b) => format!("duplicate entry with key `{b}`"),
        Value::Number(n) => format!("duplicate entry with key {n}"),
        Value::String(s) => format!("duplicate entry with key {s:?}"),
        Value::Sequence(_) | Value::Mapping(_) | Value::Tagged(_) => {
            "duplicate entry in YAML map".to_owned()
        }
    }
}
