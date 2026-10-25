// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Typed reads (design section 3): a serde `Deserializer` over the parse
//! representation with the replaced backend's rules. A unit variant reads
//! from a scalar of any style and a data variant only from a tag, so the
//! map form of an externally tagged enum is refused (G3); a `String`
//! target gets the source text (D26); a map target keeps the last of a
//! repeated key and a struct or the tree refuses it (D2, D3). Every error
//! names its key path and place (D11); every alias crossed costs the
//! document's budget (D16).

use std::fmt;

use serde::de::{self, Unexpected, Visitor};

mod access;

use access::{EnumAccess, MapAccess, SeqAccess, UnitVariantAccess};

use super::Error;
use super::rep::{Budget, Document, Kind, NodeId, Pos};
use super::resolve;

/// Where a value sits, for error text: `a.b[0].c`; `.` is the root.
#[derive(Clone, Copy)]
pub(crate) enum Path<'a> {
    Root,
    Seq { parent: &'a Path<'a>, index: usize },
    Map { parent: &'a Path<'a>, key: &'a str },
    Alias { parent: &'a Path<'a> },
    Unknown { parent: &'a Path<'a> },
}

impl fmt::Display for Path<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Parent<'a>(&'a Path<'a>);
        impl fmt::Display for Parent<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.0 {
                    Path::Root => Ok(()),
                    path => write!(f, "{path}."),
                }
            }
        }
        match self {
            Path::Root => f.write_str("."),
            Path::Seq { parent, index } => write!(f, "{parent}[{index}]"),
            Path::Map { parent, key } => write!(f, "{}{key}", Parent(parent)),
            Path::Alias { parent } => write!(f, "{parent}"),
            Path::Unknown { parent } => write!(f, "{}?", Parent(parent)),
        }
    }
}

/// The enum a tag already named, so the variant's content is not read as a
/// second enum.
#[derive(Clone, Copy)]
struct CurrentEnum<'a> {
    name: Option<&'static str>,
    tag: &'a str,
}

/// The replaced backend's nesting budget for typed reads.
const DEPTH: usize = 128;

/// One node being read. `'a` is the frame: the document, the budget and
/// the key path all outlive it.
pub(crate) struct De<'a> {
    document: &'a Document,
    id: NodeId,
    budget: &'a mut Budget,
    path: Path<'a>,
    depth: usize,
    current_enum: Option<CurrentEnum<'a>>,
}

/// A scalar's parts, borrowed from the document.
struct Scalar<'a> {
    text: &'a str,
    plain: bool,
    tag: Option<&'a str>,
    empty: bool,
}

impl<'a> De<'a> {
    pub(crate) fn new(document: &'a Document, budget: &'a mut Budget) -> Self {
        De {
            document,
            id: document.root,
            budget,
            path: Path::Root,
            depth: DEPTH,
            current_enum: None,
        }
    }

    fn pos(&self) -> Pos {
        self.document.node(self.id).pos
    }

    fn kind(&self) -> &'a Kind {
        &self.document.node(self.id).kind
    }

    fn scalar(&self) -> Option<Scalar<'a>> {
        match self.kind() {
            Kind::Scalar {
                text,
                plain,
                tag,
                empty,
            } => Some(Scalar {
                text: if *empty { "" } else { text },
                plain: *plain,
                tag: tag.as_deref(),
                empty: *empty,
            }),
            _ => None,
        }
    }

    /// The node an alias names, as a deserializer one level down the path;
    /// `None` when this node is not an alias.
    fn follow(&mut self) -> Result<Option<De<'_>>, Error> {
        let Kind::Alias(target) = *self.kind() else {
            return Ok(None);
        };
        self.budget.jump()?;
        Ok(Some(De {
            document: self.document,
            id: target,
            budget: &mut *self.budget,
            path: Path::Alias { parent: &self.path },
            depth: self.depth,
            current_enum: None,
        }))
    }

    /// `result` with this node's key path and place, for a serde message
    /// that has none yet.
    fn place<T>(&self, result: Result<T, Error>) -> Result<T, Error> {
        let at = self.pos();
        result.map_err(|e| e.fix_place(at.line, at.column, &self.path.to_string()))
    }

    /// One level of nesting, refused past the budget.
    fn deeper(&mut self) -> Result<(), Error> {
        self.depth = match self.depth.checked_sub(1) {
            Some(depth) => depth,
            None => return Err(self.pos().refuse("recursion limit exceeded")),
        };
        Ok(())
    }
}

/// A scalar to `visitor` (the replaced backend's `visit_scalar`): a core
/// `bool`/`int`/`float`/`null` tag forces its type; a plain scalar, or a
/// local tag over a plain one, resolves untagged; anything else is text.
fn visit_scalar<'de, V: Visitor<'de>>(
    visitor: V,
    scalar: &Scalar<'_>,
    tagged_already: bool,
) -> Result<V::Value, Error> {
    let text = scalar.text;
    if let (Some(tag), false) = (scalar.tag, tagged_already) {
        if tag == resolve::BOOL {
            return match resolve::parse_bool(text) {
                Some(b) => visitor.visit_bool(b),
                None => Err(de::Error::invalid_value(
                    Unexpected::Str(text),
                    &"a boolean",
                )),
            };
        } else if tag == resolve::INT {
            return match resolve::visit_int(visitor, text) {
                Ok(result) => result,
                Err(_) => Err(de::Error::invalid_value(
                    Unexpected::Str(text),
                    &"an integer",
                )),
            };
        } else if tag == resolve::FLOAT {
            return match resolve::parse_f64(text) {
                Some(f) => visitor.visit_f64(f),
                None => Err(de::Error::invalid_value(Unexpected::Str(text), &"a float")),
            };
        } else if tag == resolve::NULL {
            return match resolve::parse_null(text) {
                Some(()) => visitor.visit_unit(),
                None => Err(de::Error::invalid_value(Unexpected::Str(text), &"null")),
            };
        } else if tag.starts_with('!') && scalar.plain {
            return resolve::visit_untagged(visitor, text);
        }
    } else if scalar.plain {
        return resolve::visit_untagged(visitor, text);
    }
    visitor.visit_str(text)
}

/// A local tag as an enum's variant name: `!pair` names `pair`. A core or
/// URI tag names nothing.
fn enum_tag(tag: Option<&str>) -> Option<&str> {
    let rest = tag?.strip_prefix('!')?;
    Some(if rest.is_empty() { "!" } else { rest })
}

/// A node's tag as an enum variant, unless a tag already named the enum:
/// inside a variant the node's own tag is not a second enum.
fn variant_tag(tag: Option<&str>, tagged_already: bool) -> Option<&str> {
    if tagged_already { None } else { enum_tag(tag) }
}

/// Whether a typed number or bool read accepts this scalar: a plain one.
///
/// ponytail: the replaced backend also accepted a literal block (`|`)
/// carrying exactly the target's core tag (`!!int |` over `5`); the parse
/// representation does not record block style, so that form reads as a
/// type error here. Add a `literal` flag to `rep::Kind::Scalar` if a
/// golden row or a shipped file ever uses it.
fn readable(scalar: &Scalar<'_>) -> bool {
    scalar.plain
}

/// serde's type error for this node against what `exp` wanted, naming the
/// node's kind (and a scalar's resolved kind) as the replaced backend did.
fn invalid_type(de: &De<'_>, exp: &dyn de::Expected) -> Error {
    struct Expecting<'e>(&'e dyn de::Expected);
    impl Visitor<'_> for Expecting<'_> {
        type Value = std::convert::Infallible;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.0.fmt(f)
        }
    }
    match de.kind() {
        Kind::Scalar { .. } => {
            let scalar = de.scalar().expect("a scalar node");
            match visit_scalar(Expecting(exp), &scalar, false) {
                Ok(never) => match never {},
                Err(error) => error,
            }
        }
        Kind::Seq { .. } => de::Error::invalid_type(Unexpected::Seq, exp),
        Kind::Map { .. } => de::Error::invalid_type(Unexpected::Map, exp),
        Kind::Alias(_) => unreachable!("aliases are followed before a type check"),
    }
}

impl<'a> De<'a> {
    /// Read a sequence's items with `visitor`, then refuse any it left
    /// unread, as the replaced backend did.
    fn visit_seq<'de, V: Visitor<'de>>(
        &mut self,
        visitor: V,
        items: &'a [NodeId],
    ) -> Result<V::Value, Error> {
        self.deeper()?;
        let mut access = SeqAccess {
            de: self,
            items,
            next: 0,
        };
        let value = visitor.visit_seq(&mut access)?;
        let read = access.next;
        self.depth += 1;
        if read == items.len() {
            Ok(value)
        } else {
            Err(de::Error::invalid_length(
                items.len(),
                &ExpectedLen(read, "sequence of", "element", "elements"),
            ))
        }
    }

    /// Read a mapping's entries with `visitor`, then refuse any it left
    /// unread.
    fn visit_map<'de, V: Visitor<'de>>(
        &mut self,
        visitor: V,
        entries: &'a [(NodeId, NodeId)],
    ) -> Result<V::Value, Error> {
        self.deeper()?;
        let mut access = MapAccess {
            de: self,
            entries,
            next: 0,
        };
        let value = visitor.visit_map(&mut access)?;
        let read = access.next;
        self.depth += 1;
        if read == entries.len() {
            Ok(value)
        } else {
            Err(de::Error::invalid_length(
                entries.len(),
                &ExpectedLen(read, "map containing", "entry", "entries"),
            ))
        }
    }

    /// An empty plain scalar where a collection was wanted: the replaced
    /// backend read it as an empty one.
    fn is_empty_plain(&self) -> bool {
        self.scalar().is_some_and(|s| s.plain && s.text.is_empty())
    }
}

/// `sequence of 1 element`, `map containing 2 entries`.
struct ExpectedLen(usize, &'static str, &'static str, &'static str);

impl de::Expected for ExpectedLen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let noun = if self.0 == 1 { self.2 } else { self.3 };
        write!(f, "{} {} {noun}", self.1, self.0)
    }
}

/// A typed number read: follow an alias, read a plain scalar with `read`,
/// or refuse with serde's type error; placed at this node.
macro_rules! typed {
    ($de:ident, $visitor:ident, $method:ident, $read:expr) => {{
        if let Some(mut target) = $de.follow()? {
            return target.$method($visitor);
        }
        let result = match $de.scalar() {
            Some(scalar) if readable(&scalar) => match $read(scalar.text, $visitor) {
                Ok(done) => done,
                Err(visitor) => Err(invalid_type($de, &visitor)),
            },
            _ => Err(invalid_type($de, &$visitor)),
        };
        $de.place(result)
    }};
}

impl<'de> de::Deserializer<'de> for &mut De<'_> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        if let Some(mut target) = self.follow()? {
            return target.deserialize_any(visitor);
        }
        let tagged_already = self.current_enum.is_some();
        let result = match self.kind() {
            Kind::Scalar { tag: t, .. } | Kind::Seq { tag: t, .. } | Kind::Map { tag: t, .. }
                if variant_tag(t.as_deref(), tagged_already).is_some() =>
            {
                let tag = variant_tag(t.as_deref(), tagged_already).expect("checked");
                visitor.visit_enum(EnumAccess {
                    de: self,
                    name: None,
                    tag,
                })
            }
            Kind::Scalar { .. } => {
                let scalar = self.scalar().expect("a scalar node");
                visit_scalar(visitor, &scalar, tagged_already)
            }
            Kind::Seq { items, .. } => self.visit_seq(visitor, items),
            Kind::Map { entries, .. } => self.visit_map(visitor, entries),
            Kind::Alias(_) => unreachable!("followed above"),
        };
        self.place(result)
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        typed!(
            self,
            visitor,
            deserialize_bool,
            |text: &str, v: V| match resolve::parse_bool(text) {
                Some(b) => Ok(v.visit_bool(b)),
                None => Err(v),
            }
        )
    }

    fn deserialize_i64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        typed!(
            self,
            visitor,
            deserialize_i64,
            |text: &str, v: V| match resolve::parse_signed_int(text, i64::from_str_radix) {
                Some(i) => Ok(v.visit_i64(i)),
                None => Err(v),
            }
        )
    }

    fn deserialize_i128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        typed!(
            self,
            visitor,
            deserialize_i128,
            |text: &str, v: V| match resolve::parse_signed_int(text, i128::from_str_radix) {
                Some(i) => Ok(v.visit_i128(i)),
                None => Err(v),
            }
        )
    }

    fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        typed!(
            self,
            visitor,
            deserialize_u64,
            |text: &str, v: V| match resolve::parse_unsigned_int(text, u64::from_str_radix) {
                Some(u) => Ok(v.visit_u64(u)),
                None => Err(v),
            }
        )
    }

    fn deserialize_u128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        typed!(
            self,
            visitor,
            deserialize_u128,
            |text: &str, v: V| match resolve::parse_unsigned_int(text, u128::from_str_radix) {
                Some(u) => Ok(v.visit_u128(u)),
                None => Err(v),
            }
        )
    }

    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        typed!(
            self,
            visitor,
            deserialize_f64,
            |text: &str, v: V| match resolve::parse_f64(text) {
                Some(f) => Ok(v.visit_f64(f)),
                None => Err(v),
            }
        )
    }

    fn deserialize_i8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_i64(visitor)
    }
    fn deserialize_i16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_i64(visitor)
    }
    fn deserialize_i32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_i64(visitor)
    }
    fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_u64(visitor)
    }
    fn deserialize_u16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_u64(visitor)
    }
    fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_u64(visitor)
    }
    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_f64(visitor)
    }
    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_str(visitor)
    }

    /// The scalar's source text, whatever it would resolve to (D26).
    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        if let Some(mut target) = self.follow()? {
            return target.deserialize_str(visitor);
        }
        let result = match self.scalar() {
            Some(scalar) => visitor.visit_str(scalar.text),
            None => Err(invalid_type(self, &visitor)),
        };
        self.place(result)
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Error> {
        Err(Error::message(
            "serialization and deserialization of bytes in YAML is not implemented",
        ))
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Error> {
        Err(Error::message(
            "serialization and deserialization of bytes in YAML is not implemented",
        ))
    }

    /// Null (plain, or tagged `!!null` over a null spelling) is `None`;
    /// anything else, quoted text included, is `Some`.
    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        if let Some(mut target) = self.follow()? {
            return target.deserialize_option(visitor);
        }
        let tagged_already = self.current_enum.is_some();
        let is_some = match self.scalar() {
            Some(s) if !s.plain => true,
            Some(s) => match (s.tag, tagged_already) {
                (Some(tag), false) if tag == resolve::NULL => {
                    if resolve::parse_null(s.text).is_none() {
                        return Err(de::Error::invalid_value(Unexpected::Str(s.text), &"null"));
                    }
                    false
                }
                (Some(_), false) => true,
                _ => !s.text.is_empty() && resolve::parse_null(s.text).is_none(),
            },
            None => true,
        };
        if is_some {
            visitor.visit_some(self)
        } else {
            self.current_enum = None;
            visitor.visit_none()
        }
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        if let Some(mut target) = self.follow()? {
            return target.deserialize_unit(visitor);
        }
        let tagged_already = self.current_enum.is_some();
        let result = match self.scalar() {
            Some(s) => {
                let is_null = if !s.plain {
                    false
                } else if let (Some(tag), false) = (s.tag, tagged_already) {
                    tag == resolve::NULL && resolve::parse_null(s.text).is_some()
                } else {
                    s.text.is_empty() || resolve::parse_null(s.text).is_some()
                };
                if is_null {
                    visitor.visit_unit()
                } else {
                    Err(de::Error::invalid_value(Unexpected::Str(s.text), &"null"))
                }
            }
            None => Err(invalid_type(self, &visitor)),
        };
        self.place(result)
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
        self.deeper()?;
        let result = visitor.visit_newtype_struct(&mut *self);
        self.depth += 1;
        result
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        if let Some(mut target) = self.follow()? {
            return target.deserialize_seq(visitor);
        }
        let result = match self.kind() {
            Kind::Seq { items, .. } => self.visit_seq(visitor, items),
            _ if self.is_empty_plain() => self.visit_seq(visitor, &[]),
            _ => Err(invalid_type(self, &visitor)),
        };
        self.place(result)
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
        if let Some(mut target) = self.follow()? {
            return target.deserialize_map(visitor);
        }
        let result = match self.kind() {
            Kind::Map { entries, .. } => self.visit_map(visitor, entries),
            _ if self.is_empty_plain() => self.visit_map(visitor, &[]),
            _ => Err(invalid_type(self, &visitor)),
        };
        self.place(result)
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_map(visitor)
    }

    /// An externally tagged enum: a unit variant from a scalar's text of any
    /// style, a data variant only from a local tag. The map form is refused
    /// (G3, D6).
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        if let Some(current) = self.current_enum {
            let result = match self.scalar() {
                Some(s) if !s.text.is_empty() => visitor.visit_enum(UnitVariantAccess { de: self }),
                _ => Err(Error::message(match current.name {
                    Some(outer) => format!(
                        "deserializing nested enum in {outer}::{} from YAML is not supported yet",
                        current.tag
                    ),
                    None => format!(
                        "deserializing nested enum in !{} from YAML is not supported yet",
                        current.tag
                    ),
                })),
            };
            return self.place(result);
        }
        if let Some(mut target) = self.follow()? {
            return target.deserialize_enum(name, variants, visitor);
        }
        let result = match self.kind() {
            Kind::Scalar { tag, .. } | Kind::Seq { tag, .. } | Kind::Map { tag, .. }
                if enum_tag(tag.as_deref()).is_some() =>
            {
                let tag = enum_tag(tag.as_deref()).expect("checked");
                visitor.visit_enum(EnumAccess {
                    de: self,
                    name: Some(name),
                    tag,
                })
            }
            Kind::Scalar { .. } => visitor.visit_enum(UnitVariantAccess { de: self }),
            Kind::Map { .. } => Err(de::Error::invalid_type(
                Unexpected::Map,
                &"a YAML tag starting with '!'",
            )),
            Kind::Seq { .. } => Err(de::Error::invalid_type(
                Unexpected::Seq,
                &"a YAML tag starting with '!'",
            )),
            Kind::Alias(_) => unreachable!("followed above"),
        };
        self.place(result)
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_str(visitor)
    }

    /// Skipped without following its aliases, as the replaced backend
    /// skipped an ignored field's events.
    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_unit()
    }
}

/// `T` from `document`, with one alias budget for the whole read.
pub(crate) fn from_document<T: serde::de::DeserializeOwned>(
    document: &Document,
) -> Result<T, Error> {
    let mut budget = Budget::for_document(document);
    T::deserialize(&mut De::new(document, &mut budget))
}
