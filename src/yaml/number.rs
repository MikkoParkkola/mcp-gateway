// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A YAML number, as the replaced backend held it: an unsigned, negative or
//! float value, printed, compared and hashed the same way, so a tree's
//! digest and every `as_*` answer stay as recorded.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

use serde::{Serialize, Serializer};

/// One YAML number. Integers that fit `u64` are unsigned; other integers
/// are negative `i64`; everything else is a float. YAML has one NaN.
#[derive(Clone, Copy)]
pub(crate) struct Number {
    n: N,
}

#[derive(Clone, Copy)]
enum N {
    PosInt(u64),
    NegInt(i64),
    Float(f64),
}

impl Number {
    pub(crate) fn is_i64(&self) -> bool {
        match self.n {
            N::PosInt(v) => i64::try_from(v).is_ok(),
            N::NegInt(_) => true,
            N::Float(_) => false,
        }
    }

    pub(crate) fn is_u64(&self) -> bool {
        matches!(self.n, N::PosInt(_))
    }

    pub(crate) fn is_f64(&self) -> bool {
        matches!(self.n, N::Float(_))
    }

    pub(crate) fn as_i64(&self) -> Option<i64> {
        match self.n {
            N::PosInt(v) => i64::try_from(v).ok(),
            N::NegInt(v) => Some(v),
            N::Float(_) => None,
        }
    }

    pub(crate) fn as_u64(&self) -> Option<u64> {
        match self.n {
            N::PosInt(v) => Some(v),
            N::NegInt(_) | N::Float(_) => None,
        }
    }

    /// Every number reads as a float, the integers by conversion.
    #[allow(
        clippy::cast_precision_loss,
        clippy::unnecessary_wraps,
        reason = "the replaced backend's as_f64: same conversion, same signature"
    )]
    pub(crate) fn as_f64(&self) -> Option<f64> {
        match self.n {
            N::PosInt(v) => Some(v as f64),
            N::NegInt(v) => Some(v as f64),
            N::Float(v) => Some(v),
        }
    }

    pub(crate) fn is_nan(&self) -> bool {
        matches!(self.n, N::Float(f) if f.is_nan())
    }

    pub(crate) fn is_infinite(&self) -> bool {
        matches!(self.n, N::Float(f) if f.is_infinite())
    }

    pub(crate) fn is_finite(&self) -> bool {
        match self.n {
            N::PosInt(_) | N::NegInt(_) => true,
            N::Float(f) => f.is_finite(),
        }
    }

    /// A total order: negatives below positives, integers below floats,
    /// NaN last.
    pub(crate) fn total_cmp(&self, other: &Self) -> Ordering {
        match (self.n, other.n) {
            (N::PosInt(a), N::PosInt(b)) => a.cmp(&b),
            (N::NegInt(a), N::NegInt(b)) => a.cmp(&b),
            (N::Float(a), N::Float(b)) => {
                a.partial_cmp(&b)
                    .unwrap_or_else(|| match (a.is_nan(), b.is_nan()) {
                        (false, _) => Ordering::Less,
                        (true, false) => Ordering::Greater,
                        (true, true) => Ordering::Equal,
                    })
            }
            // Negatives below positives; integers below floats.
            (N::NegInt(_), N::PosInt(_)) | (N::PosInt(_) | N::NegInt(_), N::Float(_)) => {
                Ordering::Less
            }
            (N::PosInt(_), N::NegInt(_)) | (N::Float(_), N::PosInt(_) | N::NegInt(_)) => {
                Ordering::Greater
            }
        }
    }

    /// What a serde error names as the unexpected value.
    pub(crate) fn unexpected(&self) -> serde::de::Unexpected<'static> {
        match self.n {
            N::PosInt(v) => serde::de::Unexpected::Unsigned(v),
            N::NegInt(v) => serde::de::Unexpected::Signed(v),
            N::Float(v) => serde::de::Unexpected::Float(v),
        }
    }

    /// Hand the number to a serde visitor in its own kind.
    pub(crate) fn visit<'de, V: serde::de::Visitor<'de>, E: serde::de::Error>(
        self,
        visitor: V,
    ) -> Result<V::Value, E> {
        match self.n {
            N::PosInt(v) => visitor.visit_u64(v),
            N::NegInt(v) => visitor.visit_i64(v),
            N::Float(v) => visitor.visit_f64(v),
        }
    }
}

impl fmt::Display for Number {
    /// Integers in decimal; floats as `.nan`, `.inf`, `-.inf`, or the
    /// shortest round-tripping form (`1000.0`, `1e100`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.n {
            N::PosInt(v) => write!(f, "{v}"),
            N::NegInt(v) => write!(f, "{v}"),
            N::Float(v) if v.is_nan() => f.write_str(".nan"),
            N::Float(v) if v.is_infinite() => f.write_str(if v.is_sign_negative() {
                "-.inf"
            } else {
                ".inf"
            }),
            N::Float(v) => f.write_str(ryu::Buffer::new().format_finite(v)),
        }
    }
}

impl fmt::Debug for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Number({self})")
    }
}

impl PartialEq for Number {
    fn eq(&self, other: &Self) -> bool {
        match (self.n, other.n) {
            (N::PosInt(a), N::PosInt(b)) => a == b,
            (N::NegInt(a), N::NegInt(b)) => a == b,
            (N::Float(a), N::Float(b)) => (a.is_nan() && b.is_nan()) || a == b,
            _ => false,
        }
    }
}

impl Eq for Number {}

impl PartialOrd for Number {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self.n, other.n) {
            (N::Float(a), N::Float(b)) if a.is_nan() && b.is_nan() => Some(Ordering::Equal),
            (N::Float(a), N::Float(b)) => a.partial_cmp(&b),
            _ => Some(self.total_cmp(other)),
        }
    }
}

impl Hash for Number {
    /// Floats share one hash: equal floats must hash alike, and NaN equals
    /// NaN here.
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self.n {
            N::Float(_) => 3.hash(state),
            N::PosInt(v) => v.hash(state),
            N::NegInt(v) => v.hash(state),
        }
    }
}

impl Serialize for Number {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.n {
            N::PosInt(v) => serializer.serialize_u64(v),
            N::NegInt(v) => serializer.serialize_i64(v),
            N::Float(v) => serializer.serialize_f64(v),
        }
    }
}

macro_rules! from_int {
    ($($t:ty)*) => {$(
        impl From<$t> for Number {
            fn from(v: $t) -> Self {
                match u64::try_from(v) {
                    Ok(u) => Number { n: N::PosInt(u) },
                    // Below zero, so it fits i64 for every source type here.
                    Err(_) => Number { n: N::NegInt(i64::try_from(v).unwrap_or(i64::MIN)) },
                }
            }
        }
    )*};
}

from_int!(i8 i16 i32 i64 isize u8 u16 u32 u64 usize);

impl From<f32> for Number {
    fn from(v: f32) -> Self {
        Number::from(f64::from(v))
    }
}

impl From<f64> for Number {
    /// One NaN: sign and payload are dropped, as YAML has only `.nan`.
    fn from(v: f64) -> Self {
        let v = if v.is_nan() {
            f64::NAN.copysign(1.0)
        } else {
            v
        };
        Number { n: N::Float(v) }
    }
}
