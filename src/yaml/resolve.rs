// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Scalar resolution exactly as the replaced backend did it (D9, D23 to
//! D26): `tests/fixtures/mik_8425_yaml/behaviour.txt` is the specification,
//! not a YAML schema. `0755` and `1_000` stay strings; `0o755`, `0x1F`,
//! `1e3`, `.inf` and `.nan` are numbers; `true`/`True`/`TRUE` are booleans
//! and `yes` is a string.

use std::num::ParseIntError;

use serde::de::Visitor;

use super::Error;

pub(crate) const BOOL: &str = "tag:yaml.org,2002:bool";
pub(crate) const INT: &str = "tag:yaml.org,2002:int";
pub(crate) const FLOAT: &str = "tag:yaml.org,2002:float";
pub(crate) const NULL: &str = "tag:yaml.org,2002:null";

/// `~`, `null`, `Null` or `NULL` (not the empty string: callers check it).
pub(crate) fn parse_null(text: &str) -> Option<()> {
    matches!(text, "null" | "Null" | "NULL" | "~").then_some(())
}

pub(crate) fn parse_bool(text: &str) -> Option<bool> {
    match text {
        "true" | "True" | "TRUE" => Some(true),
        "false" | "False" | "FALSE" => Some(false),
        _ => None,
    }
}

/// A decimal with a leading zero (`0755`, `-00`): a string, as YAML 1.2
/// says.
pub(crate) fn digits_but_not_number(text: &str) -> bool {
    let body = text.strip_prefix(['-', '+']).unwrap_or(text);
    body.len() > 1 && body.starts_with('0') && body[1..].bytes().all(|b| b.is_ascii_digit())
}

/// What the digits after a radix prefix are.
enum Prefixed<T> {
    /// A second sign after the prefix: not an integer at all.
    Refused,
    /// They parse in the radix.
    Found(T),
    /// They do not; the caller tries the next spelling.
    Other,
}

/// `digits` in `radix`, refusing a second sign after the prefix.
fn prefixed<T>(
    digits: &str,
    radix: u32,
    from_str_radix: fn(&str, u32) -> Result<T, ParseIntError>,
) -> Prefixed<T> {
    if digits.starts_with(['+', '-']) {
        return Prefixed::Refused;
    }
    from_str_radix(digits, radix).map_or(Prefixed::Other, Prefixed::Found)
}

pub(crate) fn parse_unsigned_int<T>(
    text: &str,
    from_str_radix: fn(&str, u32) -> Result<T, ParseIntError>,
) -> Option<T> {
    let unpositive = text.strip_prefix('+').unwrap_or(text);
    for (prefix, radix) in [("0x", 16), ("0o", 8), ("0b", 2)] {
        if let Some(rest) = unpositive.strip_prefix(prefix) {
            match prefixed(rest, radix, from_str_radix) {
                Prefixed::Refused => return None,
                Prefixed::Found(int) => return Some(int),
                Prefixed::Other => {}
            }
        }
    }
    if unpositive.starts_with(['+', '-']) || digits_but_not_number(text) {
        return None;
    }
    from_str_radix(unpositive, 10).ok()
}

pub(crate) fn parse_signed_int<T>(
    text: &str,
    from_str_radix: fn(&str, u32) -> Result<T, ParseIntError>,
) -> Option<T> {
    let unpositive = match text.strip_prefix('+') {
        Some(rest) if rest.starts_with(['+', '-']) => return None,
        Some(rest) => rest,
        None => text,
    };
    for (prefix, radix) in [("0x", 16), ("0o", 8), ("0b", 2)] {
        if let Some(rest) = unpositive.strip_prefix(prefix) {
            match prefixed(rest, radix, from_str_radix) {
                Prefixed::Refused => return None,
                Prefixed::Found(int) => return Some(int),
                Prefixed::Other => {}
            }
        }
        if let Some(rest) = text.strip_prefix('-').and_then(|t| t.strip_prefix(prefix))
            && let Ok(int) = from_str_radix(&format!("-{rest}"), radix)
        {
            return Some(int);
        }
    }
    if digits_but_not_number(text) {
        return None;
    }
    from_str_radix(unpositive, 10).ok()
}

pub(crate) fn parse_negative_int<T>(
    text: &str,
    from_str_radix: fn(&str, u32) -> Result<T, ParseIntError>,
) -> Option<T> {
    for (prefix, radix) in [("-0x", 16), ("-0o", 8), ("-0b", 2)] {
        if let Some(rest) = text.strip_prefix(prefix)
            && let Ok(int) = from_str_radix(&format!("-{rest}"), radix)
        {
            return Some(int);
        }
    }
    if digits_but_not_number(text) {
        return None;
    }
    from_str_radix(text, 10).ok()
}

/// A float spelling, `.inf`/`.nan` forms included; a finite parse only
/// (`1e400` is not a float). The caller rules out leading-zero decimals.
pub(crate) fn parse_f64(text: &str) -> Option<f64> {
    let unpositive = match text.strip_prefix('+') {
        Some(rest) if rest.starts_with(['+', '-']) => return None,
        Some(rest) => rest,
        None => text,
    };
    if matches!(unpositive, ".inf" | ".Inf" | ".INF") {
        return Some(f64::INFINITY);
    }
    if matches!(text, "-.inf" | "-.Inf" | "-.INF") {
        return Some(f64::NEG_INFINITY);
    }
    if matches!(text, ".nan" | ".NaN" | ".NAN") {
        return Some(f64::NAN.copysign(1.0));
    }
    unpositive.parse::<f64>().ok().filter(|f| f.is_finite())
}

/// An integer to `visitor` in the narrowest kind it fits, or the visitor
/// back when `text` is not an integer.
pub(crate) fn visit_int<'de, V: Visitor<'de>>(
    visitor: V,
    text: &str,
) -> Result<Result<V::Value, Error>, V> {
    if let Some(int) = parse_unsigned_int(text, u64::from_str_radix) {
        return Ok(visitor.visit_u64(int));
    }
    if let Some(int) = parse_negative_int(text, i64::from_str_radix) {
        return Ok(visitor.visit_i64(int));
    }
    if let Some(int) = parse_unsigned_int(text, u128::from_str_radix) {
        return Ok(visitor.visit_u128(int));
    }
    if let Some(int) = parse_negative_int(text, i128::from_str_radix) {
        return Ok(visitor.visit_i128(int));
    }
    Err(visitor)
}

/// A plain, untagged scalar to `visitor`: null, bool, integer, float, or
/// its text.
pub(crate) fn visit_untagged<'de, V: Visitor<'de>>(
    visitor: V,
    text: &str,
) -> Result<V::Value, Error> {
    if text.is_empty() || parse_null(text).is_some() {
        return visitor.visit_unit();
    }
    if let Some(b) = parse_bool(text) {
        return visitor.visit_bool(b);
    }
    let visitor = match visit_int(visitor, text) {
        Ok(result) => return result,
        Err(visitor) => visitor,
    };
    if !digits_but_not_number(text)
        && let Some(f) = parse_f64(text)
    {
        return visitor.visit_f64(f);
    }
    visitor.visit_str(text)
}
