// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A config load error names the key, the place and the expected type, never
//! the value that caused it (MIK-8375, CWE-532).
//!
//! A config error reaches stderr, CI and container logs, and the log line of a
//! refused reload. The value a field got wrong is often the secret the field
//! holds: a token typed into a number, a key pasted one line too low. So the
//! value is dropped everywhere figment or serde would have printed it, and
//! the key path, the source file, the line and column and the expected type
//! are kept, which is what an operator needs to find and fix the line.

use figment::error::{Actual, Kind, OneOf};

/// What serde puts between a quoted value and the type it wanted.
const EXPECTED: &str = ", expected ";

/// The error every config extract reports: each error in figment's chain with
/// its value removed, its key path and source kept.
pub(crate) fn from_figment(error: figment::Error) -> crate::Error {
    let parts: Vec<String> = error
        .into_iter()
        .map(|mut part| {
            part.kind = redact_kind(part.kind);
            part.to_string()
        })
        .collect();
    crate::Error::Config(parts.join("\n"))
}

fn redact_kind(kind: Kind) -> Kind {
    match kind {
        Kind::Message(message) => Kind::Message(redact_message(&message)),
        Kind::InvalidType(actual, expected) => Kind::InvalidType(kind_of(&actual), expected),
        Kind::InvalidValue(actual, expected) => Kind::InvalidValue(kind_of(&actual), expected),
        Kind::Unsupported(actual) => Kind::Unsupported(kind_of(&actual)),
        Kind::UnsupportedKey(actual, wanted) => Kind::UnsupportedKey(kind_of(&actual), wanted),
        Kind::UnknownVariant(_, expected) => {
            Kind::Message(format!("unknown variant, expected {}", OneOf(expected)))
        }
        Kind::ISizeOutOfRange(_) | Kind::USizeOutOfRange(_) => {
            Kind::Message("integer out of range".to_owned())
        }
        // Key names, lengths and field names: never a value.
        kind @ (Kind::InvalidLength(..)
        | Kind::UnknownField(..)
        | Kind::MissingField(..)
        | Kind::DuplicateField(..)) => kind,
    }
}

/// The kind of value `actual` was, without the value.
fn kind_of(actual: &Actual) -> Actual {
    let word = match actual {
        Actual::Bool(_) => "a boolean",
        Actual::Unsigned(_) | Actual::Signed(_) => "an integer",
        Actual::Float(_) => "a float",
        Actual::Char(_) => "a character",
        Actual::Str(_) => "a string",
        Actual::Bytes(_) => "bytes",
        Actual::Other(_) => "a value",
        // The rest carry no data: their own text is already value-free.
        data_free => return data_free.clone(),
    };
    Actual::Other(word.to_owned())
}

/// `message` with any value serde quoted in it removed.
///
/// serde's own messages put the value between a fixed marker and the LAST
/// `, expected ` after it; a value may itself contain `, expected `, so the
/// first one is not the end of it. Every other message passes through:
/// libyaml's syntax problems are fixed strings, and the gateway's own refusals
/// name keys, never values.
pub(crate) fn redact_message(message: &str) -> String {
    for marker in ["invalid type: ", "invalid value: "] {
        if let Some(start) = message.find(marker) {
            let from = start + marker.len();
            let tail = &message[from..];
            return match tail.rfind(EXPECTED) {
                Some(cut) => format!(
                    "{}{}{}",
                    &message[..from],
                    kind_word(&tail[..cut]),
                    &tail[cut..]
                ),
                None => format!("{}a value{}", &message[..from], location(tail)),
            };
        }
    }
    let marker = "unknown variant `";
    if let Some(start) = message.find(marker) {
        let tail = &message[start + marker.len()..];
        let rest = tail
            .rfind(EXPECTED)
            .map_or_else(|| location(tail), |cut| &tail[cut..]);
        return format!("{}unknown variant{rest}", &message[..start]);
    }
    message.to_owned()
}

/// serde's description of a value, cut before the value: `string "x"` is
/// `string`. serde's data-free descriptions (`sequence`, `map`) are kept as
/// they are; any other description with no quoted part is serde's `Other`,
/// which is verbatim input, so it becomes `a value`.
fn kind_word(unexpected: &str) -> &str {
    const DATA_FREE: [&str; 11] = [
        "unit value",
        "Option value",
        "newtype struct",
        "sequence",
        "map",
        "enum",
        "unit variant",
        "newtype variant",
        "tuple variant",
        "struct variant",
        "byte array",
    ];
    if DATA_FREE.contains(&unexpected) {
        return unexpected;
    }
    match unexpected.find(['"', '`', '[', '\'']) {
        Some(at) if !unexpected[..at].trim().is_empty() => unexpected[..at].trim_end(),
        _ => "a value",
    }
}

/// `serde_yaml`'s trailing ` at line L column C`, kept only when it is exactly
/// that, so no part of a value can ride along.
fn location(tail: &str) -> &str {
    let Some(at) = tail.rfind(" at line ") else {
        return "";
    };
    let suffix = &tail[at..];
    let mut words = suffix.split(' ').skip(1);
    let exact = matches!(
        (words.next(), words.next(), words.next(), words.next(), words.next()),
        (Some("at"), Some("line"), Some(line), Some("column"), Some(column))
            if line.bytes().all(|b| b.is_ascii_digit())
                && column.bytes().all(|b| b.is_ascii_digit())
                && !line.is_empty()
                && !column.is_empty()
    ) && words.next().is_none();
    if exact { suffix } else { "" }
}
