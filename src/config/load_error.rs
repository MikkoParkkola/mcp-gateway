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
//!
//! The message redactor lives in the YAML adapter
//! (`crate::yaml::redact_message`) since B3, shared by every YAML read.

pub(crate) use crate::yaml::redact_message;
use figment::error::{Actual, Kind, OneOf};

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
