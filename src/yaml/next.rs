// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The replacement backend, built here beside the current one (MIK-8425
//! MIG.2). Every entry point mirrors the adapter's own signature, so
//! `tests/mik_8425_mig2_parity.rs` drives the same golden reports over it.
//! Step 3 leaves each one a stub that refuses, which makes every parity row
//! red; step 4 fills them in; the switch collapses this module into the
//! adapter.

use figment::value::{Dict, Map};
use serde::Serialize;
use serde::de::DeserializeOwned;

pub(crate) use super::{Error, Limit, Location, Mapping, Value, redact_message, to_json};

const NOT_YET: &str = "yaml::next is not implemented yet (MIK-8425 MIG.2 step 4)";

fn not_yet() -> Error {
    Error::backend(<serde_yaml::Error as serde::de::Error>::custom(NOT_YET))
}

pub(crate) fn from_str<T: DeserializeOwned>(_text: &str) -> Result<T, Error> {
    Err(not_yet())
}

pub(crate) fn from_str_loose(_text: &str) -> Result<Dict, Error> {
    Err(not_yet())
}

pub(crate) fn figment_data(_text: &str) -> figment::Result<Map<figment::Profile, Dict>> {
    Err(figment::Error::from(NOT_YET.to_owned()))
}

pub(crate) fn to_string<T: Serialize + ?Sized>(_value: &T) -> Result<String, Error> {
    Err(not_yet())
}

pub(crate) fn to_value<T: Serialize>(_value: T) -> Result<Value, Error> {
    Err(not_yet())
}

pub(crate) fn from_value<T: DeserializeOwned>(_value: Value) -> Result<T, Error> {
    Err(not_yet())
}

pub(crate) fn documents(_text: &str) -> impl Iterator<Item = Result<Value, Error>> + '_ {
    std::iter::once(Err(not_yet()))
}
