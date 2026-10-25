// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The replacement backend, built here beside the current one (MIK-8425
//! MIG.2). Every entry point mirrors the adapter's own signature, so
//! `tests/mik_8425_mig2_parity.rs` drives the same golden reports over it.
//! Each parse entry point runs the adapter's own pre-parse guard first, as
//! the adapter does. Step 3 left every entry point a stub that refuses;
//! step 4 fills them in; the switch collapses this module into the adapter.

use figment::value::{Dict, Map};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::guard;

mod mapping;
mod number;
mod tagged;
mod value;

pub(crate) use super::{Error, Limit, Location, redact_message};
pub(crate) use mapping::Mapping;
pub(crate) use number::Number;
pub(crate) use tagged::{Tag, TaggedValue};
pub(crate) use value::{Sequence, Value};

const NOT_YET: &str = "yaml::next is not implemented yet (MIK-8425 MIG.2 step 4)";

fn not_yet() -> Error {
    Error::backend(<serde_yaml::Error as serde::de::Error>::custom(NOT_YET))
}

pub(crate) fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, Error> {
    guard(text)?;
    Err(not_yet())
}

pub(crate) fn from_str_loose(text: &str) -> Result<Dict, Error> {
    guard(text)?;
    Err(not_yet())
}

#[allow(
    clippy::result_large_err,
    reason = "figment's own `Provider::data` signature, which the config loader returns"
)]
pub(crate) fn figment_data(text: &str) -> figment::Result<Map<figment::Profile, Dict>> {
    guard(text).map_err(|err| figment::Error::from(err.to_string()))?;
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

pub(crate) fn documents(text: &str) -> impl Iterator<Item = Result<Value, Error>> + '_ {
    // The guard refuses the stream as a whole, as the adapter's does.
    std::iter::once(guard(text).and_then(|()| Err(not_yet())))
}
