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

mod de;
mod mapping;
mod number;
mod rep;
mod resolve;
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

/// The replaced backend's refusal of a second document where one is read.
const MORE_THAN_ONE: &str =
    "deserializing from YAML containing more than one document is not supported";

/// `T` from the only document in `text`. The first document is read before
/// a second one is refused, so its own error wins, as before.
pub(crate) fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, Error> {
    guard(text)?;
    let documents = rep::parse(text)?;
    let value = de::from_document(&documents[0])?;
    if documents.len() > 1 {
        return Err(Error::message(MORE_THAN_ONE));
    }
    Ok(value)
}

/// figment's `Dict` from `text`: a repeated key keeps its last value, at
/// every level (D4).
pub(crate) fn from_str_loose(text: &str) -> Result<Dict, Error> {
    from_str(text)
}

#[allow(
    clippy::result_large_err,
    reason = "figment's own `Provider::data` signature, which the config loader returns"
)]
pub(crate) fn figment_data(text: &str) -> figment::Result<Map<figment::Profile, Dict>> {
    let dict = from_str_loose(text).map_err(|err| figment::Error::from(err.to_string()))?;
    Ok(figment::Profile::Default.collect(dict))
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

/// Every document in `text` as a tree, an empty one as null, ending at the
/// first refusal (D19). The guard refuses the stream as a whole.
pub(crate) fn documents(text: &str) -> impl Iterator<Item = Result<Value, Error>> + '_ {
    let parsed = guard(text).and_then(|()| rep::parse(text));
    let readings: Vec<Result<Value, Error>> = match parsed {
        Err(error) => vec![Err(error)],
        Ok(documents) => {
            let mut out = Vec::with_capacity(documents.len());
            for document in &documents {
                let reading = de::from_document(document);
                let refused = reading.is_err();
                out.push(reading);
                if refused {
                    break;
                }
            }
            out
        }
    };
    readings.into_iter()
}
