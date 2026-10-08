// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every config writer spells a backend's address `url`, in the same write:
//! a backend it adds, and one the file already spelled `url`. Other backends
//! keep the spelling the operator chose.

use serde_yaml::{Mapping, Value};

use crate::config::{Config, transport_key_for};

/// Move a serialised backend's `http_url` or `ws_url` to `url`, when its
/// value is a literal address of that transport. An address from the
/// environment (`${VAR}`) keeps its alias: the loader resolves `url` before
/// it expands variables, so `url: ${VAR}` would not load.
pub(super) fn spell_as_url(entry: &mut Mapping) {
    for alias in ["http_url", "ws_url"] {
        let literal = entry
            .get(alias)
            .and_then(Value::as_str)
            .is_some_and(|value| transport_key_for(value) == Some(alias));
        if let Some(value) = literal.then(|| entry.remove(alias)).flatten() {
            entry.insert(Value::from("url"), value);
            return;
        }
    }
}

/// `config` rendered in full, with `url` for each backend that `existing`
/// (the file's text, when there is one) does not have or spells `url`.
pub(super) fn render(config: &Config, existing: Option<&str>) -> Result<String, String> {
    let mut value =
        serde_yaml::to_value(config).map_err(|e| format!("Failed to serialize config: {e}"))?;
    let file: Option<Value> = existing.and_then(|text| serde_yaml::from_str(text).ok());
    let in_file = file
        .as_ref()
        .and_then(|f| f.get("backends"))
        .and_then(Value::as_mapping);
    if let Some(backends) = value.get_mut("backends").and_then(Value::as_mapping_mut) {
        for (name, entry) in backends.iter_mut() {
            let was = in_file.and_then(|b| b.get(name));
            if was.is_none_or(|w| w.get("url").is_some())
                && let Value::Mapping(entry) = entry
            {
                spell_as_url(entry);
            }
        }
    }
    serde_yaml::to_string(&value).map_err(|e| format!("Failed to serialize config: {e}"))
}
